from __future__ import annotations

import base64
import json
import os
import random
import secrets
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from statistics import mean
from typing import Any

import requests

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from fss.dpf import gen_dpf_keys


BIN_MAGIC = b"MPIR"
BIN_VER = 1
BIN_MSG_PIR_BATCH = 1


def pick_port() -> int:
    s = socket.socket()
    s.bind(("", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def wait_http_ok(url: str, tries: int = 120) -> None:
    for _ in range(tries):
        try:
            r = requests.get(url, timeout=0.5)
            if r.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"health check failed: {url}")


def pct(xs: list[float], q: float) -> float:
    if not xs:
        return 0.0
    ys = sorted(xs)
    k = int(round((q / 100.0) * (len(ys) - 1)))
    k = max(0, min(len(ys) - 1, k))
    return float(ys[k])


def _u16(x: int) -> bytes:
    return int(x).to_bytes(2, "little", signed=False)


def _u32(x: int) -> bytes:
    return int(x).to_bytes(4, "little", signed=False)


def _pack_str(buf: bytearray, s: str) -> None:
    b = str(s).encode("utf-8")
    buf.extend(_u32(len(b)))
    buf.extend(b)


def _pack_batch_req(*, db: str, keys: list[bytes]) -> bytes:
    if not keys:
        raise ValueError("empty_keys")
    key_len = len(keys[0])
    if key_len <= 0:
        raise ValueError("bad_key_len")
    for k in keys:
        if len(k) != key_len:
            raise ValueError("nonuniform_key_len")
    buf = bytearray()
    buf.extend(BIN_MAGIC)
    buf.append(BIN_VER)
    buf.append(BIN_MSG_PIR_BATCH)
    buf.extend(_u16(0))
    _pack_str(buf, db)
    buf.extend(_u32(len(keys)))
    buf.extend(_u16(key_len))
    for k in keys:
        buf.extend(k)
    return bytes(buf)


def _parse_batch_resp(content: bytes) -> list[int]:
    if len(content) < 12:
        raise ValueError("short_bin_resp")
    if content[0:4] != BIN_MAGIC:
        raise ValueError("bad_magic")
    if int(content[4]) != BIN_VER or int(content[5]) != BIN_MSG_PIR_BATCH:
        raise ValueError("bad_version_or_msg")
    n = int.from_bytes(content[8:12], "little", signed=False)
    if len(content) != 12 + n:
        raise ValueError("bad_resp_len")
    return [int(x) & 1 for x in content[12:]]


def parse_int_list(s: str, default: list[int]) -> list[int]:
    out: list[int] = []
    for part in (s or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(int(part))
        except Exception:
            continue
    return out if out else list(default)


def parse_str_list(s: str, default: list[str]) -> list[str]:
    out: list[str] = []
    for part in (s or "").split(","):
        p = part.strip().lower()
        if not p:
            continue
        out.append(p)
    return out if out else list(default)


def run_cfg(
    *,
    url: str,
    wire: str,
    db: str,
    keys_raw: list[bytes],
    keys_b64: list[str],
    requests_n: int,
    conc: int,
) -> dict[str, Any]:
    wire = str(wire).strip().lower()
    if wire not in ("json", "bin"):
        raise ValueError("wire must be json|bin")
    endpoint = f"{url}/pir/query_batch" if wire == "json" else f"{url}/pir/query_batch_bin"
    payload_json = {"db": db, "dpf_keys_b64": keys_b64}
    payload_bin = _pack_batch_req(db=db, keys=keys_raw)
    headers_bin = {"content-type": "application/octet-stream"}

    def one() -> float:
        t0 = time.perf_counter()
        if wire == "json":
            r = requests.post(endpoint, json=payload_json, timeout=20)
            r.raise_for_status()
            out = r.json().get("ans_shares") or []
            if len(out) != len(keys_b64):
                raise RuntimeError("unexpected json answer size")
        else:
            r = requests.post(endpoint, data=payload_bin, headers=headers_bin, timeout=20)
            r.raise_for_status()
            out = _parse_batch_resp(r.content)
            if len(out) != len(keys_raw):
                raise RuntimeError("unexpected bin answer size")
        return time.perf_counter() - t0

    # Warmup
    for _ in range(5):
        _ = one()

    lat: list[float] = []
    t_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=max(1, int(conc))) as tp:
        futs = [tp.submit(one) for _ in range(int(requests_n))]
        for f in as_completed(futs):
            lat.append(float(f.result()))
    t_end = time.perf_counter()
    wall = max(1e-9, t_end - t_start)
    return {
        "wire": wire,
        "requests": int(requests_n),
        "concurrency": int(conc),
        "batch": int(len(keys_raw)),
        "latency_avg_ms": float(mean(lat) * 1000.0) if lat else 0.0,
        "latency_p50_ms": float(pct(lat, 50) * 1000.0),
        "latency_p95_ms": float(pct(lat, 95) * 1000.0),
        "throughput_reqs_s": float(requests_n) / wall,
        "throughput_keys_s": (float(requests_n) * float(len(keys_raw))) / wall,
    }


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    out_dir = Path(os.getenv("OUT_DIR", str(repo_root / "artifact_out")))
    out_dir.mkdir(parents=True, exist_ok=True)
    perf_dir = out_dir / "policy_perf"
    perf_dir.mkdir(parents=True, exist_ok=True)

    domain_size = int(os.getenv("FSS_DOMAIN_SIZE", "4096"))
    if domain_size <= 0 or (domain_size & (domain_size - 1)) != 0:
        domain_size = 4096
    domain_bits = int(domain_size.bit_length() - 1)
    batch = int(os.getenv("POLICY_SCALING_BATCH", "128"))
    if batch < 1:
        batch = 1
    if batch > 4096:
        batch = 4096
    requests_n = int(os.getenv("POLICY_SCALING_REQUESTS", "100"))
    if requests_n < 10:
        requests_n = 10
    conc = int(os.getenv("POLICY_SCALING_CONCURRENCY", "8"))
    if conc < 1:
        conc = 1
    if conc > 128:
        conc = 128

    threads = parse_int_list(os.getenv("POLICY_SCALING_THREADS", "1,2,4,8"), default=[1, 2, 4, 8])
    wires = parse_str_list(os.getenv("POLICY_SCALING_WIRES", "json,bin"), default=["json", "bin"])
    wires = [w for w in wires if w in ("json", "bin")]
    if not wires:
        wires = ["json", "bin"]

    seed = int(os.getenv("MIRAGE_SEED", "7"))
    rng = random.Random(seed)
    keys_raw: list[bytes] = []
    for _ in range(batch):
        idx = rng.randrange(domain_size)
        k0, _ = gen_dpf_keys(alpha=idx, beta=1, domain_bits=domain_bits)
        keys_raw.append(k0)
    keys_b64 = [base64.b64encode(k).decode("ascii") for k in keys_raw]

    # Ensure data exists.
    env_common = os.environ.copy()
    env_common["PYTHONPATH"] = str(repo_root)
    subprocess.run([sys.executable, "-m", "policy_server.build_dbs"], check=True, env=env_common)

    rust_bin = repo_root / "policy_server_rust" / "target" / "release" / "mirage_policy_server"
    rebuild = bool(int(os.getenv("POLICY_SCALING_REBUILD", "1")))
    if shutil.which("cargo") and (rebuild or not rust_bin.exists()):
        subprocess.run(["cargo", "build", "--release"], check=True, cwd=str(repo_root / "policy_server_rust"))
    if not rust_bin.exists():
        raise RuntimeError("cargo is required for rust scaling benchmark")

    rows: list[dict[str, Any]] = []
    for t in threads:
        tt = max(1, int(t))
        port = pick_port()
        url = f"http://127.0.0.1:{port}"
        env = env_common.copy()
        env["SERVER_ID"] = "0"
        env["PORT"] = str(port)
        env["DATA_DIR"] = str(repo_root / "policy_server" / "data")
        env["POLICY_MAC_KEY"] = secrets.token_hex(32)
        env["RAYON_NUM_THREADS"] = str(tt)
        env["TOKIO_WORKER_THREADS"] = str(max(2, tt))
        env["PIR_EVAL_MODE"] = str(os.getenv("PIR_EVAL_MODE", "auto"))
        proc = subprocess.Popen([str(rust_bin)], env=env, text=True)
        try:
            wait_http_ok(f"{url}/health")
            for w in wires:
                m = run_cfg(url=url, wire=w, db="allow_recipients", keys_raw=keys_raw, keys_b64=keys_b64, requests_n=requests_n, conc=conc)
                rows.append(
                    {
                        "backend": "rust",
                        "threads": int(tt),
                        "rayon_threads": int(tt),
                        "tokio_threads": int(max(2, tt)),
                        "domain_size": int(domain_size),
                        **m,
                    }
                )
        finally:
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    out = {
        "status": "OK",
        "seed": seed,
        "domain_size": int(domain_size),
        "batch": int(batch),
        "requests": int(requests_n),
        "concurrency": int(conc),
        "threads": [int(x) for x in threads],
        "wires": wires,
        "rows": rows,
    }

    json_path = perf_dir / "policy_server_scaling.json"
    csv_path = perf_dir / "policy_server_scaling.csv"
    json_path.write_text(json.dumps(out, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    with csv_path.open("w", encoding="utf-8") as f:
        f.write(
            "backend,threads,rayon_threads,tokio_threads,wire,domain_size,requests,concurrency,batch,latency_avg_ms,latency_p50_ms,latency_p95_ms,throughput_reqs_s,throughput_keys_s\n"
        )
        for r in rows:
            f.write(
                f"{r['backend']},{int(r['threads'])},{int(r['rayon_threads'])},{int(r['tokio_threads'])},{r['wire']},{int(r['domain_size'])},{int(r['requests'])},{int(r['concurrency'])},{int(r['batch'])},"
                f"{float(r['latency_avg_ms']):.6f},{float(r['latency_p50_ms']):.6f},{float(r['latency_p95_ms']):.6f},{float(r['throughput_reqs_s']):.6f},{float(r['throughput_keys_s']):.6f}\n"
            )

    print(str(json_path))


if __name__ == "__main__":
    main()
