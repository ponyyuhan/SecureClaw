from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


def _parse_int_list(s: str, default: list[int]) -> list[int]:
    xs: list[int] = []
    for part in (s or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            xs.append(int(part))
        except Exception:
            continue
    return xs if xs else list(default)


def _run_once(*, repo_root: Path, env: dict[str, str], out_path: Path) -> dict[str, Any]:
    e = os.environ.copy()
    e.update(env)
    e["PYTHONPATH"] = str(repo_root)
    e["BENCH_OUT_PATH"] = str(out_path.resolve())
    p = subprocess.run(
        [sys.executable, str(repo_root / "scripts" / "bench_e2e_throughput.py")],
        env=e,
        cwd=str(repo_root),
        text=True,
        capture_output=True,
        timeout=int(env.get("BENCH_TIMEOUT_S", "1800")),
        check=False,
    )
    if p.returncode != 0:
        raise RuntimeError(f"bench_e2e_throughput failed rc={p.returncode}\nstdout_tail={(p.stdout or '')[-1200:]}\nstderr_tail={(p.stderr or '')[-1200:]}")
    return json.loads(out_path.read_text(encoding="utf-8"))


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    out_dir = Path(os.getenv("OUT_DIR", str(repo_root / "artifact_out")))
    out_dir.mkdir(parents=True, exist_ok=True)
    perf_dir = out_dir / "shaping_perf"
    perf_dir.mkdir(parents=True, exist_ok=True)

    iters = int(os.getenv("SHAPING_CURVE_ITERS", os.getenv("BENCH_ITERS", "40")))
    conc = int(os.getenv("SHAPING_CURVE_CONCURRENCY", os.getenv("BENCH_CONCURRENCY", "8")))
    pad_tos = _parse_int_list(os.getenv("SHAPING_PAD_TOS", "1,4,8,16"), default=[1, 4, 8, 16])

    # Keep the tick short; larger intervals add queuing latency (intentionally).
    pir_interval_ms = int(os.getenv("PIR_MIX_INTERVAL_MS", "20"))
    mpc_interval_ms = int(os.getenv("MPC_MIX_INTERVAL_MS", "20"))

    backend = (os.getenv("POLICY_BACKEND") or "rust").strip().lower()

    rows: list[dict[str, Any]] = []

    # 0) Baseline (no mixing, no cover traffic).
    base_env = {
        "OUT_DIR": str(out_dir),
        "POLICY_BACKEND": backend,
        "BENCH_ITERS": str(iters),
        "BENCH_CONCURRENCY": str(conc),
        "PIR_MIX_ENABLED": "0",
        "MPC_MIX_ENABLED": "0",
        "PIR_COVER_TRAFFIC": "0",
        "MPC_COVER_TRAFFIC": "0",
        "PIR_EVAL_MODE": os.getenv("PIR_EVAL_MODE", "auto"),
        "PIR_BINARY_TRANSPORT": os.getenv("PIR_BINARY_TRANSPORT", "0"),
    }
    out_path = perf_dir / "bench_e2e.baseline.json"
    res = _run_once(repo_root=repo_root, env=base_env, out_path=out_path)
    rows.append(
        {
            "variant": "baseline",
            "pad_to": 0,
            "pir_interval_ms": 0,
            "mpc_interval_ms": 0,
            **res,
        }
    )

    # 1) Constant-shape mixing + cover traffic (sweep pad_to).
    for pad_to in pad_tos:
        pad_to = max(1, int(pad_to))
        env = dict(base_env)
        env.update(
            {
                "PIR_MIX_ENABLED": "1",
                "PIR_MIX_PAD_TO": str(pad_to),
                "PIR_MIX_INTERVAL_MS": str(pir_interval_ms),
                "PIR_COVER_TRAFFIC": "1",
                "PIR_MIX_LANES": os.getenv("PIR_MIX_LANES", "1"),
                "PIR_MIX_MAX_INFLIGHT": os.getenv("PIR_MIX_MAX_INFLIGHT", "1"),
                "PIR_MIX_SCHEDULE": os.getenv("PIR_MIX_SCHEDULE", "fixed"),
                "MPC_MIX_ENABLED": "1",
                "MPC_MIX_PAD_TO": str(pad_to),
                "MPC_MIX_INTERVAL_MS": str(mpc_interval_ms),
                "MPC_COVER_TRAFFIC": "1",
                # Prefer the multi endpoints when available.
                "MPC_MIX_MULTI_ENDPOINTS": "1",
                "MPC_MIX_LANES": os.getenv("MPC_MIX_LANES", "1"),
                "MPC_MIX_MAX_INFLIGHT": os.getenv("MPC_MIX_MAX_INFLIGHT", "1"),
                "MPC_MIX_SCHEDULE": os.getenv("MPC_MIX_SCHEDULE", "fixed"),
            }
        )
        out_path = perf_dir / f"bench_e2e.mixed.pad{pad_to}.json"
        res = _run_once(repo_root=repo_root, env=env, out_path=out_path)
        rows.append(
            {
                "variant": "mixed_cover",
                "pad_to": pad_to,
                "pir_interval_ms": pir_interval_ms,
                "mpc_interval_ms": mpc_interval_ms,
                **res,
            }
        )

    out = {
        "status": "OK",
        "policy_backend": backend,
        "iters": iters,
        "concurrency": conc,
        "pad_tos": pad_tos,
        "rows": rows,
    }

    json_path = perf_dir / "e2e_shaping_curves.json"
    csv_path = perf_dir / "e2e_shaping_curves.csv"
    json_path.write_text(json.dumps(out, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    with csv_path.open("w", encoding="utf-8") as f:
        f.write("variant,pad_to,pir_interval_ms,mpc_interval_ms,policy_backend,avg_ms,p50_ms,p95_ms,throughput_ops_s\n")
        for r in rows:
            f.write(
                f"{r.get('variant')},{int(r.get('pad_to') or 0)},{int(r.get('pir_interval_ms') or 0)},{int(r.get('mpc_interval_ms') or 0)},"
                f"{r.get('policy_backend')},{float(r.get('avg_ms') or 0.0):.6f},{float(r.get('p50_ms') or 0.0):.6f},{float(r.get('p95_ms') or 0.0):.6f},{float(r.get('throughput_ops_s') or 0.0):.6f}\n"
            )

    print(str(json_path))


if __name__ == "__main__":
    main()
