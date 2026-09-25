from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    return obj if isinstance(obj, dict) else {}


def _pick_existing(cands: list[Path]) -> Path | None:
    for p in cands:
        if p.exists():
            return p
    return None


def _run_script(repo_root: Path, script_rel: str, env: dict[str, str]) -> None:
    e = os.environ.copy()
    e.update(env)
    e["PYTHONPATH"] = str(repo_root)
    p = subprocess.run(
        [sys.executable, str(repo_root / script_rel)],
        cwd=str(repo_root),
        env=e,
        text=True,
        capture_output=True,
        check=False,
        timeout=int(env.get("BENCH_TIMEOUT_S", "5400")),
    )
    if p.returncode != 0:
        raise RuntimeError(f"{script_rel} failed rc={p.returncode}\nstdout_tail={(p.stdout or '')[-1200:]}\nstderr_tail={(p.stderr or '')[-1200:]}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out",
        default="artifact_out_compare_noprompt/perf_production_report.json",
        help="Output report path",
    )
    ap.add_argument("--run-missing", type=int, default=0, help="Run benches when input files are missing")
    ap.add_argument("--target-ops", type=float, default=25.0, help="Production throughput target (ops/s)")
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    out_path = Path(str(args.out)).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    shaping_path = _pick_existing(
        [
            repo_root / "artifact_out" / "shaping_perf" / "e2e_shaping_curves.json",
            repo_root / "artifact_out_perf_v3" / "shaping_perf" / "e2e_shaping_curves.json",
            repo_root / "artifact_out_perf_v2" / "shaping_perf" / "e2e_shaping_curves.json",
        ]
    )
    scaling_path = _pick_existing(
        [
            repo_root / "artifact_out" / "policy_perf" / "policy_server_scaling.json",
            repo_root / "artifact_out_perf_v3" / "policy_perf" / "policy_server_scaling.json",
            repo_root / "artifact_out_perf_v2" / "policy_perf" / "policy_server_scaling.json",
        ]
    )

    if (shaping_path is None or scaling_path is None) and int(args.run_missing):
        bench_env = {
            "OUT_DIR": str(repo_root / "artifact_out"),
            "POLICY_BACKEND": "rust",
            "MIRAGE_USE_UDS": "1",
            "PIR_BINARY_TRANSPORT": "1",
            "PIR_MIX_SCHEDULE": "eager",
            "MPC_MIX_SCHEDULE": "eager",
            "PIR_MIX_LANES": "2",
            "MPC_MIX_LANES": "2",
            "PIR_MIX_MAX_INFLIGHT": "4",
            "MPC_MIX_MAX_INFLIGHT": "4",
            "SHAPING_PAD_TOS": "1,2,4,8",
            "POLICY_SCALING_THREADS": "1,2,4,8",
            "POLICY_SCALING_WIRES": "json,bin",
        }
        _run_script(repo_root, "scripts/bench_e2e_shaping_curves.py", bench_env)
        _run_script(repo_root, "scripts/bench_policy_server_scaling.py", bench_env)
        shaping_path = repo_root / "artifact_out" / "shaping_perf" / "e2e_shaping_curves.json"
        scaling_path = repo_root / "artifact_out" / "policy_perf" / "policy_server_scaling.json"

    if shaping_path is None or scaling_path is None:
        raise SystemExit("missing benchmark inputs; rerun with --run-missing 1")

    shaping = _load_json(shaping_path)
    scaling = _load_json(scaling_path)

    srows = shaping.get("rows") if isinstance(shaping.get("rows"), list) else []
    base = next((r for r in srows if isinstance(r, dict) and str(r.get("variant") or "") == "baseline"), None)
    mixed = [r for r in srows if isinstance(r, dict) and str(r.get("variant") or "") == "mixed_cover"]
    best_mixed = max(mixed, key=lambda r: float(r.get("throughput_ops_s") or 0.0), default=None)

    base_ops = float((base or {}).get("throughput_ops_s") or 0.0)
    best_ops = float((best_mixed or {}).get("throughput_ops_s") or 0.0)
    best_p50 = float((best_mixed or {}).get("p50_ms") or 0.0)
    best_p95 = float((best_mixed or {}).get("p95_ms") or 0.0)
    overhead_factor = (base_ops / best_ops) if best_ops > 0 else 0.0

    target_ops = float(args.target_ops)
    target_pass = bool(best_ops >= target_ops)

    # Scaling summary by wire type.
    scale_rows = scaling.get("rows") if isinstance(scaling.get("rows"), list) else []
    by_wire: dict[str, list[dict[str, Any]]] = {}
    for r in scale_rows:
        if not isinstance(r, dict):
            continue
        w = str(r.get("wire") or "unknown")
        by_wire.setdefault(w, []).append(r)

    scaling_summary: dict[str, Any] = {}
    for w, rs in sorted(by_wire.items(), key=lambda kv: kv[0]):
        rs2 = sorted(rs, key=lambda r: int(r.get("threads") or 0))
        if not rs2:
            continue
        t1 = next((r for r in rs2 if int(r.get("threads") or 0) == 1), rs2[0])
        tmax = rs2[-1]
        thr1 = float(t1.get("throughput_reqs_s") or 0.0)
        thrm = float(tmax.get("throughput_reqs_s") or 0.0)
        scaling_summary[w] = {
            "threads_1": int(t1.get("threads") or 0),
            "threads_max": int(tmax.get("threads") or 0),
            "throughput_reqs_s_t1": thr1,
            "throughput_reqs_s_tmax": thrm,
            "speedup_tmax_vs_t1": (thrm / thr1) if thr1 > 0 else 0.0,
            "best_p50_ms": min(float(r.get("latency_p50_ms") or 0.0) for r in rs2),
            "best_p95_ms": min(float(r.get("latency_p95_ms") or 0.0) for r in rs2),
        }

    out: dict[str, Any] = {
        "status": "OK",
        "inputs": {
            "shaping_curves": str(shaping_path),
            "policy_scaling": str(scaling_path),
        },
        "production_profile": {
            "policy_backend": "rust",
            "transport_preference": "uds+binary",
            "mixer_profile": {
                "schedule": "eager",
                "lanes": 2,
                "max_inflight": 4,
            },
        },
        "e2e_throughput": {
            "baseline_ops_s": base_ops,
            "best_mixed_cover_ops_s": best_ops,
            "best_mixed_cover_p50_ms": best_p50,
            "best_mixed_cover_p95_ms": best_p95,
            "overhead_factor_vs_baseline": overhead_factor,
            "target_ops_s": target_ops,
            "target_met": target_pass,
            "best_mixed_variant": best_mixed,
        },
        "policy_server_scaling": scaling_summary,
    }

    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(str(out_path))


if __name__ == "__main__":
    main()
