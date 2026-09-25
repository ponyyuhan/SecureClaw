# Mechanism evaluations

The original mechanism-evaluation source is included alongside the benchmark runners. The scripts generate their own outputs; no historical results are required to inspect or rerun their logic.

| Evaluation | Source |
| --- | --- |
| Deterministic summary-pair diagnostic | `scripts/measure_summary_tv_distance.py` |
| Request-authorization adversarial cases | `scripts/security_game_nbe_check.py` |
| Payment example | `scripts/e3_payment_nbe_demo.py` |
| Boundary/handle ablations | `scripts/run_pillar_ablation.py`, `scripts/paper_eval.py` |
| Denial-recovery ablation | `scripts/run_recovery_ablation.py` |
| Runtime/capsule checks and combined report | `scripts/artifact_report.py`, `scripts/compromised_bypass_report.py` |
| Local latency and throughput | `scripts/bench_e2e_throughput.py`, `scripts/bench_e2e_shaping_curves.py`, `scripts/bench_policy_server_scaling.py`, `scripts/perf_production_report.py` |

These are the existing evaluation implementations, with their original CLI or environment options. They include deliberate insecure ablation modes as experimental controls; leave the normal runtime configuration enabled outside those comparisons. Capsule-specific checks require their documented platform tools, and the Rust timing variant requires Cargo.

`measure_summary_tv_distance.py` runs the independent deterministic-core paired diagnostic; it makes no model requests. It is separate from the current adapter's optional model-assisted summary mode. `run_recovery_ablation.py` invokes hosted inference when run and takes `RECOVERY_ABLATION_MODEL` and `RECOVERY_ABLATION_N_PER_ATTACK` from the environment. The benchmark-facing pillar ablations can also invoke hosted inference. The local payment demonstration uses simulated effects.

Consult each script's existing argument definitions before execution. Several original local diagnostics use `OUT_DIR` or `artifact_out/` rather than command-line output options. Run them in an isolated checkout when comparing variants, since some rebuild local policy databases. The public source includes these evaluation paths; the small release-validation run does not rerun every experiment.
