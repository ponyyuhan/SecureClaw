# Mechanism evaluations

The mechanism-evaluation scripts listed below are included alongside the benchmark runners. They generate their own outputs; no historical results are required to inspect or rerun their logic. The standalone four-configuration Boundary/Handles experiment driver is not included in this release.

| Evaluation | Source |
| --- | --- |
| Deterministic summary-pair diagnostic | `scripts/measure_summary_tv_distance.py` |
| Request-authorization adversarial cases | `scripts/security_game_nbe_check.py` |
| Payment example | `scripts/e3_payment_nbe_demo.py` |
| Local policy-check diagnostic | `scripts/paper_eval.py` |
| ASB denial-recovery ablation | `scripts/run_recovery_ablation.py` |
| AgentLeak-style recovery and three-seed diagnostics | `scripts/additional_experiments_runner.py` |
| Runtime/capsule checks and combined report | `scripts/artifact_report.py`, `scripts/compromised_bypass_report.py` |
| Local latency and throughput | `scripts/bench_e2e_throughput.py`, `scripts/bench_e2e_shaping_curves.py`, `scripts/bench_policy_server_scaling.py`, `scripts/perf_production_report.py` |

These are the existing evaluation implementations, with their original CLI or environment options. They include deliberate insecure ablation modes as experimental controls; leave the normal runtime configuration enabled outside those comparisons. Capsule-specific checks require their documented platform tools, and the Rust timing variant requires Cargo.

`measure_summary_tv_distance.py` runs the independent deterministic-core paired diagnostic; it makes no model requests. It is separate from the current adapter's optional model-assisted summary mode. `run_recovery_ablation.py` invokes hosted inference when run and takes `RECOVERY_ABLATION_MODEL` and `RECOVERY_ABLATION_N_PER_ATTACK` from the environment. The local payment demonstration uses simulated effects.

Consult each script's existing argument definitions before execution. Several original local diagnostics use `OUT_DIR` or `artifact_out/` rather than command-line output options. Run them in an isolated checkout when comparing variants, since some rebuild local policy databases. The public source includes these evaluation paths; the small release-validation run does not rerun every experiment.

## AgentLeak-style recovery and stability diagnostics

`python scripts/additional_experiments_runner.py` exposes the original lightweight
recovery and three-seed diagnostics described in the extended-results appendix.
Its source comes from the authors' research runner of the same name, with the
unrelated exploratory sweeps omitted. It preserves the scenario construction,
prompts, compact boundary simulation, valid-response metrics, and recovery hint.
It is separate from the official AgentLeak multi-agent parity experiment.

```bash
python scripts/additional_experiments_runner.py --plan --n-per-family 2 \
  --experiments recovery stability --stability-seeds 42 1337 2024
python scripts/additional_experiments_runner.py --out runs/style-diagnostics \
  --n-per-family 2 --experiments recovery stability \
  --stability-seeds 42 1337 2024 --max-workers 2
```

Two scenarios per each of five injected attack families give ten cases per arm
or seed: 20 for recovery plus 30 for stability. The original 30-case setting is
`--n-per-family 6`. Provider access uses `OPENROUTER_API_KEY` by default;
`--api-key-env`, `--base-url`, and `--model` support compatible providers and
controlled local validation. `OPENAI_BASE_URL` is honored when set.

Unlike the old research runner, HTTP errors and exhausted provider retries are
reported as incomplete runs rather than counted as safe refusals. Successfully
completed rows and error counts are retained in an `errors_*.json` output when
this happens; the failed stage does not emit a security aggregate. This change
fixes error reporting without changing scoring for valid model responses.
