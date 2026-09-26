# Paper-to-code map

This repository is an executable runtime reference for [SecureClaw: Clawing Back Control of LLM Agents](https://openreview.net/forum?id=0omFi3ZiBf). It includes the core mechanisms, method adapters, and experiment source. Demonstrations use synthetic data and simulated external sinks; the benchmark runners use the upstream task environments and evaluators documented in the experiment guide.

| Mechanism | Implementation | Local validation |
| --- | --- | --- |
| Opaque references, TTL, session/caller binding | `gateway/handles.py`, `gateway/guardrails.py`, `gateway/executors/cryptoexec.py` | `tests/test_ogpp.py`, `scripts/validate_runtime.py` |
| Canonical request and context binding | `common/canonical.py`, `gateway/tx_store.py` | `tests/test_request_binding.py`, `tests/test_security_games.py` |
| PREVIEW–COMMIT and dual policy MAC verification | `gateway/egress_policy.py`, `gateway/policy_unified.py`, `executor_server/server.py` | `tests/test_security_games.py`, `scripts/validate_runtime.py` |
| Replay protection and revocation | `executor_server/server.py`, `gateway/handles.py`, `gateway/tx_store.py` | `tests/test_security_games.py`, `scripts/validate_runtime.py` |
| Distributed policy lookup/evaluation | `fss/dpf.py`, `gateway/fss_pir.py`, `policy_server/`, `gateway/policy_unified.py` | DPF tests and local two-server validation |
| Inter-agent and memory channels | `gateway/executors/interagentexec.py`, `gateway/executors/memoryexec.py` | `tests/test_agentleak_channels.py`, `scripts/validate_runtime.py` |
| Final-output gate and budget | `gateway/executors/outputexec.py`, `gateway/leakage_budget.py`, `gateway/turn_gate.py` | `tests/test_agentleak_channels.py`, `scripts/validate_runtime.py` |
| OS mediation examples | `capsule/capsule.sb`, `capsule/run_smoke.sh`, `capsule/run_smoke_linux.sh` | Platform-specific capsule smoke scripts and existing contract verifier |
| Demo filesystem containment | `gateway/executors/fsexec.py` | `tests/test_fs_path_containment.py` |

## Implementation boundaries

The bundled `CryptoExec.declassify` operation is a regex-redacted text preview with a configurable character cap. Its default is 400 characters, clamped to 50–2000. It is not the benchmark adapter's schema-aware M=8, C=512 summary operator. The schema-aware summary implementation is included separately in `method_adapters/agentdojo/tool_execution.py`; field classification and channel adapters are in `method_adapters/agentleak/`. The standalone demo continues to use its original declassification operation.

The message, fetch, and webhook executors perform authorization verification, then return simulated results. They do not include real email, HTTP-fetch, or webhook delivery backends. File and skill examples similarly use the supplied demonstration workspace.

The policy servers run together on loopback for convenience. This validates protocol behavior, not the non-collusion deployment assumption. Likewise, adding an MCP tool to an otherwise unrestricted agent does not establish complete mediation; that requires the corresponding runtime and OS restrictions.

## Results and reproducibility

The source of the paper's quantitative claims is the paper and its official author discussion. The new local validation results in `release_notes.md` concern this code release only. They neither replace nor independently reproduce the paper or rebuttal numbers.

The experiment runners, scoring code, configurations, and dependency retrieval instructions are included. Upstream benchmark and baseline code is retrieved at the recorded revisions and patched with the supplied integration changes. Original model traces, stored experiment outputs, private review material, and temporary working files are not bundled. In particular, `scripts/validate_runtime.py` has 50 local mechanism checks and is distinct from the paper's bypass suite. The filename `test_agentleak_channels.py` refers to channel mechanisms; these tests do not run the AgentLeak benchmark.

The standalone four-configuration Boundary/Handles experiment driver is outside this release's scope. Its underlying runtime mechanisms and regression tests remain included.

## Method adapters

| Paper component | Disclosed source | Local checks |
| --- | --- | --- |
| Deterministic summary core, per-read typed aliases, controlled tool calls (AgentDojo and ASB) | `method_adapters/agentdojo/tool_execution.py` | `tests/test_method_agentdojo.py` |
| Schema-only fallback and value-free classification interface | `method_adapters/agentleak/boundary_fields.py`, `parity_fields.py` | `tests/test_method_agentleak.py` |
| Contextual field-classifier prompt and inference | `method_adapters/agentleak/contextual_schema.py` | Profile construction and decision validation; no hosted inference |
| C1/C2/C5 gateway mediation | `method_adapters/agentleak/channels.py` | Synthetic MCP responses and calls |

The summary's item limit applies to each container and its character limit to each text value, with additional truncation indicators. Select `SECURECLAW_LLM_READ_SUMMARY=0` for the deterministic core. The source retains other configurations; their presence is not evidence that a particular historical experiment used them. The adapter READMEs distinguish benchmark metadata, in-process aliases, and gateway-stored handles.

## Evaluation source

| Evaluation | Entry points |
| --- | --- |
| Primary AgentDojo | `scripts/run_agentdojo_native_plain_secureclaw.py`, upstream patched `run/eval.py` |
| Primary ASB | `scripts/asb_five_baseline_compare.py` |
| Primary AgentLeak C1/C2/C5 | `scripts/paper_parity_agentleak_eval.py`, `scripts/agentleak_native_baselines.py` |
| Channel diagnostics | `scripts/agentleak_channel_baseline_compare.py`, channel/native helpers |
| Main baseline comparison and aggregation | `scripts/run_drift_ipiguard_full_lowmem.sh`, `scripts/run_agentdojo_faramesh.py`, `scripts/agentdojo_five_baseline_fair_report.py` |
| Additional evaluation (Appendix C) | `rebuttal/experiments/`, documented in `rebuttal/README.md` |
| Formal-mechanism tests, summary diagnostic, ablations and timing | `experiments/mechanism_evaluations.md` |

See `experiments/README.md` for benchmark input retrieval, exact command examples, dependencies, and scoring paths. The public code does not require previously generated result files; executing the runners produces new outputs. Hosted-model responses can vary between runs.
