# Paper-to-code map

This repository is an executable runtime reference for [SecureClaw: Clawing Back Control of LLM Agents](https://openreview.net/forum?id=0omFi3ZiBf). It demonstrates the core mechanisms with synthetic data and simulated external sinks. It is not an exact snapshot of the paper's benchmark environment.

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

The bundled `CryptoExec.declassify` operation is a regex-redacted text preview with a configurable character cap. Its default is 400 characters, clamped to 50–2000. It is not the benchmark adapter's schema-aware M=8, C=512 summary operator. The exact benchmark summary and classification adapters are outside this release.

The message, fetch, and webhook executors perform authorization verification, then return simulated results. They do not include real email, HTTP-fetch, or webhook delivery backends. File and skill examples similarly use the supplied demonstration workspace.

The policy servers run together on loopback for convenience. This validates protocol behavior, not the non-collusion deployment assumption. Likewise, adding an MCP tool to an otherwise unrestricted agent does not establish complete mediation; that requires the corresponding runtime and OS restrictions.

## Results and reproducibility

The source of the paper's quantitative claims is the paper and its official author discussion. The new local validation results in `release_notes.md` concern this code release only. They neither replace nor independently reproduce the paper or rebuttal numbers.

This repository does not ship AgentDojo, AgentLeak, ASB, benchmark adapters, baseline implementations, original model traces, private review material, or the full statistical reconstruction pipeline. In particular, `scripts/validate_runtime.py` has 50 local mechanism checks and is distinct from the paper's bypass suite. The filename `test_agentleak_channels.py` refers to channel mechanisms; these tests do not run the AgentLeak benchmark.
