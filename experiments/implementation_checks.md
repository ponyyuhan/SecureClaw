# Implementation and evaluation checks

The release contains the SecureClaw implementation and its evaluation source. Historical generated results are not required inputs. Small verification runs check both the implemented mechanism and whether the intended configuration was exercised; provider failures are recorded separately from task/security outcomes.

## Correctness repairs

- Reference IDs use a public read ordinal to avoid reusing an ID for a different value on a later read. Earlier bindings remain resolvable during the same task. The per-read value counter remains independent of earlier secret cardinality, and task changes clear the bindings.
- AgentLeak context construction preserves the first record referenced by the task, and retains additional records separately. Later records no longer overwrite the requested subject.
- Sensitive-value registration includes scalar members of lists/objects and comma formatting of actual numeric values under their original field policy. This does not change caller/session checks or the policy determining which fields are protected.
- The AgentLeak topology adapter delivers enabled attack payloads as explicitly untrusted observations, records the actual delivery stage, and does not reuse an old cache that omitted the attack. The benchmark's data and scoring functions are unchanged.
- Channel extraction includes actual returned plaintext when a confinement ablation disables handles, while excluding opaque IDs and authorization metadata. An unobserved payload is not evidence that confinement worked.
- Model/provider errors are reported as incomplete execution. They are not counted as successful defenses. The confirmation test uses a request that actually requires confirmation and checks a correctly bound token.
- The field-identification runner selects from the generated benchmark inventory in a fresh checkout. Historical outcome-enriched subsets require an explicit option and are not prerequisites for ordinary execution.

Regression tests are under `tests/`; installation patches reproduce the repaired adapter in the upstream integration. If benchmark dependencies were fetched before a release update, use a fresh dependency checkout or apply the updated patch from its recorded upstream revision. The fetch helper deliberately leaves an existing dependency directory unchanged.

## AgentLeak evaluation profiles

`scripts/paper_parity_agentleak_eval.py` generates the multi-agent topology and evaluates gateway-mediated C1/C2/C5 outputs. It is a channel-mediation experiment: its default generation context is the raw synthetic vault. It should not be interpreted as a direct test that the generator never received the vault.

`rebuttal/experiments/run_agentleak_parity_extensions.py` supplies the protected read view before generation and then exercises the gateway channel path. Use that entry point when checking the protected-read interface. The schema-only field diagnostic and contextual-classifier audit are separate protocols, documented in `rebuttal/README.md`.

The same benchmark evaluators are retained. Small-sample checks establish operation and expose implementation errors; they are not a claim that every percentage in a historical table will recur under a hosted provider.
