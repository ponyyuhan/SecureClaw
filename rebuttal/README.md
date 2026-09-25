# Additional experiment source

This directory contains executable source for the paper's additional experiments.
The original `rebuttal/experiments/` paths are preserved so imports and relative
paths retain their meaning. Generated results, traces, cached decisions, service
state, and intermediate engineering artifacts are not distributed.

The source is copied from the authors' current research working tree. A fresh run
generates its own output files. It does not recover historical hosted model
responses or promise the same aggregate numbers from a provider today.

## Source map

| Paper evaluation | Entry point and supporting source |
| --- | --- |
| ASB model transfer | `run_asb_cross_model.py`; reuses `scripts/asb_five_baseline_compare.py` |
| ASB plain control | `run_asb_plain_shard.py`; same primary ASB scenario/scoring runner |
| AgentDojo alias/confirmation accommodations | `run_agentdojo_accommodation.py`, `agentdojo_accommodation_core.py` |
| Protected-field misses and conservative schema fallback | `run_agentleak_boundary.py`, `agentleak_boundary_core.py` |
| Contextual field-classification audit | `build_agentleak_contextual_schema_detector.py`, including its `_classification_evaluation` function |
| AgentLeak parity-path extensions | `run_agentleak_parity_extensions.py`, `agentleak_parity_core.py`; reuses `scripts/paper_parity_agentleak_eval.py` |
| Adapted Progent comparison | `run_progent_agentdojo.py`, `baseline_common.py` |
| Adapted CaMeL comparison | `run_camel_agentdojo.py`, `baseline_common.py` |

No result-repair, queue, watcher, recovery, materialization, or output-merging
scripts are required by these entry points. Existing runner checks and resume
protections are preserved. The source includes its original optional diagnostic
CLI modes; their presence does not mean every mode has a result in the final paper.

## Dependencies and upstream source

Use the repository's `experiments/` instructions and upstream-source retrieval
script before attempting benchmark execution. These runners expect the following
directory names:

- `third_party/ipiguard/agentdojo/src` for the SecureClaw AgentDojo pipeline.
- `third_party/ASB` and primary ASB runner dependencies.
- `third_party/agentleak_official` for AgentLeak scenarios and evaluators.
- `third_party/agentdojo/src` for the shared AgentDojo baseline inventory.
- `third_party/progent` and `third_party/camel-prompt-injection/src` for the two
  additional baselines.

Additional baselines use the shared AgentDojo revision
`462c88ddf596cb745882702f9999c8aeb5fe467f` (package version 0.1.35), Progent
`9befb41cbf992b49dbf035cbd3d53eb953d3b351`, and CaMeL
`f083b6b396399d3b3c7f2ddaf613a5945eaf32d8`.
Their versions and source changes are recorded in `experiments/upstream_sources.json`.

Install each upstream package's declared dependencies in a separate Python
environment when version requirements conflict. In the baseline environment,
the shared AgentDojo source precedes the baseline forks on `sys.path`; install
that shared package's dependencies as well. Progent additionally requires its
`secagent` package (`pip install -e third_party/progent`). CaMeL requires its
own package dependencies (`pip install -e third_party/camel-prompt-injection`).
Installing packages does not run an experiment.

The runners load provider credentials from environment variables, generally
`OPENROUTER_API_KEY` (or the explicitly documented API-key environment option).
No credentials are included. Help, plan, dry-run, and summary modes do not make
model requests, but some import benchmark packages and therefore still need
their dependencies. The contextual builder has no plan/dry-run mode: only its
`--help` is a no-inference CLI action; its ordinary invocation calls a model.

## Commands

Run commands from the repository root. First inspect `--help`. Use a fresh output
directory for a new configuration; subsequent commands for that configuration
must retain the same options. The full examples below can incur substantial
provider usage when the execution step is selected.

### ASB transfer and plain control

```bash
python rebuttal/experiments/run_asb_cross_model.py plan \
  --out results/asb-transfer --model openai/gpt-4o-mini-2024-07-18 \
  --n-per-attack 400 --seed 3179
python rebuttal/experiments/run_asb_cross_model.py dry-run --out results/asb-transfer
python rebuttal/experiments/run_asb_cross_model.py run --out results/asb-transfer
python rebuttal/experiments/run_asb_cross_model.py summarize --out results/asb-transfer
```

There are five ASB attack families; 400 scenarios per family gives a 2,000-row
selection when the pinned inventory has those rows. The default is 50 per
family, a smaller selection. Change `--model` and use a separate output directory
for another backbone.

The plain-control wrapper selects one attack family and supports modulo sharding:

```bash
python rebuttal/experiments/run_asb_plain_shard.py --help
python rebuttal/experiments/run_asb_plain_shard.py dry-run \
  --out results/asb-plain-naive --model openai/gpt-4o-mini-2024-07-18 \
  --attack-type naive --task-num 1 --shard-index 0 --num-shards 1
```

Use `run` with the same arguments to execute and `summarize` to score its local
outputs. Enumerate the five family choices printed by `--help` for full coverage.

### AgentDojo accommodations

```bash
python rebuttal/experiments/run_agentdojo_accommodation.py \
  --out results/accommodation --dry-run
python rebuttal/experiments/run_agentdojo_accommodation.py \
  --out results/accommodation
python rebuttal/experiments/run_agentdojo_accommodation.py \
  --out results/accommodation --analyze-only
```

The defaults enumerate all 629 attacked and 97 benign rows for each of `full`,
`no_alias`, `no_confirm`, and `neither`. `--max-rows` limits coverage for a small
check. `--submitted-reference` is optional provenance information: the original
default points to an unbundled historical report, and its absence is recorded
as unavailable rather than supplying the paper's prior outcomes.

### AgentLeak field-identification diagnostics

```bash
python rebuttal/experiments/run_agentleak_boundary.py \
  --experiment schema --full-selection --scenario-seed 42 --run-seeds 0 \
  --out-root results/agentleak-schema --dry-run
python rebuttal/experiments/run_agentleak_boundary.py \
  --experiment misclassification --full-selection --scenario-seed 42 --run-seeds 0 \
  --out-root results/agentleak-field-misses --dry-run
```

Remove `--dry-run` to execute. `--max-cases` limits scenarios. The full generator
request is 1,000 and returns 996 usable scenarios. These are the separate
protected-value diagnostics, not the official hybrid parity scorer underlying
the primary any-channel leakage result.

The diagnostic summary in `agentleak_boundary_core.build_boundary_summary`
uses benchmark ground-truth labels when prioritizing items. It is disclosed as
part of this experimental diagnostic, not as the deployment summary or as an
oracle-free end-to-end method. The schema fallback itself classifies using
field names/types; its prediction function does not inspect labels or values.
Controlled false-negative/false-positive experiments explicitly perturb an
oracle protected-field reference set. The original optional `summary` and
`openweight` modes remain in the source; no corresponding new results are
implied by including them.

For the contextual development-inventory audit:

```bash
python rebuttal/experiments/build_agentleak_contextual_schema_detector.py \
  --out results/contextual-schema --model anthropic/claude-sonnet-4 \
  --seed 3179 --total-count 1000
```

This calls the provider, stores field decisions, then runs the included
`_classification_evaluation` only after the decisions are complete. The model
request uses the trusted privacy instruction, domain, field names, and types;
values, benchmark labels, attacks, and outcome labels are excluded. The type
projection derives Python value types before constructing that value-free
request. This is a development-inventory classification audit, not a separate
held-out evaluation. Later v4/v5 exploratory builders/evaluators are excluded.

### AgentLeak parity-path extensions

```bash
python rebuttal/experiments/run_agentleak_parity_extensions.py plan \
  --out results/agentleak-parity --seed 3179 --total-count 1000 \
  --attack-count 496 --benign-count 500 --detector schema
python rebuttal/experiments/run_agentleak_parity_extensions.py dry-run \
  --out results/agentleak-parity --detector schema
```

`run` executes the official scorer/gateway path and `summarize` aggregates its
outputs. `offline-smoke` uses synthetic model outputs but starts local services;
it is not a benchmark result. This runner's `ConservativeSchemaDetector` differs
from the preceding schema-only diagnostic classifier. The actual deployment
summary comes from the modified AgentDojo `SecureClawToolsExecutor`, not from
the lightweight diagnostic summary. Its default summary caps are 8 items and
512 characters with the original recursive semantics.

### Progent and CaMeL

```bash
python rebuttal/experiments/run_progent_agentdojo.py plan \
  --out results/progent --selection full --policy-mode generated
python rebuttal/experiments/run_progent_agentdojo.py run \
  --out results/progent --selection full --policy-mode generated
python rebuttal/experiments/run_progent_agentdojo.py summarize \
  --out results/progent --selection full --policy-mode generated

python rebuttal/experiments/run_camel_agentdojo.py plan \
  --out results/camel --selection full
python rebuttal/experiments/run_camel_agentdojo.py stage1 \
  --out results/camel --selection full
python rebuttal/experiments/run_camel_agentdojo.py stage2 \
  --out results/camel --selection full
python rebuttal/experiments/run_camel_agentdojo.py summarize \
  --out results/camel --selection full
```

`--selection pilot` selects 100 attacked and 20 benign rows instead. Progent's
generated-policy mode is the formal adapted comparison; manual mode is marked
diagnostic-only in the runner. The official Progent fork has 589 attacked rows,
so this adapter combines its original SecAgent core/policy wrappers with the
shared 629-row AgentDojo inventory. It is not execution of an unchanged upstream
fork. CaMeL first creates model traces and then replays them with security
policies; stage 2 has no additional model request. A disclosed interpreter patch
removes a dependency by object identity to avoid recursive equality overflow
on deep objects. See [baseline scope](experiments/BASELINE_FAITHFULNESS.md).

## Licensing and validation scope

Author-written runners use the repository MIT license. Upstream code retains its
own licenses, included under `experiments/licenses/`; the retrieval manifest
records upstream projects separately. No benchmark data or upstream repository
is re-licensed by this directory.

Source syntax, dependency-light imports, help entry points, and synthetic helper
behavior are checked offline. A help/import check is not a claim that a complete
hosted experiment was rerun. Exact dependency and model-execution verification
for the release is recorded by the repository's release validation notes.
