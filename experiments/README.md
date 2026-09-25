# Experiment source and reproduction

This directory provides the benchmark dependency setup and configurations for
the paper's experiments. The original experiment runners and their scoring code
are in `scripts/`. The runtime, policies, and method adapters are included in this
repository. Results, model transcripts, local queues, caches, and intermediate
working directories are intentionally excluded; the runners generate new outputs
when executed.

## Setup

Use Python 3.11 in a fresh environment. Fetch the benchmark and baseline sources
at the recorded revisions, including the local source patches used by our
integrations:

```bash
python -m venv .venv-experiments
source .venv-experiments/bin/activate
python experiments/fetch_dependencies.py
python -m pip install -r requirements.txt -r experiments/requirements.txt
python -m pip install -e third_party/ipiguard/agentdojo
python -m pip install -e third_party/agentleak_official
python -m pip install -e third_party/faramesh-core
python -m spacy download en_core_web_sm
```

The fetch script leaves existing directories unchanged. For manual setup, clone
the URL and check out the revision in `upstream_sources.json`, then apply its
listed patch with `git -C third_party/NAME apply /absolute/path/to/PATCH`.
The patches modify Python source only. Third-party licenses and attribution are
listed in [THIRD_PARTY.md](THIRD_PARTY.md).

Do not install a second pip AgentDojo distribution on top of the patched fork
for these primary runners. The separate official AgentDojo checkout is used by
the DRIFT, Progent, and CaMeL launchers through their explicit Python paths. The
standalone method-adapter tests have their own documented dependency setup.

Set your API credential in the environment, then load the common configuration:

```bash
# Set OPENROUTER_API_KEY using your preferred local secret mechanism.
source experiments/primary.env.example
export PYTHONPATH="$PWD:$PWD/third_party/ipiguard/agentdojo/src:$PWD/third_party/DRIFT${PYTHONPATH:+:$PYTHONPATH}"
```

The paper reports GPT-4o-mini-2024-07-18 and temperature 0 for the primary
comparisons. The example above sets the summary-core limits M=8 and C=512. The summary caps
apply per container/per text value as described in the method-adapter docs.
`SC_MODEL_TEMPERATURE=0` and `SECURECLAW_TASK_CAPSULE=0` are common settings.
The read-summary option is set per benchmark below: the AgentDojo primary records
use the deterministic view, while the ASB records also contain the optional
model-generated facts. The general-purpose runner supports both. Provider model
availability and hosted inference can change; new executions need not be
bit-for-bit identical to historical responses.

## Primary benchmark commands

Run from the repository root. The output directories below are newly generated
local outputs and are not required as inputs to rerun these experiments.

### AgentDojo

```bash
SECURECLAW_LLM_READ_SUMMARY=0 python scripts/run_agentdojo_native_plain_secureclaw.py \
  --out-root runs/agentdojo \
  --model gpt-4o-mini-2024-07-18 \
  --benchmark-version v1.1.2 \
  --attack-name important_instructions \
  --suites banking,slack,travel,workspace \
  --modes benign,under_attack --run-plain 1 --run-secureclaw 1
```

This starts the SecureClaw services and invokes the patched native
`third_party/ipiguard/run/eval.py`. AgentDojo supplies task utility and attack
scoring; the source patch includes reference resolution in the scoring path.
The inventory is 97 benign and 629 attacked task/injection pairs. The native
runner uses AgentDojo's model enum, hence the unqualified model name here.

For the remaining common-harness baselines:

```bash
MODEL=gpt-4o-mini-2024-07-18 \
BENCHMARK_VERSION=v1.1.2 IPIGUARD_BENCHMARK_VERSION=v1.1.2 \
OUT_ROOT="$PWD/runs/agentdojo_baselines" \
bash scripts/run_drift_ipiguard_full_lowmem.sh

python scripts/run_agentdojo_faramesh.py \
  --out-root runs/agentdojo_faramesh \
  --model gpt-4o-mini-2024-07-18 --benchmark-version v1.1.2 \
  --attack-name important_instructions --modes benign,under_attack

python scripts/agentdojo_five_baseline_fair_report.py \
  --plain-secureclaw-root runs/agentdojo \
  --ipiguard-root runs/agentdojo_baselines/ipiguard \
  --drift-run-root runs/agentdojo_baselines \
  --faramesh-root runs/agentdojo_faramesh \
  --model gpt-4o-mini-2024-07-18 --benchmark-version v1.1.2 \
  --output-json runs/agentdojo_comparison.json \
  --output-md runs/agentdojo_comparison.md
```

### ASB

```bash
SECURECLAW_LLM_READ_SUMMARY=1 python scripts/asb_five_baseline_compare.py \
  --out-root runs/asb \
  --model openai/gpt-4o-mini-2024-07-18 --task-num 1 \
  --attack-types naive,escape_characters,fake_completion,context_ignoring,combined_attack \
  --baselines plain,drift,ipiguard,faramesh,secureclaw
```

Each of the five attack styles has 400 rows, for 2,000 rows per method. Inputs
come from the ASB checkout (`data/agent_task.jsonl`, `all_normal_tools.jsonl`,
`all_attack_tools.jsonl`, and the agent configurations). The same script contains
attack and task-utility scoring, per-row CSV generation, and report aggregation.
Plain and DRIFT execute their upstream `main_attacker.py` integrations; the other
methods use the shared AgentDojo tool interface. A small end-to-end run can use
`--baselines secureclaw --attack-types naive --smoke-limit 1`.

`asb_multifamily_compare.py` additionally exposes observation injection and other
attack families. Its memory-poisoning mode requires the corresponding upstream
memory database as an **input**; it is not part of the primary 2,000-row DPI
comparison. A previously mutated local memory database is not supplied as a
benchmark input. Use the upstream input or reconstruct it for that separate
family before comparing its results.

### AgentLeak parity lane

```bash
python scripts/paper_parity_agentleak_eval.py \
  --out runs/agentleak \
  --model openai/gpt-4o-mini-2024-07-18 --model-runtime openai \
  --judge-model openai/gpt-4o-mini-2024-07-18 \
  --n 1000 --seed 42 \
  --modes plain,ipiguard,drift,faramesh,secureclaw
```

The official generator requested with `--n 1000` yields 996 scenarios: 500
benign and 496 attacked. The runner includes the C1/C2/C5 channel mediation,
uses the official hybrid leakage detector and strict task evaluator, and writes
per-method summaries plus `paper_parity_report.json`. `agentleak_native_baselines.py`
provides the baseline integrations. Presidio and its English spaCy model are
installed above; the runner requests the detector with its documented thresholds.
A small end-to-end run can use `--n 2 --modes secureclaw`.

For the additional C3/C4/C6 channel lanes:

```bash
python scripts/agentleak_channel_baseline_compare.py \
  --out-root runs/agentleak_channels --caseset official \
  --channels C3,C4 --seed 7 \
  --model openai/gpt-4o-mini-2024-07-18 \
  --modes plain,ipiguard,drift,faramesh,secureclaw

# Separate synthetic audit-log lane; this example generates 1,000 of each kind.
python scripts/agentleak_channel_baseline_compare.py \
  --out-root runs/agentleak_c6 --caseset synthetic --channels C6 --seed 7 \
  --n-attack-per-channel 1000 --n-benign-per-channel 1000 \
  --model openai/gpt-4o-mini-2024-07-18 \
  --modes plain,ipiguard,drift,faramesh,secureclaw
```

This uses the benchmark **input** file
`third_party/agentleak_official/agentleak_data/datasets/scenarios_full_1000.jsonl`,
which is retrieved with the recorded upstream repository. Channel case
construction and scoring are in `agentleak_channel_eval.py`. The helper
`native_official_baseline_eval.py` supplies its text-defense functions; its
separate OpenClaw/OAuth launch mode is not used by this command.
The C3/C4 official lanes contain 129/122 attacked cases respectively and 504
benign cases each. C6 is a separate synthetic audit-log test because the official
dataset does not supply C6 attacked cases.

## Source inventory

| Source | Purpose |
| --- | --- |
| `scripts/run_agentdojo_native_plain_secureclaw.py` | AgentDojo services, native runs, progress/report collection |
| `scripts/run_drift_ipiguard_full_lowmem.sh` | AgentDojo DRIFT/IPIGuard execution |
| `scripts/run_agentdojo_faramesh.py` | AgentDojo Faramesh integration |
| `scripts/agentdojo_five_baseline_fair_report.py` | Matched-inventory AgentDojo aggregation |
| `scripts/summarize_agentdojo_tree.py` | Summarize native AgentDojo JSON output trees |
| `scripts/asb_five_baseline_compare.py` | ASB DPI evaluation and scoring |
| `scripts/asb_multifamily_compare.py` | Additional ASB attack families |
| `scripts/asb_csv_summary.py` | Standalone ASB CSV aggregation |
| `scripts/paper_parity_agentleak_eval.py` | AgentLeak parity evaluation, detection, and scoring |
| `scripts/agentleak_native_baselines.py` | AgentLeak baseline adapters |
| `scripts/agentleak_channel_baseline_compare.py` | AgentLeak C3/C4/C6 comparison |
| `scripts/agentleak_channel_eval.py` | Channel case construction and scoring |
| `scripts/native_official_baseline_eval.py` | Shared channel-defense helpers |

Additional experiments and their commands are documented under
`rebuttal/experiments/`. Local run status files and resume support remain in the
original runners because they are part of executing the experiments; no existing
status files, results, or historical run directories are bundled.

## Distinguishing configurations

The primary AgentLeak parity runner builds the original multi-agent topology and mediates its C1/C2/C5 outputs through the gateway. The later field-classification/summary-aware experiments are separate entry points under `rebuttal/experiments/`; they must not be substituted silently for the primary parity run. The full task inventories, record types, and scoring paths are unchanged by excluding historical output files.
