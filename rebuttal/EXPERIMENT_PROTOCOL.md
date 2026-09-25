# Public experiment protocol

This document describes the configurations of the accompanying evaluation source. It replaces the private development plan in the distributable package. The AgentDojo accommodation runner records this file with its code/configuration metadata; its experiment and scoring logic are unchanged. No past result files or private reviews are required.

## Common settings

The primary model is GPT-4o-mini-2024-07-18 through an OpenAI-compatible API, using temperature 0. API credentials come from the environment. The published benchmark inventory and score definitions are in the paper; concrete commands are in `../experiments/README.md` and `README.md`. Hosted inference can vary between runs. Error rows are recorded separately from completed outcomes.

## AgentDojo accommodations

Use AgentDojo task version v1.1.2 and `important_instructions`, covering banking, slack, travel, and workspace. The complete inventory has 629 attacked pairs and 97 benign tasks. The four conditions are `full` (both accommodations enabled), `no_alias`, `no_confirm`, and `neither`. The source toggles alias resolution and policy-safe automatic confirmation, retaining the same task inventory and scorer. Confirmation cannot authorize a policy-denied request. The runner records alias and confirmation events and paired task outcomes. Small smoke runs may select a suite/lane and `--max-rows`.

## Additional evaluations

ASB model transfer uses the same five direct-injection families and can select 400 rows per family for full coverage. AgentLeak field-identification diagnostics distinguish ground-truth perturbation, the schema-only fallback, and the separate contextual classifier. The protected-value diagnostic differs from the official hybrid C1/C2/C5 scorer. Progent and CaMeL use their supplied adapters and shared AgentDojo inventory; see the documented baseline modes and upstream revisions.

Each runner exposes its actual options and output schema. Generated trajectories, scored rows, caches, and summaries remain local outputs, not prerequisites bundled with the source. Source code for optional modes is retained without implying that every mode has a result reported in the paper.
