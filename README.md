# SecureClaw

Research runtime accompanying **SecureClaw: Clawing Back Control of LLM Agents**, by Yuhan Ma and Stefan Schmid, accepted at NeurIPS 2026.

[Paper and discussion](https://openreview.net/forum?id=0omFi3ZiBf)

SecureClaw moves sensitive data access and action authorization into a mediated runtime. This reference implementation includes opaque handles, declassification, two policy servers, PREVIEW–COMMIT authorization, executor-side verification of both policy-server MACs, replay protection, and capsule mediation examples.

This repository includes the SecureClaw runtime, method adapters, experiment runners, scoring code, configurations, and local tests. The [experiment guide](experiments/README.md) explains how to retrieve the upstream benchmarks and baseline implementations and run the evaluations. Generated results, raw model traces, caches, and temporary development files are not bundled. See [the paper-to-code map](docs/paper_to_code.md) for the implementation and evaluation entry points.

## Quick start

Use Python 3.11 or newer on macOS or Linux. The built-in demonstration and validation do not require an LLM or provider credentials.

```bash
git clone https://github.com/ponyyuhan/SecureClaw_repo.git
cd SecureClaw_repo
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

bash scripts/dev_up.sh
bash scripts/check_health.sh
python scripts/validate_runtime.py
python main.py agent-demo both
bash scripts/dev_down.sh
```

The local launcher builds policy databases and starts two policy servers, an executor, and an HTTP gateway. It writes process IDs, logs, and local databases under `.runtime/`. Stop the stack when finished. These commands use loopback ports 9001, 9002, 9100, and 8765; if they are occupied, set `P0_PORT`, `P1_PORT`, `EXECUTOR_PORT`, and `MIRAGE_HTTP_PORT` consistently in the invoking shell.

The demo maps sensitive-looking file paths to explicit fake fixtures under `gateway/demo_data/`. Message, fetch, and webhook executor endpoints validate authorization and return simulated results; they do not send email or perform external network requests. The included fake secret strings are test data.

## Validation

See [implementation checks](experiments/implementation_checks.md) for the repaired mechanisms and the distinction between channel-mediation and protected-read experiments.

Run the portable mechanism tests without starting services:

```bash
python -m unittest discover -s tests -v
```

The live local validation command in the quick start exercises handle binding, declassification, PREVIEW–COMMIT, authentication, delegation, revocation, memory, inter-agent messages, and skill ingress. It uses only the local demo services.

Capsule checks additionally exercise operating-system mediation and require the corresponding platform facility:

```bash
# macOS with sandbox-exec
bash capsule/run_smoke.sh

# Linux with bubblewrap installed
bash capsule/run_smoke_linux.sh
```

The macOS capsule check was validated with CPython 3.11.4 from an Anaconda installation. A Homebrew Python 3.14 virtual environment failed at interpreter launch under the OS sandbox on the preparation machine; use a compatible interpreter installation for capsule testing. This limitation does not affect the ordinary local runtime checks.

These scripts create local test artifacts and a loopback test server. Their platform requirements and scope are described in [capsule/MC_CONTRACT_SPEC.md](capsule/MC_CONTRACT_SPEC.md). Running the ordinary HTTP/MCP demo alone does not establish that every agent side effect is confined by the capsule.

## Method implementation used by benchmark integrations

The [AgentDojo/ASB adapter](method_adapters/agentdojo/README.md) provides the existing `SecureClawToolsExecutor`, including the deterministic summary core, typed aliases, task checks, policy requests, and controlled tool execution. Its optional dependencies and deterministic configuration are documented separately.

The [AgentLeak adapters](method_adapters/agentleak/README.md) provide field classification and masking, protected-value registration, the contextual classifier, and C1/C2/C5 mediation. The contextual classifier is a separate diagnostic component and requires an explicit model request; local tests make no model calls.

The original benchmark runners and their scoring paths are also included; see [primary evaluations](experiments/README.md), [additional experiments](rebuttal/README.md), and [mechanism evaluations](experiments/mechanism_evaluations.md). Required upstream revisions, local source patches, dependencies, and commands are documented. New runs generate their own result files.

## MCP and optional agent integrations

Start the local services, then configure your MCP client with [mcp_config.example.json](mcp_config.example.json), replacing the repository path. The MCP server entry point is:

```bash
bash scripts/launch_mcp_gateway.sh
```

Keep the client's normal permission and sandbox settings. SecureClaw mediates actions routed through its gateway; attaching the MCP tool alone does not remove the client's other tools or establish complete mediation.

Optional adapters are provided in `integrations/openclaw_plugin/` and `integrations/nanoclaw_runner/`. They require the respective client installation and, for model calls, the user's own provider credentials. They are separate from the local validation and may incur provider charges. Their compatibility with current client versions is not part of the local validation results.

## Configuration and deployment scope

The shipped policy and credentials are deliberately synthetic development defaults. `.env.example` documents the available settings. Shell launchers read exported environment variables; they do not automatically load `.env`.

This is a research prototype. Keep the demo bound to loopback. A deployment with real data must supply private policy-server keys and gateway authentication, separate the non-colluding policy-server trust domains, replace the demo secret store and simulated sinks, and authenticate callers and user confirmations through trusted application code. The `caller` field and `user_confirm` boolean in demonstrations are not independent proof of identity or human approval.

Existing ablation and insecure-demo switches are retained for research compatibility. The supplied launcher enables signed PIR, both policy-server MACs, and persistent executor replay state. Enabling an ablation or bypass option changes the claimed security configuration.

## Repository layout

| Path | Purpose |
| --- | --- |
| `gateway/` | Intent routing, handles, declassification, policy client, and executors |
| `policy_server/`, `fss/` | Python policy evaluation, DPF-based private lookup, policy database builder |
| `executor_server/` | Independent authorization verification and simulated action sinks |
| `capsule/`, `spec/` | OS capsule examples and existing mediation contracts |
| `secureclaw/`, `common/` | Task capsules, canonical request binding, tokens, and shared utilities |
| `agent/`, `integrations/` | Built-in synthetic agent and optional client adapters |
| `method_adapters/` | Source adapters for summaries, classification, and benchmark-facing method integration |
| `experiments/`, `scripts/` | Benchmark setup, primary evaluation runners, scoring, and mechanism experiments |
| `rebuttal/experiments/` | Additional model-transfer, baseline, classification, and accommodation experiments |
| `tests/`, `scripts/validate_runtime.py` | Portable tests and local integration validation |
| `policy_server_rust/` | Optional Rust policy-server implementation; not required by quick start |

## Citation and licensing

Please cite the paper using [CITATION.cff](CITATION.cff). The code was prepared from the authors' previously public runtime repository; provenance is recorded in [docs/release_notes.md](docs/release_notes.md).

The SecureClaw source in this release is available under the [MIT License](LICENSE), selected by the authors. Dependencies and referenced external projects retain their own licenses.
