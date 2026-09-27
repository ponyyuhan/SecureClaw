# Quick start and troubleshooting

[← Repository home](../README.md)

## Install

Use Python 3.11 or newer on macOS or Linux. Python 3.11 is also the recommended environment for the optional benchmark dependencies.

```bash
git clone https://github.com/ponyyuhan/SecureClaw.git
cd SecureClaw
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Run commands from the repository root with this environment active.

## Start the runtime

```bash
bash scripts/dev_up.sh
bash scripts/check_health.sh
```

The launcher builds the policy databases and starts four loopback services:

| Service | Default address |
| --- | --- |
| Policy server 0 | `http://127.0.0.1:9001` |
| Policy server 1 | `http://127.0.0.1:9002` |
| Executor | `http://127.0.0.1:9100` |
| HTTP gateway | `http://127.0.0.1:8765` |

The health check prints `OK` for each service. Process IDs, logs, handle state, and replay state are stored under `.runtime/`; generated policy databases are under `policy_server/data/`.

## Validate and try the demo

```bash
python scripts/validate_runtime.py
python main.py agent-demo both
```

Runtime validation covers handle binding, declassification, PREVIEW–COMMIT authorization, authentication, delegation, revocation, memory, inter-agent messages, and skill ingress. The agent demo runs both benign and malicious action sequences. Inspect the returned allow/deny decisions; a denied malicious action is an expected outcome.

This path uses no hosted model. Sensitive-looking paths map to explicit fake fixtures in `gateway/demo_data/`. Message, fetch, and webhook actions validate authorization and return simulated results; they do not send mail or make external requests.

Stop the services when finished:

```bash
bash scripts/dev_down.sh
```

## Offline tests

```bash
python -m unittest discover -s tests -v
```

For the optional AgentDojo/ASB method-adapter checks, use Python 3.11 and install:

```bash
python -m pip install -r method_adapters/agentdojo/requirements.txt
python -m unittest discover -s tests -v
```

The optional checks are explicitly skipped when AgentDojo is absent. Use a separate environment for the [primary benchmark setup](../experiments/README.md), which installs a patched AgentDojo fork instead of this test dependency.

## OS capsule checks

The capsule examples test OS-level confinement in addition to the runtime protocol. Choose the command for your platform:

```bash
# macOS: requires sandbox-exec and a compatible Python installation.
bash capsule/run_smoke.sh

# Linux: requires bubblewrap and a host that permits its namespaces.
bash capsule/run_smoke_linux.sh
```

These scripts create local artifacts and a loopback test server, then run the existing mediation-contract checks. See [the capsule specification](../capsule/MC_CONTRACT_SPEC.md) for their exact scope.

The macOS capsule was validated with CPython 3.11.4 from Anaconda. A Homebrew Python 3.14 virtual environment failed at interpreter launch under the OS sandbox on the preparation machine. This interpreter-specific issue does not affect the ordinary HTTP/MCP runtime checks. The Linux capsule needs a separate Linux environment; a passing macOS run does not validate it.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `ModuleNotFoundError` | Activate the virtual environment, install `requirements.txt`, and run from the repository root. |
| A service does not become healthy | Read its log in `.runtime/logs/`; check whether its configured port is already occupied. |
| Default ports are in use | Export alternate ports and service URLs before starting the stack; retain these settings for validation and shutdown. See [configuration](configuration.md#local-services). |
| MCP client cannot find the interpreter | Follow [MCP setup](integrations.md#mcp), especially when using an environment outside the repository. |
| Adapter tests are skipped | Install the optional AgentDojo test dependency in a Python 3.11 environment. |
| Capsule cannot start | Check the OS facility and Python installation described above; ordinary runtime tests do not require a capsule. |

No model-provider key is required for any command on this page.
