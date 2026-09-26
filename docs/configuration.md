# Configuration and deployment

[← Documentation](README.md)

## Local services

The supplied configuration is for a local research demo. [`.env.example`](../.env.example) lists the development settings. Shell launchers read exported variables; they do not automatically load `.env`.

To use different ports, set them before starting the stack and keep the same shell for the subsequent commands:

```bash
export P0_PORT=19001 P1_PORT=19002 EXECUTOR_PORT=19100 MIRAGE_HTTP_PORT=18765
export POLICY0_URL="http://127.0.0.1:$P0_PORT"
export POLICY1_URL="http://127.0.0.1:$P1_PORT"
export EXECUTOR_URL="http://127.0.0.1:$EXECUTOR_PORT"
bash scripts/dev_up.sh
bash scripts/check_health.sh
python scripts/validate_runtime.py
bash scripts/dev_down.sh
```

| Setting | Purpose |
| --- | --- |
| `P0_PORT`, `P1_PORT` | Policy-server listen ports |
| `POLICY0_URL`, `POLICY1_URL` | Policy-server addresses used by the gateway |
| `EXECUTOR_PORT`, `EXECUTOR_URL` | Executor port and gateway destination |
| `MIRAGE_HTTP_PORT`, `MIRAGE_HTTP_BIND` | Gateway listen address; the demo defaults to loopback |
| `MIRAGE_HTTP_TOKEN` | Bearer token for the HTTP gateway |
| `POLICY0_MAC_KEY`, `POLICY1_MAC_KEY` | Separate policy-server MAC keys |
| `SECURECLAW_RUNTIME_DIR` | Local runtime directory; defaults to `.runtime/` |
| `HANDLE_DB_PATH`, `EXECUTOR_REPLAY_DB_PATH` | Persistent handle and replay stores |
| `LEAKAGE_BUDGET_DB_PATH`, `AUDIT_LOG_PATH` | Disclosure-budget state and audit output |

The launcher enables signed PIR responses and supplies both policy-server keys. The shipped credentials and fake secret fixtures are public development examples.

## Runtime and benchmark configurations

The local runtime and benchmark adapters have distinct configuration surfaces. The demo's declassification operation produces a capped, regex-redacted preview. The AgentDojo/ASB method adapter supplies the schema-aware summary operator; the AgentLeak adapters supply classification and channel mediation. See the [paper-to-code map](paper_to_code.md#implementation-boundaries) before substituting one for another.

For benchmark models, summary limits, dependencies, and per-benchmark flags, use [the experiment guide](../experiments/README.md) and [`experiments/primary.env.example`](../experiments/primary.env.example). Model calls require the user's own provider credentials and may incur charges.

## Deployment assumptions

The repository is a research implementation. A deployment with real data needs:

- Private policy keys and gateway authentication, with the two policy servers in separate trust domains consistent with the non-collusion assumption.
- Trusted caller authentication and a trusted path for user confirmation. The demo's `caller` field and `user_confirm` boolean are not independent proof of identity or human approval.
- A protected data store and real action backends in place of the fake secret fixtures and simulated sinks.
- Runtime and OS restrictions that route every covered data read and side effect through the intended boundary.

The gateway checks the actions routed through it. Connecting an MCP tool by itself does not restrict an agent's other tools, filesystem access, or network access. Keep the client's normal permission and sandbox controls; use the [capsule examples](quickstart.md#os-capsule-checks) to inspect OS mediation.

## Research switches

Existing ablation and insecure-demo switches remain available in the implementation. They intentionally change which mechanisms are enforced. For example, `EXECUTOR_INSECURE_ALLOW` bypasses executor authorization when explicitly enabled; it is not part of the default protected configuration.

The [mechanism-evaluation guide](../experiments/mechanism_evaluations.md) documents the relevant experiment settings. Stored outputs and the standalone four-configuration Boundary/Handles driver are excluded from this release; the runtime mechanisms and regression tests remain included.
