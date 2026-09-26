# Agent integrations

[← Documentation](README.md)

## MCP

Install the [local runtime](quickstart.md) and start the services before connecting the client:

```bash
source .venv/bin/activate
bash scripts/dev_up.sh
```

Copy the server entry from [`mcp_config.example.json`](../mcp_config.example.json) into your MCP client's configuration. Replace `REPLACE_WITH_REPO_ABSOLUTE_PATH` with the actual repository path.

The stdio entry point is:

```bash
bash scripts/launch_mcp_gateway.sh
```

The launcher uses `SECURECLAW_PYTHON` when explicitly set, otherwise the repository's `.venv/bin/python` if present, then `python` from the client's `PATH`. This lets desktop clients use the standard installation without inheriting an activated terminal environment. For a virtual environment elsewhere, add `SECURECLAW_PYTHON` with its absolute interpreter path to the MCP server's `env` configuration.

Keep the client's normal permissions and sandbox settings. This exposes SecureClaw's mediated tools; it does not disable any other tools in the client.

If you change the policy or executor ports, update the corresponding URLs in the MCP configuration. The HTTP gateway bearer token is specific to HTTP transport; the MCP stdio process is launched locally by the client.

## HTTP

The local stack exposes the HTTP gateway on `127.0.0.1:8765` by default. The [runtime validation script](../scripts/validate_runtime.py) demonstrates authenticated requests and operation sequencing. The [agent client](../agent/mcp_client.py) provides the local demo's client implementation.

Preserve the caller, session, reference, and transaction bindings across requests. See [configuration](configuration.md) for endpoint and state settings.

## OpenClaw and NanoClaw

| Integration | Source | Launcher |
| --- | --- | --- |
| OpenClaw | [`integrations/openclaw_plugin/`](../integrations/openclaw_plugin/) | [`scripts/run_openclaw.sh`](../scripts/run_openclaw.sh) |
| NanoClaw / Claude Agent SDK | [`integrations/nanoclaw_runner/`](../integrations/nanoclaw_runner/) | [`scripts/run_nanoclaw.sh`](../scripts/run_nanoclaw.sh) |

These optional integrations require their respective client installations and provider configuration. Model calls can incur charges. They are separate from the credential-free Python demo; their compatibility with current client versions is not established by the local runtime tests.

The adapters retain some `mirage_ogpp` file and configuration names from the original runtime. Those names identify the supplied integration entry points and are not additional dependencies.
