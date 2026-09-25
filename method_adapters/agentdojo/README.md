# SecureClaw AgentDojo and ASB method adapter

This directory discloses the existing `SecureClawToolsExecutor` implementation
used by the local AgentDojo integration and reused by the ASB integration. It
includes the schema-aware read summary, typed reference aliases, trusted alias
resolution, tool classification, task-intent checks, policy requests, and
allow/deny handling. It contains no benchmark datasets, experiment results,
trajectories, model credentials, or experiment orchestration.

The adapter is extracted from the research workspace's modified
`third_party/ipiguard/agentdojo/src/agentdojo/agent_pipeline/tool_execution.py`.
The two retained classes and two helper functions are:
`ToolsExecutor`, `SecureClawToolsExecutor`, `tool_result_to_str`, and
`_policy_deny_tool_message`. Packaging changes select the required imports,
resolve the configuration directory relative to this release, and import the
included tool whitelist. Unrelated executor implementations and the original
benchmark pipeline are omitted. See [NOTICE.md](NOTICE.md) for upstream credits
and licenses.

The release fixes one cross-read alias issue found during validation: a later
read must not reuse an earlier reference for a different value. Each read keeps
its own local alias counter and uses a public read ordinal as a namespace;
earlier references remain resolvable until the task ends. This retains the
per-read counter reset used to avoid revealing earlier secret counts.
Regression tests cover the earlier reference's binding, independence from
earlier secret counts, and clearing the bindings at the next task.

## Install and check locally

From the repository root, use Python 3.11 and a virtual environment:

```sh
python -m pip install -r requirements.txt
python -m pip install -r method_adapters/agentdojo/requirements.txt
python -m unittest discover -s tests -p test_method_agentdojo.py -v
```

The optional dependency file pins AgentDojo 0.1.35, the installed external API
version used for the release's offline checks. The vendored research tree's
package metadata says 0.1.23 and contains local modifications. The dependency
pin makes the disclosed adapter importable; it does not identify or recreate
the original benchmark environments. The tests use synthetic records and
AgentDojo's actual `FunctionsRuntime`. They prevent HTTP requests and model
client construction.

## Deterministic summary configuration

Set these options **before constructing the executor**:

```sh
export SECURECLAW_READ_OUTPUT_MODE=sanitized_summary
export SECURECLAW_HANDLEIZE_READ_OUTPUT=1
export SECURECLAW_READ_SUMMARY_MAX_ITEMS=8
export SECURECLAW_READ_SUMMARY_MAX_CHARS=512
export SECURECLAW_LLM_READ_SUMMARY=0
export SECURECLAW_HIDE_REQUEST_MENTION_FIELDS=1
export SECURECLAW_PER_READ_ALIAS_RESET=1
export SECURECLAW_CANONICALIZE_OBFUSCATIONS=1
export SECURECLAW_STRICT_SYMBOLIC_READ=0
export SECURECLAW_DISABLE_ALIAS_RESOLUTION=0
```

For an offline example, after setting these variables:

```python
import json
from method_adapters.agentdojo.tool_execution import SecureClawToolsExecutor

adapter = SecureClawToolsExecutor()
payload = json.loads(adapter._read_result_payload({
    "sender": "alice@example.com",
    "body": "Invoice due Friday.",
}))
print(payload["summary"])
# {'sender': 'EMAIL_REF_1', 'body': 'Invoice due Friday.'}
```

`_read_result_payload` is an existing internal method, shown directly so the
example exercises the disclosed implementation. Normal AgentDojo integration
calls `query`, which passes tool results through that method and resolves
reference aliases inside the adapter before invoking tools.

## Exact behavior and scope

- The limits apply recursively: up to eight retained entries **per dictionary
  or list**, and up to 512 characters **per sanitized string**. The implementation
  can append an ellipsis or truncation-count metadata. These are not global
  limits on the serialized response. The full response also includes reference
  metadata and may contain bounded planning fields, form schemas, and guidance.
- Identifiers such as emails, URLs, IBANs, and configured credential values are
  replaced with typed aliases. The adapter holds their mappings in trusted
  in-process dictionaries. This configuration resets the local alias counter
  on each read and clears all reference bindings at the next task. Its
  `sc_handle_*` field is a response identifier, not an entry
  in the gateway's persistent protected-value store. The repository's core
  gateway separately implements stored handles and execution authorization.
- The source also retains an optional model-generated fact path. Its historical
  default is enabled, so `SECURECLAW_LLM_READ_SUMMARY=0` is necessary to select the
  deterministic interface above. The offline tests make no model calls. Other
  retained flags include experimental ablations and strict-symbolic summaries;
  their presence does not make them the main-paper configuration.
- The class contains benchmark accommodations, including configurable automatic
  confirmation, task-intent rules, and a local-executor option. They are retained
  for source fidelity. This class alone is not the operating-system isolation
  or executor-side authorization layer described by the core runtime.
- This is the current local method source. It includes later refinements and
  does not, on its own, establish that a historical benchmark trace used this
  exact revision. No complete experimental reproduction is claimed.
