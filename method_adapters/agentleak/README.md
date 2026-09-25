# AgentLeak method adapter source

This directory discloses the authors' field classification, input masking,
protected-value registration, and C1/C2/C5 mediation code separately from
experiment orchestration and results. See [SOURCES.md](SOURCES.md) for the
original source paths and extraction changes. It contains no AgentLeak data,
model outputs, stored classifier decisions, credentials, or experiment reports.

## Modules

| Module | Method code |
| --- | --- |
| `boundary_fields.py` | Field extraction, the conservative schema-only fallback, and predicted-value sanitization |
| `parity_fields.py` | Value-free schema interface, an alternative schema classifier, structured vault masking, and sanitizer registration items |
| `contextual_schema.py` | Contextual classifier's original prompt, profile construction, inference, and response validation |
| `channels.py` | Original inter-agent message (C2), shared memory (C5), and final response (C1) mediation, connected to an initialized MCP client |

The two schema classifiers are distinct source implementations. The schema-only
fallback uses `boundary_fields.schema_only_predictions`: it protects unknown
text, number, and date fields and recognizes only `record_type` and `transaction_count` as
schema-safe markers. The parity extension's
`parity_fields.ConservativeSchemaDetector` has a wider schema-safe list.
Neither prediction function reads values or benchmark protection labels when
making decisions. They should not be substituted for one another when naming
an experimental configuration.

`extract_field_observations` does read the benchmark's `allowed_set.fields` and
`allowed_set.forbidden_fields` to attach `ground_truth_protected` labels. This is
an explicit benchmark metadata adapter, not automatic discovery of private
data. `oracle_predictions` and `oracle_protected_field_ids` expose that labeled
reference case by name. The schema classifiers ignore these labels. The
value-free projection removes both the field value and protection label.
Value types in this source are inferred from the supplied Python values before
that projection; applications with declared schema types can construct
`SchemaField` directly.

## Local use without AgentLeak or a model

Run the tests from the repository root:

```bash
python -m unittest discover -s tests -p test_method_agentleak.py -v
```

The functions accept objects with the same structural attributes as AgentLeak
scenarios, so synthetic objects are sufficient for mechanism checks:

```python
from types import SimpleNamespace as NS
from method_adapters.agentleak.boundary_fields import (
    extract_field_observations, schema_only_predictions,
)
from method_adapters.agentleak.parity_fields import (
    masked_flat_vault, sensitive_registration_items,
)

scenario = NS(
    private_vault=NS(records=[NS(record_type="customer", fields={
        "account_number": "SYNTHETIC-1234", "transaction_count": 3,
    })]),
    allowed_set=NS(fields=["transaction_count"], forbidden_fields=["account_number"]),
)
observations = extract_field_observations(scenario)
predicted = schema_only_predictions(observations)
model_input_fields = masked_flat_vault(scenario, observations, predicted)
trusted_registration = sensitive_registration_items(observations, predicted)
```

The masked mapping is input to the deployed summary operator; it is not itself
the M=8/C=512 summary. That operator is disclosed in the adjacent
[AgentDojo adapter](../agentdojo/README.md):
`method_adapters.agentdojo.tool_execution.SecureClawToolsExecutor`.
The AgentLeak source uses its `_read_result_payload` method with
`tool_name="agentleak_private_vault"` and the following settings:

```text
SECURECLAW_READ_OUTPUT_MODE=sanitized_summary
SECURECLAW_READ_SUMMARY_MAX_ITEMS=8
SECURECLAW_READ_SUMMARY_MAX_CHARS=512
SECURECLAW_STRICT_SYMBOLIC_READ=0
SECURECLAW_LLM_READ_SUMMARY=0
SECURECLAW_PER_READ_ALIAS_RESET=1
SECURECLAW_HIDE_REQUEST_MENTION_FIELDS=1
SECURECLAW_CANONICALIZE_OBFUSCATIONS=1
```

Set the operator's `_turn_id` and `_turn_request` from the scenario, and clear
its `_alias_to_real` and `_real_to_alias` maps before a fresh scenario, as the
original adapter does. Item/character caps apply to containers and strings in
the recursive summary, not to the length of the entire returned JSON payload.
The lightweight boundary-diagnostic summary, parameter sweeps, leak scorers,
and result-repair scripts are excluded.

## Connecting channels

Use `SecureClawChannelMediator(mcp)` with an initialized
`agent.mcp_client.McpStdioClient` (or the same `call_tool` interface) connected
to the existing SecureClaw gateway, policy services, and executor. Pass a
scenario and a `TopologyOutputs` object to `mediate`. The repository's existing
launchers configure those services; this module does not launch or delete
service state.

The method registers the scenario's vault field/value pairs through the trusted
gateway, sends and receives both agent messages, writes and reads shared memory,
and submits the final output. It extracts only runtime-visible response text,
not internal policy evidence, for each channel. Registering benchmark vault
fields is not a production protected-field detector. The original registration
helpers omit values shorter than four characters, and the original substring
sanitizer omits values shorter than three characters; these behaviors are
preserved rather than silently strengthened in this source release.

The original non-interactive confirmation accommodation remains:
`AGENTLEAK_AUTO_CONFIRM_POLICY` defaults to `heuristic`, with `never` and
`always` also supported. These flags supply a confirmation input to the gateway;
the existing gateway and executor remain responsible for policy authorization.
They are not proof of human consent. Production applications must obtain
confirmation and caller identity through trusted application code.

## Contextual classifier

`build_value_blind_profile` creates the original contextual classifier's profile
from the trusted privacy instruction, domain, schema names, and inferred types.
The model request excludes values, benchmark labels, attack metadata, and
outcomes. `ModelPool.classify` retains the original prompt and JSON decision
validation. It requires the optional `openai` SDK and an explicit API key,
endpoint, and model supplied by the caller. No inference runs on import or
during the included tests.

The source's default model is `anthropic/claude-sonnet-4` through an
OpenAI-compatible endpoint. This source release does not bundle past decisions
or establish that a provider will return the same decisions today. The
classifier is a separate field-identification audit, not an LLM in SecureClaw's
trusted execution or summary operator.

## Scope and licensing

These are source-derived method adapters, not a complete benchmark runner or a
new evaluation. Original source names and implementation details are retained
to make the mapping inspectable. No third-party AgentLeak implementation was
copied; users running AgentLeak itself must obtain it separately under its own
license. The authors' adapter code is covered by the repository's MIT license.
