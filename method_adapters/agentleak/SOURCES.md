# Source provenance

These functions were extracted from the authors' local SecureClaw working tree
on 2026-09-25. The paths below identify the research source; line numbers refer
to that source at extraction time. No benchmark implementation is vendored.
The extracted authors' code is covered by this repository's MIT license.

Function bodies and constants are unchanged, with the following integration changes:

- Imports are restricted to the dependencies of the selected definitions and
  local relative imports.
- `Scenario` is a typing alias for `Any`, avoiding an AgentLeak dependency for
  structurally equivalent objects; no runtime checks are removed.
- The four `SecureClawRuntime` mediation methods are retained in
  `SecureClawChannelMediator`, whose constructor accepts an initialized MCP client.
  Service startup, process cleanup, generated state, and benchmark scoring are
  excluded.
- The contextual classifier's `OpenAI` import is deferred to `ModelPool.__init__`;
  its prompt, request construction, parsing, and validation remain unchanged.

This is a disclosure of method source. It is not a claim that the current working
copy is byte-identical to every historical experiment. It does not include model
responses, generated profiles, results, traces, benchmark data, or API credentials.

## `rebuttal/experiments/agentleak_boundary_core.py`

`FieldObservation` (10–21), `_HIGH_RISK_MARKERS` (42–80), `_SCHEMA_SAFE_MARKERS` (82–85), `_normalize_name` (88–91), `_name_matches` (94–105), `_safe_name_matches` (108–132), `_value_type` (135–144), `classify_field` (147–223), `_iter_leaves` (226–236), `extract_field_observations` (239–293), `oracle_predictions` (296–301), `schema_only_predictions` (304–322), `_replace_value` (502–511), `sanitize_predicted_values` (514–536).

## `rebuttal/experiments/agentleak_parity_core.py`

`canonical_json` (10–17), `sha256_json` (20–21), `normalized_name` (24–25), `SchemaField` (28–42), `SchemaDetector` (45–49), `_HIGH_RISK_MARKERS` (52–91), `_PUBLIC_SCHEMA_MARKERS` (93–107), `_marker_matches` (110–118), `ConservativeSchemaDetector` (121–145), `value_free_schema_fields` (148–161), `oracle_protected_field_ids` (164–171), `_mask_value` (249–285), `masked_flat_vault` (288–321), `sensitive_registration_items` (324–344).

## `scripts/paper_parity_agentleak_eval.py`

`_gateway_user_visible_text` (94–117), `_vault_field_value_pairs` (155–176), `TopologyOutputs` (179–185), `_SECRET_PATTERNS` (238–243), `_attack_payload_is_suspicious` (246–272), `_secret_like_high_entropy_atom` (275–288), `_looks_secret_like_text` (291–301), `_trusted_recipient` (403–415), `_should_auto_confirm` (418–428), `SecureClawRuntime._act` (789–794), `SecureClawRuntime._finalize_turn` (796–802), `SecureClawRuntime._recv_messages` (804–821), `SecureClawRuntime.mediate` (823–939).

## `rebuttal/experiments/build_agentleak_contextual_schema_detector.py`

`DEFAULT_MODEL` (44–44), `DEFAULT_BASE_URL` (45–45), `PROMPT_VERSION` (46–46), `ALLOWED_REASON_CODES` (47–52), `_schema_signature` (79–87), `build_value_blind_profile` (90–131), `_system_prompt` (134–150), `_request_payload` (153–159), `_parse_json_object` (162–170), `_validate_decisions` (173–208), `ModelResult` (211–218), `ModelPool` (221–292), `_profile_predictions` (295–309).
