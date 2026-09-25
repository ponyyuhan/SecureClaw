#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

STATE_DIR="${OPENCLAW_STATE_DIR:-$SECURECLAW_RUNTIME_DIR/openclaw_state}"
mkdir -p "$STATE_DIR"

CFG="${STATE_DIR}/openclaw.json"
PLUGIN_FILE="$ROOT/integrations/openclaw_plugin/mirage_ogpp.ts"
MODEL_PRIMARY="${OPENCLAW_MODEL_PRIMARY:-openai-codex/gpt-5.4}"

cat >"$CFG" <<JSON
{
  "plugins": {
    "enabled": true,
    "load": { "paths": ["$PLUGIN_FILE"] },
    "entries": {
      "mirage_ogpp": { "enabled": true }
    }
  },
  "tools": {
    "profile": "minimal",
    "alsoAllow": ["secureclaw_act", "mirage_act"]
  },
  "agents": {
    "defaults": {
      "workspace": "$ROOT/integrations/openclaw_workspace",
      "model": {
        "primary": "$MODEL_PRIMARY"
      }
    }
  }
}
JSON

echo "Wrote OpenClaw state config: $CFG"
echo "Model: $MODEL_PRIMARY"
echo "Next step:"
echo "  OPENCLAW_STATE_DIR=\"$STATE_DIR\" openclaw agent --message \"Use secureclaw_act exactly once with caller='openclaw' and intent_id='FetchResource' to fetch https://api.github.com, then summarize status and reason_code.\""
