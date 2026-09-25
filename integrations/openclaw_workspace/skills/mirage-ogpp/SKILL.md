---
name: mirage-ogpp
description: Use the SecureClaw gateway via the single tool `secureclaw_act` (alias `mirage_act`) with high-level intents only.
---

# SecureClaw Gateway

You are operating in a constrained environment where **the only allowed side-effect tool is** `secureclaw_act` (alias `mirage_act`).

## Tool Contract

Call `secureclaw_act` with:

- `intent_id`: high-level intent name (examples: `ReadFile`, `ReadSecret`, `SendMessage`, `FetchResource`, `Declassify`)
- `inputs`: intent-specific inputs
- `constraints`: optional constraints (for example `user_confirm: true` for risky declassification)
- `caller`: set to `openclaw` unless instructed otherwise

The tool returns a JSON observation. Treat that JSON as the source of truth.

## Security Rules (Must Follow)

- Never attempt to access secrets directly; request them via intents and expect **sealed handles**, not plaintext.
- Never try to bypass SecureClaw by using other tools. If you believe you need another capability, explain why and stop.
- When asked to print results, print the returned JSON verbatim.
