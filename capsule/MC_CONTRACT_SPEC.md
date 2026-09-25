# SecureClaw Capsule Mediation Contract Specification v1

Status: Normative system assumption for SCS proofs  
Version: `1`

This document defines the capsule mediation contract as a verifiable assumption.
It is bound to machine-checkable artifacts in `spec/` and executable checks in `capsule/`.

## 1. Contract Object

Normative contract files:

1. `spec/secureclaw_capsule_contract_v1.schema.json`
2. `spec/secureclaw_capsule_contract_v1.json`

Normative verifier and probes:

1. `capsule/verify_contract.py`
2. `capsule/smoke.py`
3. `capsule/run_smoke.sh`
4. `capsule/run_smoke_linux.sh`

## 2. Security Objective

Under active contract mode, skill code cannot perform direct bypass actions outside gateway mediation.

Forbidden direct actions:

1. Reading host secret paths outside allowlisted roots.
2. Executing arbitrary shell commands or binaries outside allowlist.
3. Accessing public internet directly.
4. Posting to loopback exfiltration endpoints when loopback HTTP is disallowed.

Required direct action:

1. Gateway-mediated `act` call must remain available through constrained transport.

## 3. Normative Clauses

### 3.1 Filesystem Mediation

1. Reads are allowlisted by prefix through `filesystem.allow_read_prefixes`.
2. Writes are allowlisted by prefix through `filesystem.allow_write_prefixes`.
3. Sensitive roots in `filesystem.deny_read_prefixes` are denied.
4. Deny takes precedence over allow on overlapping paths.

### 3.2 Process Mediation

1. Process creation is denied by default when `process.deny_by_default=true`.
2. Only binaries in `process.allow_exec_paths` may be executable.
3. Shell interpreters are denied unless explicitly allowlisted and justified.

### 3.3 Network Mediation

1. Public internet must be denied when `network.allow_public_internet=false`.
2. Loopback HTTP bypass must be denied when `network.allow_loopback_http=false`.
3. Transport to gateway is constrained by `transport.mode`.

### 3.4 Transport Mediation

1. `transport.mode=uds` is required for strong local mediation.
2. Allowed socket paths are fixed by `transport.allowed_uds_paths`.
3. Any transport outside this set violates the contract.

## 4. Assertion Set and Verdict Semantics

Each assertion in `spec/secureclaw_capsule_contract_v1.json` includes:

1. `id`
2. `kind`
3. `must_deny`
4. optional `allow_skip`

Verifier output reason codes:

1. `PASS_DENY`: forbidden probe was denied.
2. `PASS_ALLOW`: required probe succeeded.
3. `SKIPPED_ALLOWED`: skipped probe allowed by contract.
4. `FAIL_MUST_DENY`: forbidden probe succeeded.
5. `FAIL_MUST_ALLOW`: required probe failed.
6. `MISSING_PROBE`: probe result not present.
7. `SKIPPED`: probe skipped but not allowed by contract.

Global verdict:

1. `status=OK` iff every assertion result has `ok=true`.
2. `status=FAIL` otherwise.

### 4.1 Clause-to-Assertion-to-Probe Mapping

| Contract clause | Assertion id(s) in `spec/secureclaw_capsule_contract_v1.json` | Probe/report key in `capsule/smoke.py` | Verifier mapping |
|---|---|---|---|
| Filesystem deny for host secrets | `no_host_secret_read` | `direct_fs_read` | `capsule/verify_contract.py:_select_probe(kind="fs_read")` |
| Process deny-by-default (arbitrary exec) | `no_arbitrary_exec_true`, `no_arbitrary_exec_sh` | `direct_exec_true`, `direct_exec_sh` | `capsule/verify_contract.py:_select_probe(kind="exec")` |
| Network deny for public internet | `no_public_internet` | `direct_internet` | `capsule/verify_contract.py:_select_probe(kind="internet_get")` |
| Network deny for loopback exfiltration | `no_loopback_http_exfil` | `direct_exfil_post` | `capsule/verify_contract.py:_select_probe(kind="http_post")` |
| Transport/gateway path must remain usable | `gateway_act_allowed`, `gateway_mcp_act_allowed` | `gateway_act`, `gateway_mcp_act` | `capsule/verify_contract.py:_select_probe(kind="gateway_act|gateway_mcp_act")` |

## 5. Mandatory Assertions for SCS Claim

SCS theorem may be claimed only if all mandatory assertion classes pass:

1. Host secret read denial.
2. Public internet denial.
3. Loopback exfil POST denial.
4. Arbitrary exec denial.
5. Gateway direct `act` allow.
6. Gateway MCP `act` allow.

The repository default contract already encodes these assertions.

## 6. Cross-Platform Minimal Implementations

### 6.1 macOS Profile

1. Mechanism: `sandbox-exec` with `capsule/capsule.sb`.
2. Execution: `bash capsule/run_smoke.sh`.
3. Expected: contract verifier emits `OK`.

### 6.2 Linux Profile

1. Mechanism: `bubblewrap` netless profile in `capsule/run_smoke_linux.sh`.
2. Transport: UDS-only gateway path.
3. Expected: contract verifier emits `OK` for implemented probe set.

## 7. Downgrade and Fail-Closed Semantics

If contract verification fails:

1. `SCS` claim is invalid for this deployment.
2. Runtime must be treated as unconstrained for skill ingress safety analysis.
3. Deployment should fail closed for high-risk skill operations or explicitly run in reduced-claim mode.

Reduced-claim mode:

1. Keep NBE, SM, SAP claims if their own assumptions still hold.
2. Do not claim skill confinement.
3. Emit explicit audit marker indicating contract failure.

## 8. CI and Reproducibility Procedure

Recommended check sequence:

```bash
bash capsule/run_smoke.sh
python -m capsule.verify_contract \
  --contract spec/secureclaw_capsule_contract_v1.json \
  --report artifact_out/capsule_smoke.json \
  --out artifact_out/capsule_contract_verdict.json
```

Success criteria:

1. Process exit code is zero.
2. Verdict JSON has `status="OK"`.
3. All mandatory assertion IDs have `ok=true`.
