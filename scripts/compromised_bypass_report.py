from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _as_bool(x: Any) -> bool:
    if isinstance(x, bool):
        return x
    s = str(x).strip().lower()
    return s in {"1", "true", "yes", "y"}


def _write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def _table_row(*, property_name: str, scenario: str, expected: str, observed: str, ok: bool, source: str) -> dict[str, Any]:
    return {
        "property": property_name,
        "scenario": scenario,
        "expected": expected,
        "observed": observed,
        "ok": bool(ok),
        "source": source,
    }


def _render_markdown(rows: list[dict[str, Any]]) -> str:
    out = [
        "# Compromised Runtime / Bypass Suite (Table B)",
        "",
        "| Property | Scenario | Expected | Observed | Pass | Source |",
        "|---|---|---|---|---:|---|",
    ]
    for r in rows:
        out.append(
            f"| {r['property']} | {r['scenario']} | {r['expected']} | {r['observed']} | "
            f"{'yes' if r['ok'] else 'no'} | `{r['source']}` |"
        )
    out.append("")
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact-report", default="artifact_out/report.json", help="Path to artifact report.json")
    ap.add_argument("--security-game", default="artifact_out/security_game_nbe.json", help="Path to NBE security game json")
    ap.add_argument("--capsule-verdict", default="artifact_out/capsule_contract_verdict.json", help="Path to capsule contract verdict json")
    ap.add_argument("--out-json", default="artifact_out/compromised_bypass_report.json", help="Output json path")
    ap.add_argument("--out-md", default="artifact_out/compromised_bypass_report.md", help="Output markdown path")
    args = ap.parse_args()

    artifact_path = Path(str(args.artifact_report)).expanduser().resolve()
    security_game_path = Path(str(args.security_game)).expanduser().resolve()
    capsule_verdict_path = Path(str(args.capsule_verdict)).expanduser().resolve()
    out_json = Path(str(args.out_json)).expanduser().resolve()
    out_md = Path(str(args.out_md)).expanduser().resolve()

    art = _load_json(artifact_path) if artifact_path.exists() else {}
    sec = _load_json(security_game_path) if security_game_path.exists() else {}
    cap = _load_json(capsule_verdict_path) if capsule_verdict_path.exists() else {}

    rows: list[dict[str, Any]] = []

    baselines = art.get("baselines") if isinstance(art.get("baselines"), dict) else {}
    capsule_smoke = art.get("capsule_smoke") if isinstance(art.get("capsule_smoke"), dict) else {}
    bypass_attempts = art.get("executor_bypass_attempts") if isinstance(art.get("executor_bypass_attempts"), dict) else {}

    # Downgrade/bypass openings should be observable in baseline (unsafe) variants.
    no_capsule = baselines.get("no_capsule_direct_exfil") if isinstance(baselines.get("no_capsule_direct_exfil"), dict) else {}
    rows.append(
        _table_row(
            property_name="SCS necessity",
            scenario="No capsule direct exfil",
            expected="bypass possible",
            observed=f"ok={_as_bool(no_capsule.get('ok'))}",
            ok=_as_bool(no_capsule.get("ok")),
            source=f"{artifact_path}:baselines.no_capsule_direct_exfil",
        )
    )

    no_nbe = baselines.get("no_nbe_insecure_executor") if isinstance(baselines.get("no_nbe_insecure_executor"), dict) else {}
    rows.append(
        _table_row(
            property_name="NBE necessity",
            scenario="No NBE insecure executor",
            expected="ALLOW_INSECURE observable",
            observed=f"reason_code={str(no_nbe.get('reason_code') or '')}",
            ok=str(no_nbe.get("reason_code") or "") == "ALLOW_INSECURE",
            source=f"{artifact_path}:baselines.no_nbe_insecure_executor",
        )
    )

    loopback = baselines.get("capsule_loopback_http_exfil") if isinstance(baselines.get("capsule_loopback_http_exfil"), dict) else {}
    loopback_exfil = loopback.get("direct_exfil_post") if isinstance(loopback.get("direct_exfil_post"), dict) else {}
    rows.append(
        _table_row(
            property_name="SCS transport caveat",
            scenario="Capsule with loopback HTTP exfil",
            expected="downgrade can reopen bypass",
            observed=f"ok={_as_bool(loopback_exfil.get('ok'))}",
            ok=_as_bool(loopback_exfil.get("ok")),
            source=f"{artifact_path}:baselines.capsule_loopback_http_exfil.direct_exfil_post",
        )
    )

    # Full system fail-closed checks.
    miss_pf = bypass_attempts.get("missing_evidence") if isinstance(bypass_attempts.get("missing_evidence"), dict) else {}
    rows.append(
        _table_row(
            property_name="NBE fail-closed",
            scenario="Missing proof share",
            expected="DENY",
            observed=f"status={str(miss_pf.get('status') or '')}",
            ok=str(miss_pf.get("status") or "") == "DENY",
            source=f"{artifact_path}:executor_bypass_attempts.missing_evidence",
        )
    )

    one_pf = bypass_attempts.get("one_server_proof_only") if isinstance(bypass_attempts.get("one_server_proof_only"), dict) else {}
    rows.append(
        _table_row(
            property_name="NBE fail-closed",
            scenario="One-server proof only",
            expected="DENY",
            observed=f"status={str(one_pf.get('status') or '')}",
            ok=str(one_pf.get("status") or "") == "DENY",
            source=f"{artifact_path}:executor_bypass_attempts.one_server_proof_only",
        )
    )

    fs_read = capsule_smoke.get("direct_fs_read") if isinstance(capsule_smoke.get("direct_fs_read"), dict) else {}
    rows.append(
        _table_row(
            property_name="SCS mediation",
            scenario="Host secret direct fs read",
            expected="deny",
            observed=f"ok={_as_bool(fs_read.get('ok'))}",
            ok=not _as_bool(fs_read.get("ok")),
            source=f"{artifact_path}:capsule_smoke.direct_fs_read",
        )
    )

    net = capsule_smoke.get("direct_internet") if isinstance(capsule_smoke.get("direct_internet"), dict) else {}
    rows.append(
        _table_row(
            property_name="SCS mediation",
            scenario="Public internet egress",
            expected="deny",
            observed=f"ok={_as_bool(net.get('ok'))}",
            ok=not _as_bool(net.get("ok")),
            source=f"{artifact_path}:capsule_smoke.direct_internet",
        )
    )

    gate_act = capsule_smoke.get("gateway_act") if isinstance(capsule_smoke.get("gateway_act"), dict) else {}
    rows.append(
        _table_row(
            property_name="SCS liveness",
            scenario="Mediated gateway act",
            expected="allow",
            observed=f"ok={_as_bool(gate_act.get('ok'))}",
            ok=_as_bool(gate_act.get("ok")),
            source=f"{artifact_path}:capsule_smoke.gateway_act",
        )
    )

    # Security game checks (NBE theorem harness).
    checks = sec.get("checks") if isinstance(sec.get("checks"), list) else []
    for chk in checks:
        if not isinstance(chk, dict):
            continue
        nm = str(chk.get("name") or "")
        if nm in {
            "valid_dual_proof_accepts",
            "replay_denied",
            "session_binding_denied",
            "caller_binding_denied",
            "hctx_external_principal_binding_denied",
            "hctx_delegation_jti_binding_denied",
            "request_hash_binding_denied",
        }:
            rows.append(
                _table_row(
                    property_name="NBE theorem harness",
                    scenario=nm,
                    expected=str(chk.get("want") or ""),
                    observed=f"{str(chk.get('got') or '')}/{str(chk.get('reason_code') or '')}",
                    ok=_as_bool(chk.get("ok")),
                    source=f"{security_game_path}:checks[{nm}]",
                )
            )

    cap_ok = bool(cap.get("ok")) if isinstance(cap, dict) else False
    rows.append(
        _table_row(
            property_name="SCS contract",
            scenario="Capsule contract verdict",
            expected="OK",
            observed=f"ok={cap_ok}",
            ok=cap_ok,
            source=str(capsule_verdict_path),
        )
    )

    n_ok = sum(1 for r in rows if bool(r.get("ok")))
    out = {
        "status": "OK",
        "inputs": {
            "artifact_report": str(artifact_path),
            "security_game": str(security_game_path),
            "capsule_verdict": str(capsule_verdict_path),
        },
        "summary": {
            "n_rows": int(len(rows)),
            "n_pass": int(n_ok),
            "pass_rate": (float(n_ok) / float(len(rows))) if rows else 0.0,
        },
        "rows": rows,
    }
    _write_json(out_json, out)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(_render_markdown(rows), encoding="utf-8")
    print(str(out_json))
    print(str(out_md))


if __name__ == "__main__":
    main()
