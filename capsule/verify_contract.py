from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any

import jsonschema


_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?)|)\}")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_json(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("expected_json_object")
    return obj


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _expand_vars(s: str, *, env: dict[str, str] | None = None, max_rounds: int = 8) -> str:
    """
    Expand ${VAR} and ${VAR:-default} patterns. Nested expansion is supported by iterating.
    """
    env2 = os.environ if env is None else env
    out = str(s or "")
    for _ in range(max_rounds):
        changed = False

        def repl(m: re.Match[str]) -> str:
            nonlocal changed
            var = str(m.group(1) or "")
            default = m.group(2)
            val = env2.get(var)
            if val is None or val == "":
                val = default if default is not None else ""
            changed = True
            return str(val)

        new = _VAR_RE.sub(repl, out)
        out = new
        if not changed:
            break
    return out


def _select_probe(assertion: dict[str, Any], report: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    kind = str(assertion.get("kind") or "")
    if kind == "fs_read":
        return (report.get("direct_fs_read") if isinstance(report.get("direct_fs_read"), dict) else None), "direct_fs_read"
    if kind == "internet_get":
        return (report.get("direct_internet") if isinstance(report.get("direct_internet"), dict) else None), "direct_internet"
    if kind == "http_post":
        return (report.get("direct_exfil_post") if isinstance(report.get("direct_exfil_post"), dict) else None), "direct_exfil_post"
    if kind == "gateway_act":
        return (report.get("gateway_act") if isinstance(report.get("gateway_act"), dict) else None), "gateway_act"
    if kind == "gateway_mcp_act":
        return (report.get("gateway_mcp_act") if isinstance(report.get("gateway_mcp_act"), dict) else None), "gateway_mcp_act"
    if kind == "exec":
        argv = assertion.get("argv")
        if isinstance(argv, list) and argv:
            if str(argv[0]) == "/usr/bin/true":
                return (report.get("direct_exec_true") if isinstance(report.get("direct_exec_true"), dict) else None), "direct_exec_true"
            if str(argv[0]) in ("/bin/sh", "/usr/bin/sh"):
                return (report.get("direct_exec_sh") if isinstance(report.get("direct_exec_sh"), dict) else None), "direct_exec_sh"
        # Fallback: no stable mapping.
        return None, "exec_unmapped"
    return None, f"unknown_kind:{kind}"


def _verdict_for_assertion(assertion: dict[str, Any], probe: dict[str, Any] | None) -> dict[str, Any]:
    aid = str(assertion.get("id") or "")
    kind = str(assertion.get("kind") or "")
    must_deny = bool(assertion.get("must_deny"))
    allow_skip = bool(assertion.get("allow_skip", False))

    out: dict[str, Any] = {
        "id": aid,
        "kind": kind,
        "must_deny": must_deny,
        "allow_skip": allow_skip,
        "ok": False,
        "reason_code": "UNSET",
        "details": {},
    }

    # Attach resolved parameters for auditability.
    if isinstance(assertion.get("path"), str):
        out["path"] = _expand_vars(str(assertion.get("path") or ""))
    if isinstance(assertion.get("url"), str):
        out["url"] = _expand_vars(str(assertion.get("url") or ""))
    if isinstance(assertion.get("argv"), list):
        out["argv"] = [str(x) for x in (assertion.get("argv") or [])]

    if probe is None:
        out["reason_code"] = "MISSING_PROBE"
        out["details"] = {}
        return out
    if bool(probe.get("skipped")):
        if allow_skip:
            out["ok"] = True
            out["reason_code"] = "SKIPPED_ALLOWED"
            out["details"] = {"skipped": True}
            return out
        out["reason_code"] = "SKIPPED"
        out["details"] = {"skipped": True}
        return out

    ok = bool(probe.get("ok"))

    if kind == "exec":
        # exec probes include `spawned` to distinguish denial from nonzero return codes.
        spawned = bool(probe.get("spawned", False))
        if must_deny:
            out["ok"] = not spawned
            out["reason_code"] = "PASS_DENY" if out["ok"] else "FAIL_MUST_DENY"
        else:
            out["ok"] = spawned and ok
            out["reason_code"] = "PASS_ALLOW" if out["ok"] else "FAIL_MUST_ALLOW"
        out["details"] = {k: probe.get(k) for k in ("ok", "spawned", "returncode", "error", "details", "note") if k in probe}
        return out

    if must_deny:
        out["ok"] = not ok
        out["reason_code"] = "PASS_DENY" if out["ok"] else "FAIL_MUST_DENY"
    else:
        out["ok"] = ok
        out["reason_code"] = "PASS_ALLOW" if out["ok"] else "FAIL_MUST_ALLOW"

    # Include a small stable subset for citations.
    out["details"] = {k: probe.get(k) for k in ("ok", "status", "http_status", "error", "details", "transport", "note") if k in probe}
    return out


def verify(*, contract_path: Path, report_path: Path, out_path: Path | None = None) -> tuple[bool, dict[str, Any]]:
    repo_root = _repo_root()

    contract = _load_json(contract_path)
    report = _load_json(report_path)

    schema_path = repo_root / "spec" / "secureclaw_capsule_contract_v1.schema.json"
    schema = _load_json(schema_path)
    jsonschema.validate(instance=contract, schema=schema)

    results: list[dict[str, Any]] = []
    for a in contract.get("assertions") or []:
        if not isinstance(a, dict):
            continue
        probe, probe_key = _select_probe(a, report)
        r = _verdict_for_assertion(a, probe)
        r["probe_key"] = str(probe_key)
        results.append(r)

    ok = all(bool(r.get("ok")) for r in results)
    verdict = {
        "status": "OK" if ok else "FAIL",
        "ok": bool(ok),
        "ts_unix": int(time.time()),
        "contract_path": str(contract_path),
        "contract_sha256": _sha256_file(contract_path),
        "report_path": str(report_path),
        "schema_path": str(schema_path),
        "schema_sha256": _sha256_file(schema_path),
        "summary": {
            "n_assertions": int(len(results)),
            "n_ok": int(sum(1 for r in results if bool(r.get("ok")))),
            "n_fail": int(sum(1 for r in results if not bool(r.get("ok")))),
        },
        "results": results,
    }
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(verdict, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    return ok, verdict


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--contract", default="spec/secureclaw_capsule_contract_v1.json")
    ap.add_argument("--report", required=True, help="capsule smoke report JSON path")
    ap.add_argument("--out", default="", help="optional verdict JSON output path")
    args = ap.parse_args()

    repo_root = _repo_root()
    contract_path = Path(str(args.contract)).expanduser()
    if not contract_path.is_absolute():
        contract_path = (repo_root / contract_path).resolve()
    report_path = Path(str(args.report)).expanduser().resolve()
    out_path = Path(str(args.out)).expanduser().resolve() if str(args.out or "").strip() else None

    ok, _verdict = verify(contract_path=contract_path, report_path=report_path, out_path=out_path)
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()

