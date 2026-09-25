#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

_FALLBACK_EXPECTED_ROWS: dict[str, dict[str, int]] = {
    "banking": {"benign": 16, "under_attack": 16 * 9},
    "slack": {"benign": 21, "under_attack": 21 * 5},
    "travel": {"benign": 20, "under_attack": 20 * 7},
    "workspace": {"benign": 40, "under_attack": 40 * 6},
}


def _safe_rate(n: int, d: int) -> float | None:
    if d <= 0:
        return None
    return float(n) / float(d)


def _iter_json_objects(path: Path):
    txt = path.read_text(encoding="utf-8", errors="replace")
    dec = json.JSONDecoder()
    i = 0
    n = len(txt)
    while i < n:
        while i < n and txt[i].isspace():
            i += 1
        if i >= n:
            break
        try:
            obj, j = dec.raw_decode(txt, i)
            i = j
            yield obj
        except json.JSONDecodeError:
            i += 1


def _compute_expected_rows(benchmark_version: str) -> dict[str, dict[str, int]]:
    """
    Derive expected denominators from AgentDojo suite metadata.
    Falls back to legacy constants if metadata loading fails.
    """
    repo_root = Path(__file__).resolve().parents[1]
    src_root = repo_root / "third_party" / "ipiguard" / "agentdojo" / "src"
    if str(src_root) not in sys.path:
        sys.path.insert(0, str(src_root))
    try:
        from agentdojo.task_suite.load_suites import get_suite  # type: ignore

        out: dict[str, dict[str, int]] = {}
        for suite_name in ("banking", "slack", "travel", "workspace"):
            suite = get_suite(str(benchmark_version), suite_name)
            benign = int(len(suite.user_tasks))
            under_attack = 0
            if hasattr(suite, "get_injections_for_user_task"):
                for ut in suite.user_tasks.values():
                    under_attack += int(len(suite.get_injections_for_user_task(ut)))
            else:
                under_attack = benign * int(len(getattr(suite, "injection_tasks", {}) or {}))
            out[suite_name] = {"benign": benign, "under_attack": under_attack}
        return out
    except Exception:
        return {k: dict(v) for k, v in _FALLBACK_EXPECTED_ROWS.items()}


def _summarize_results_jsonl(path: Path, mode: str) -> dict[str, Any]:
    if not path.exists():
        return {"status": "missing", "path": str(path), "rows": 0, "mode": mode}

    dedup: dict[tuple[int, int | None], dict[str, Any]] = {}
    raw = 0
    for obj in _iter_json_objects(path):
        if not isinstance(obj, dict):
            continue
        if "user_task_id" not in obj:
            continue

        iid = obj.get("injection_task_id")
        if mode == "under_attack" and iid is None:
            continue
        if mode == "benign" and iid is not None:
            continue

        try:
            uid = int(obj.get("user_task_id"))
            key = (uid, int(iid)) if iid is not None else (uid, None)
        except Exception:
            continue

        dedup[key] = obj
        raw += 1

    rows = len(dedup)
    security_true = 0
    utility_true = 0
    for obj in dedup.values():
        security_true += int(bool(obj.get("security")))
        utility_true += int(bool(obj.get("utility")))

    out: dict[str, Any] = {
        "status": "ok",
        "mode": mode,
        "path": str(path),
        "raw_rows": raw,
        "rows": rows,
        "duplicate_rows": max(0, raw - rows),
        "security_true_count": security_true,
        "security_true_rate": _safe_rate(security_true, rows),
        "utility_success_count": utility_true,
        "utility_success_rate": _safe_rate(utility_true, rows),
    }
    if mode == "under_attack":
        out["attack_success_count"] = security_true
        out["attack_success_rate"] = _safe_rate(security_true, rows)
    return out


def _summarize_drift_suite(root: Path, model: str, suite: str, attack_name: str, mode: str) -> dict[str, Any]:
    suite_root = root / "drift_workspace" / "runs" / model / suite
    if not suite_root.exists():
        return {"status": "missing", "mode": mode, "path": str(suite_root), "rows": 0}

    dedup: dict[tuple[int, int | None], dict[str, Any]] = {}
    raw = 0
    if mode == "under_attack":
        pat = re.compile(r"user_task_(\d+).+injection_task_(\d+)\.json$")
        paths = sorted(suite_root.glob(f"user_task_*/{attack_name}/injection_task_*.json"))
    else:
        pat = re.compile(r"user_task_(\d+)/none/none\.json$")
        paths = sorted(suite_root.glob("user_task_*/none/none.json"))

    for p in paths:
        m = pat.search(str(p))
        if not m:
            continue
        try:
            uid = int(m.group(1))
            iid = int(m.group(2)) if mode == "under_attack" else None
            obj = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        dedup[(uid, iid)] = obj
        raw += 1

    rows = len(dedup)
    security_true = 0
    utility_true = 0
    for obj in dedup.values():
        security_true += int(bool(obj.get("security")))
        utility_true += int(bool(obj.get("utility")))

    out: dict[str, Any] = {
        "status": "ok",
        "mode": mode,
        "path": str(suite_root),
        "raw_rows": raw,
        "rows": rows,
        "duplicate_rows": max(0, raw - rows),
        "security_true_count": security_true,
        "security_true_rate": _safe_rate(security_true, rows),
        "utility_success_count": utility_true,
        "utility_success_rate": _safe_rate(utility_true, rows),
    }
    if mode == "under_attack":
        out["attack_success_count"] = security_true
        out["attack_success_rate"] = _safe_rate(security_true, rows)
    return out


def _render_md(rep: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# AgentDojo Five-Baseline Fairness Report")
    lines.append("")
    lines.append(f"- benchmark_version: `{rep.get('benchmark_version')}`")
    lines.append(f"- model: `{rep.get('model')}`")
    lines.append(f"- attack_name: `{rep.get('attack_name')}`")
    fairness = rep.get("fairness", {}) if isinstance(rep.get("fairness"), dict) else {}
    lines.append(f"- equal_attack_rows_all: `{fairness.get('equal_attack_rows_all')}`")
    lines.append(f"- equal_benign_rows_all: `{fairness.get('equal_benign_rows_all')}`")
    lines.append(f"- equal_rows_all: `{fairness.get('equal_rows_all')}`")

    reasons = fairness.get("reasons")
    if isinstance(reasons, list) and reasons:
        lines.append("- reasons:")
        for r in reasons:
            lines.append(f"  - {r}")
    lines.append("")

    lines.append("## Suites")
    suites = rep.get("suites", {}) if isinstance(rep.get("suites"), dict) else {}
    for sname in ("banking", "slack", "travel", "workspace"):
        s = suites.get(sname, {}) if isinstance(suites.get(sname), dict) else {}
        er = s.get("expected_rows") if isinstance(s.get("expected_rows"), dict) else {}
        lines.append(
            f"- {sname}: expected_benign_rows={er.get('benign')} expected_attack_rows={er.get('under_attack')} "
            f"equal_benign_rows={s.get('equal_benign_rows')} equal_attack_rows={s.get('equal_attack_rows')}"
        )
        for mode in ("benign", "under_attack"):
            md = s.get(mode, {}) if isinstance(s.get(mode), dict) else {}
            lines.append(f"  - mode={mode}")
            for base in ("plain", "secureclaw", "ipiguard", "drift", "faramesh"):
                b = md.get(base, {}) if isinstance(md.get(base), dict) else {}
                if mode == "under_attack":
                    lines.append(
                        f"    - {base}: rows={b.get('rows')} asr={b.get('attack_success_rate')} utility={b.get('utility_success_rate')} status={b.get('status')}"
                    )
                else:
                    lines.append(
                        f"    - {base}: rows={b.get('rows')} utility={b.get('utility_success_rate')} status={b.get('status')}"
                    )
    lines.append("")

    lines.append("## Overall")
    overall = rep.get("overall", {}) if isinstance(rep.get("overall"), dict) else {}
    for mode in ("benign", "under_attack"):
        md = overall.get(mode, {}) if isinstance(overall.get(mode), dict) else {}
        lines.append(f"- mode={mode}")
        for base in ("plain", "secureclaw", "ipiguard", "drift", "faramesh"):
            b = md.get(base, {}) if isinstance(md.get(base), dict) else {}
            if mode == "under_attack":
                lines.append(
                    f"  - {base}: rows={b.get('rows')} asr={b.get('attack_success_rate')} utility={b.get('utility_success_rate')}"
                )
            else:
                lines.append(
                    f"  - {base}: rows={b.get('rows')} utility={b.get('utility_success_rate')}"
                )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Compare plain/SecureClaw/IPIGuard/DRIFT/Faramesh on fair AgentDojo denominators (benign + under_attack).")
    ap.add_argument("--plain-secureclaw-root", default="", help="Root from run_agentdojo_native_plain_secureclaw.py (contains plain/ and secureclaw/).")
    ap.add_argument("--plain-root", default="", help="Optional explicit plain root containing benign/<suite>/results.jsonl and under_attack/<suite>/results.jsonl.")
    ap.add_argument("--secureclaw-root", default="", help="Optional explicit secureclaw root containing benign/<suite>/results.jsonl and under_attack/<suite>/results.jsonl.")
    ap.add_argument("--ipiguard-root", required=True, help="IPIGuard output root containing benign/<suite>/results.jsonl and under_attack/<suite>/results.jsonl")
    ap.add_argument("--drift-run-root", required=True, help="External run root containing drift_workspace/runs/<model>/<suite>")
    ap.add_argument("--faramesh-root", required=True, help="Faramesh output root containing benign/<suite>/results.jsonl and under_attack/<suite>/results.jsonl")
    ap.add_argument("--model", default="gpt-4o-mini-2024-07-18")
    ap.add_argument("--attack-name", default="important_instructions")
    ap.add_argument("--benchmark-version", default="v1.1.2")
    ap.add_argument("--require-equal-attacks", type=int, default=1)
    ap.add_argument("--require-equal-benign", type=int, default=1)
    ap.add_argument("--output-json", required=True)
    ap.add_argument("--output-md", required=True)
    args = ap.parse_args()

    ps_raw = str(args.plain_secureclaw_root).strip()
    ps_root = Path(ps_raw).expanduser().resolve() if ps_raw else None
    plain_root = Path(str(args.plain_root)).expanduser().resolve() if str(args.plain_root).strip() else (ps_root / "plain" if ps_root is not None else None)
    secure_root = (
        Path(str(args.secureclaw_root)).expanduser().resolve()
        if str(args.secureclaw_root).strip()
        else (ps_root / "secureclaw" if ps_root is not None else None)
    )
    if plain_root is None or secure_root is None:
        raise SystemExit("plain/secureclaw roots are missing. Provide --plain-secureclaw-root or both --plain-root and --secureclaw-root.")

    ipi_root = Path(str(args.ipiguard_root)).expanduser().resolve()
    drift_root = Path(str(args.drift_run_root)).expanduser().resolve()
    far_root = Path(str(args.faramesh_root)).expanduser().resolve()

    out: dict[str, Any] = {
        "status": "OK",
        "benchmark": "AgentDojo-native-five-baseline-fair",
        "benchmark_version": str(args.benchmark_version),
        "model": str(args.model),
        "attack_name": str(args.attack_name),
        "paths": {
            "plain_secureclaw_root": str(ps_root) if ps_root is not None else "",
            "plain_root": str(plain_root),
            "secureclaw_root": str(secure_root),
            "ipiguard_root": str(ipi_root),
            "drift_run_root": str(drift_root),
            "faramesh_root": str(far_root),
        },
        "suites": {},
    }

    expected_rows = _compute_expected_rows(str(args.benchmark_version))
    out["expected_rows"] = expected_rows

    attack_reasons: list[str] = []
    benign_reasons: list[str] = []

    totals: dict[str, dict[str, dict[str, int]]] = {
        "under_attack": {
            "plain": {"rows": 0, "security_true": 0, "utility_success": 0},
            "secureclaw": {"rows": 0, "security_true": 0, "utility_success": 0},
            "ipiguard": {"rows": 0, "security_true": 0, "utility_success": 0},
            "drift": {"rows": 0, "security_true": 0, "utility_success": 0},
            "faramesh": {"rows": 0, "security_true": 0, "utility_success": 0},
        },
        "benign": {
            "plain": {"rows": 0, "security_true": 0, "utility_success": 0},
            "secureclaw": {"rows": 0, "security_true": 0, "utility_success": 0},
            "ipiguard": {"rows": 0, "security_true": 0, "utility_success": 0},
            "drift": {"rows": 0, "security_true": 0, "utility_success": 0},
            "faramesh": {"rows": 0, "security_true": 0, "utility_success": 0},
        },
    }

    for suite in ("banking", "slack", "travel", "workspace"):
        suite_out: dict[str, Any] = {
            "expected_rows": dict(expected_rows.get(suite, _FALLBACK_EXPECTED_ROWS[suite])),
        }
        for mode in ("under_attack", "benign"):
            plain = _summarize_results_jsonl(plain_root / mode / suite / "results.jsonl", mode)
            secure = _summarize_results_jsonl(secure_root / mode / suite / "results.jsonl", mode)
            ipi = _summarize_results_jsonl(ipi_root / mode / suite / "results.jsonl", mode)
            drift = _summarize_drift_suite(drift_root, str(args.model), suite, str(args.attack_name), mode)
            faramesh = _summarize_results_jsonl(far_root / mode / suite / "results.jsonl", mode)

            expected = int(expected_rows.get(suite, _FALLBACK_EXPECTED_ROWS[suite]).get(mode, 0))
            rows = {
                "plain": int(plain.get("rows") or 0),
                "secureclaw": int(secure.get("rows") or 0),
                "ipiguard": int(ipi.get("rows") or 0),
                "drift": int(drift.get("rows") or 0),
                "faramesh": int(faramesh.get("rows") or 0),
            }
            equal_rows = len(set(rows.values())) == 1
            suite_out[f"equal_{mode}_rows"] = equal_rows
            if mode == "under_attack":
                suite_out["equal_attack_rows"] = equal_rows
            else:
                suite_out["equal_benign_rows"] = equal_rows
            if not equal_rows:
                if mode == "under_attack":
                    attack_reasons.append(f"rows_mismatch:{mode}:{suite}:{rows}")
                else:
                    benign_reasons.append(f"rows_mismatch:{mode}:{suite}:{rows}")
            for base, r in rows.items():
                if r != expected:
                    if mode == "under_attack":
                        attack_reasons.append(f"rows_not_expected:{mode}:{suite}:{base}:{r}!={expected}")
                    else:
                        benign_reasons.append(f"rows_not_expected:{mode}:{suite}:{base}:{r}!={expected}")

            suite_out[mode] = {
                "plain": plain,
                "secureclaw": secure,
                "ipiguard": ipi,
                "drift": drift,
                "faramesh": faramesh,
            }

            for base, rec in (("plain", plain), ("secureclaw", secure), ("ipiguard", ipi), ("drift", drift), ("faramesh", faramesh)):
                totals[mode][base]["rows"] += int(rec.get("rows") or 0)
                totals[mode][base]["security_true"] += int(rec.get("security_true_count") or 0)
                totals[mode][base]["utility_success"] += int(rec.get("utility_success_count") or 0)

        out["suites"][suite] = suite_out

    overall: dict[str, Any] = {}
    for mode in ("benign", "under_attack"):
        mode_out: dict[str, Any] = {}
        for base in ("plain", "secureclaw", "ipiguard", "drift", "faramesh"):
            agg = totals[mode][base]
            rows = int(agg["rows"])
            sec = int(agg["security_true"])
            util = int(agg["utility_success"])
            rec: dict[str, Any] = {
                "rows": rows,
                "security_true_count": sec,
                "security_true_rate": _safe_rate(sec, rows),
                "utility_success_count": util,
                "utility_success_rate": _safe_rate(util, rows),
            }
            if mode == "under_attack":
                rec["attack_success_count"] = sec
                rec["attack_success_rate"] = _safe_rate(sec, rows)
            mode_out[base] = rec
        overall[mode] = mode_out
    out["overall"] = overall

    all_reasons = [*attack_reasons, *benign_reasons]
    out["fairness"] = {
        "equal_attack_rows_all": len(attack_reasons) == 0,
        "equal_benign_rows_all": len(benign_reasons) == 0,
        "equal_rows_all": len(all_reasons) == 0,
        "attack_reasons": attack_reasons,
        "benign_reasons": benign_reasons,
        "reasons": all_reasons,
    }

    invalid = False
    if attack_reasons and int(args.require_equal_attacks) == 1:
        invalid = True
    if benign_reasons and int(args.require_equal_benign) == 1:
        invalid = True
    if invalid:
        out["status"] = "INVALID_FAIRNESS"

    out_json = Path(str(args.output_json)).expanduser().resolve()
    out_md = Path(str(args.output_md)).expanduser().resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(out, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    out_md.write_text(_render_md(out), encoding="utf-8")

    print(str(out_json))
    print(str(out_md))

    if invalid:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
