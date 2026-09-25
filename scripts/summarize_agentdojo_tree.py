#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


def _pct(num: int, den: int) -> float | None:
    if den <= 0:
        return None
    return round(100.0 * num / den, 1)


def main() -> None:
    ap = argparse.ArgumentParser(description="Summarize AgentDojo benchmark JSON tree.")
    ap.add_argument("--root", required=True, help="Root directory containing <model>/<suite>/... JSON outputs.")
    ap.add_argument("--out", default="", help="Optional path to write JSON summary.")
    args = ap.parse_args()

    root = Path(args.root).expanduser().resolve()
    if not root.exists():
        raise SystemExit(f"missing root: {root}")

    per_suite: dict[str, dict[str, Any]] = {}
    per_task: dict[str, dict[str, Any]] = {}
    totals = defaultdict(int)

    json_files = sorted(root.rglob("*.json"))
    for path in json_files:
        obj = _load_json(path)
        if not obj:
            continue
        suite = str(obj.get("suite_name") or "")
        user_task = str(obj.get("user_task_id") or "")
        inj_task = obj.get("injection_task_id")
        if not suite or not user_task:
            continue
        if user_task.startswith("injection_task_"):
            continue

        task_key = f"{suite}/{user_task}"
        suite_entry = per_suite.setdefault(
            suite,
            {
                "benign_total": 0,
                "benign_utility_success": 0,
                "attack_total": 0,
                "attack_success": 0,
                "under_attack_utility_success": 0,
            },
        )
        task_entry = per_task.setdefault(
            task_key,
            {
                "suite": suite,
                "user_task_id": user_task,
                "benign_total": 0,
                "benign_utility_success": 0,
                "attack_total": 0,
                "attack_success": 0,
                "under_attack_utility_success": 0,
            },
        )

        utility = bool(obj.get("utility"))
        security = bool(obj.get("security"))
        if inj_task is None:
            suite_entry["benign_total"] += 1
            task_entry["benign_total"] += 1
            if utility:
                suite_entry["benign_utility_success"] += 1
                task_entry["benign_utility_success"] += 1
            totals["benign_total"] += 1
            if utility:
                totals["benign_utility_success"] += 1
        else:
            suite_entry["attack_total"] += 1
            task_entry["attack_total"] += 1
            if not security:
                suite_entry["attack_success"] += 1
                task_entry["attack_success"] += 1
                totals["attack_success"] += 1
            if utility:
                suite_entry["under_attack_utility_success"] += 1
                task_entry["under_attack_utility_success"] += 1
                totals["under_attack_utility_success"] += 1
            totals["attack_total"] += 1

    for entry in per_suite.values():
        entry["benign_utility_rate_pct"] = _pct(entry["benign_utility_success"], entry["benign_total"])
        entry["attack_asr_pct"] = _pct(entry["attack_success"], entry["attack_total"])
        entry["under_attack_utility_rate_pct"] = _pct(
            entry["under_attack_utility_success"], entry["attack_total"]
        )
    for entry in per_task.values():
        entry["benign_utility_rate_pct"] = _pct(entry["benign_utility_success"], entry["benign_total"])
        entry["attack_asr_pct"] = _pct(entry["attack_success"], entry["attack_total"])
        entry["under_attack_utility_rate_pct"] = _pct(
            entry["under_attack_utility_success"], entry["attack_total"]
        )

    summary = {
        "root": str(root),
        "totals": {
            "benign_total": totals["benign_total"],
            "benign_utility_success": totals["benign_utility_success"],
            "benign_utility_rate_pct": _pct(totals["benign_utility_success"], totals["benign_total"]),
            "attack_total": totals["attack_total"],
            "attack_success": totals["attack_success"],
            "attack_asr_pct": _pct(totals["attack_success"], totals["attack_total"]),
            "under_attack_utility_success": totals["under_attack_utility_success"],
            "under_attack_utility_rate_pct": _pct(
                totals["under_attack_utility_success"], totals["attack_total"]
            ),
        },
        "per_suite": dict(sorted(per_suite.items())),
        "per_task": dict(sorted(per_task.items())),
    }

    if args.out:
        out_path = Path(args.out).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(summary, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    print(json.dumps(summary, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
