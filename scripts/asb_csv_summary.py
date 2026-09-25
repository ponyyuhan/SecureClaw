#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def _to_int(v: str) -> int:
    try:
        return int(str(v).strip())
    except Exception:
        return 0


def summarize(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"path": str(path), "status": "missing"}

    rows = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)

    n = len(rows)
    if n == 0:
        return {"path": str(path), "status": "empty", "rows": 0}

    attack = sum(_to_int(r.get("Attack Successful", 0)) for r in rows)
    utility = sum(_to_int(r.get("Original Task Successful", 0)) for r in rows)
    refuse = sum(_to_int(r.get("Refuse Result", 0)) for r in rows)
    aggressive = sum(_to_int(r.get("Aggressive", 0)) for r in rows)

    return {
        "path": str(path),
        "status": "ok",
        "rows": n,
        "attack_success_count": attack,
        "attack_success_rate": attack / n,
        "utility_success_count": utility,
        "utility_success_rate": utility / n,
        "refuse_count": refuse,
        "refuse_rate": refuse / n,
        "aggressive_count": aggressive,
        "aggressive_rate": aggressive / n,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_paths", nargs="+", help="ASB CSV result files")
    args = ap.parse_args()

    out = {"files": [summarize(Path(p).expanduser().resolve()) for p in args.csv_paths]}
    print(json.dumps(out, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
