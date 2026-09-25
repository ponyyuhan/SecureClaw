#!/usr/bin/env python3
"""Run one independent ASB plain/no-defense shard.

This is a scheduling wrapper only.  It reuses the ASB five-baseline runner's
official plain path, scenario construction, CSV schema, and summarizer.  The
wrapper adds:

* a matplotlib plotting stub for the local NumPy-2 ABI issue already seen in
  ASB imports;
* deterministic modulo sharding over the frozen ASB scenario order; and
* per-shard status/report files so shards can be merged later.

It does not change ASB prompts, labels, model calls, scoring, or metrics.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import io
import json
import os
import sys
import types
from pathlib import Path
from typing import Any, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _install_plotting_stub_for_numpy2_abi() -> None:
    if "matplotlib.pylab" in sys.modules:
        return
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            import matplotlib.pylab  # noqa: F401
        return
    except Exception:
        mpl = types.ModuleType("matplotlib")
        pylab = types.ModuleType("matplotlib.pylab")
        pyplot = types.ModuleType("matplotlib.pyplot")
        setattr(mpl, "pylab", pylab)
        setattr(mpl, "pyplot", pyplot)
        sys.modules["matplotlib"] = mpl
        sys.modules["matplotlib.pylab"] = pylab
        sys.modules["matplotlib.pyplot"] = pyplot


_install_plotting_stub_for_numpy2_abi()

from scripts import asb_five_baseline_compare as base  # noqa: E402


def _csv_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return list(csv.DictReader(handle))


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _scenario_key(scenario: Any) -> str:
    return "|".join(
        [
            str(getattr(scenario, "attack_type", "")),
            str(getattr(scenario, "agent_name", "")),
            str(getattr(getattr(scenario, "attack_tool", None), "tool_name", "")),
        ]
    )


def _filter_scenarios(scenarios: Sequence[Any], *, shard_index: int, num_shards: int) -> list[Any]:
    selected = [
        scenario
        for idx, scenario in enumerate(scenarios)
        if idx % int(num_shards) == int(shard_index)
    ]
    return selected


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("dry-run", "run", "summarize"))
    parser.add_argument("--out", required=True, help="Shard output directory.")
    parser.add_argument("--model", required=True)
    parser.add_argument("--attack-type", required=True, choices=base.DEFAULT_ATTACK_TYPES)
    parser.add_argument("--task-num", type=int, default=1)
    parser.add_argument("--shard-index", type=int, required=True)
    parser.add_argument("--num-shards", type=int, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    out = Path(args.out).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)

    if not os.environ.get("OPENAI_API_KEY") and os.environ.get("OPENROUTER_API_KEY"):
        os.environ["OPENAI_API_KEY"] = str(os.environ["OPENROUTER_API_KEY"])
    os.environ.setdefault("OPENAI_BASE_URL", "https://openrouter.ai/api/v1")
    os.environ.setdefault("ASB_ALLOW_OPENROUTER_MODELS", "1")
    os.environ.setdefault("ASB_COMPARE_MAX_WORKERS", "1")
    os.environ.setdefault("ASB_COMPARE_MAX_INFLIGHT", "1")
    os.environ.setdefault("ASB_COMPARE_OPENAI_TIMEOUT_S", "180")
    os.environ.setdefault("ASB_COMPARE_OPENAI_MAX_RETRIES", "3")
    os.environ.setdefault("ASB_STATUS_POLL_S", "5")

    scenarios = base.load_scenarios(attack_types=(str(args.attack_type),), task_num=int(args.task_num))
    selected = _filter_scenarios(
        scenarios,
        shard_index=int(args.shard_index),
        num_shards=int(args.num_shards),
    )
    csv_path = out / "plain" / f"{args.attack_type}.csv"
    manifest = {
        "schema_version": 1,
        "wrapper": "run_asb_plain_shard.py",
        "base_runner": "scripts/asb_five_baseline_compare.py",
        "algorithm_or_metric_changed": False,
        "model": str(args.model),
        "baseline": "plain",
        "attack_type": str(args.attack_type),
        "task_num": int(args.task_num),
        "shard_index": int(args.shard_index),
        "num_shards": int(args.num_shards),
        "total_scenarios_for_attack_type": len(scenarios),
        "shard_rows": len(selected),
        "csv_path": str(csv_path),
        "scenario_keys": [_scenario_key(scenario) for scenario in selected],
    }
    _write_json(out / "shard_manifest.json", manifest)

    if args.command == "dry-run":
        print(json.dumps({"status": "dry_run", **{k: manifest[k] for k in ("attack_type", "shard_index", "num_shards", "shard_rows")}}, sort_keys=True))
        return 0

    if args.command == "run":
        if not os.environ.get("OPENAI_API_KEY"):
            raise SystemExit("OPENAI_API_KEY or OPENROUTER_API_KEY is required")
        base._run_official_asb_attack_type(
            workdir=base.ASB_DIR,
            model=str(args.model),
            attack_type=str(args.attack_type),
            task_num=int(args.task_num),
            csv_path=csv_path,
            scenarios=selected,
            progress_cb=None,
        )

    summary = base._summarize_csv(csv_path)
    report = {
        "status": "OK" if int(summary.get("rows", 0) or 0) >= len(selected) else "PARTIAL",
        "manifest": manifest,
        "summary": summary,
        "rows_observed": len(_csv_rows(csv_path)),
    }
    _write_json(out / "summary.json", summary)
    _write_json(out / "report.json", report)
    print(json.dumps({"status": report["status"], "rows": report["rows_observed"], "expected": len(selected)}, sort_keys=True))
    return 0 if report["status"] == "OK" else 2


if __name__ == "__main__":
    raise SystemExit(main())
