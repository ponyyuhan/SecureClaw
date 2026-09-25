#!/usr/bin/env python3
"""Recovery ablation: run ASB with SecureClaw recovery enabled vs disabled.

Uses the same SecureClawInfra + evaluation loop as asb_five_baseline_compare.py,
toggling SECURECLAW_RECOVERY_DISABLED between configs.

Produces:
  artifact_out/recovery_ablation/report.json   — machine-readable
  stdout                                        — human-readable summary
"""
from __future__ import annotations

import csv
import json
import logging
import os
import random
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"

# Ensure imports resolve
for _p in (REPO_ROOT, SCRIPTS_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from asb_five_baseline_compare import (  # type: ignore
    DEFAULT_ATTACK_TYPES,
    SecureClawInfra,
    Scenario,
    _append_csv_row,
    _attack_success,
    _build_runtime,
    _ensure_csv,
    _extend_whitelist,
    _message_contents,
    _openai_client,
    _run_secureclaw_case,
    _serialize_messages,
    _summarize_csv,
    _utility_success,
    _refusal_result,
    _attack_query,
    load_scenarios,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
)
log = logging.getLogger("recovery_ablation")

N_PER_ATTACK = int(os.getenv("RECOVERY_ABLATION_N_PER_ATTACK", "10"))
MODEL = os.getenv("RECOVERY_ABLATION_MODEL", "openai/gpt-4o-mini-2024-07-18")
SEED = 42


# ---------------------------------------------------------------------------
# Sampling
# ---------------------------------------------------------------------------

def _sample_scenarios(
    all_scenarios: list[Scenario],
    *,
    n_per_attack: int,
    attack_types: tuple[str, ...],
    seed: int = SEED,
) -> dict[str, list[Scenario]]:
    """Return at most *n_per_attack* scenarios per attack type (deterministic)."""
    by_attack: dict[str, list[Scenario]] = {at: [] for at in attack_types}
    for s in all_scenarios:
        if s.attack_type in by_attack:
            by_attack[s.attack_type].append(s)
    rng = random.Random(seed)
    sampled: dict[str, list[Scenario]] = {}
    for at, pool in by_attack.items():
        if len(pool) <= n_per_attack:
            sampled[at] = list(pool)
        else:
            sampled[at] = rng.sample(pool, n_per_attack)
    return sampled


# ---------------------------------------------------------------------------
# Single-config runner
# ---------------------------------------------------------------------------

def run_config(
    config_name: str,
    *,
    sampled: dict[str, list[Scenario]],
    model: str,
    out_dir: Path,
    recovery_disabled: bool,
) -> dict[str, Any]:
    """Run SecureClaw on the sampled scenarios and return per-attack + overall metrics."""
    config_dir = out_dir / config_name
    config_dir.mkdir(parents=True, exist_ok=True)

    # Set the recovery flag *before* launching infra (it propagates via env)
    os.environ["SECURECLAW_RECOVERY_DISABLED"] = "1" if recovery_disabled else "0"

    log.info("=== Config: %s  (SECURECLAW_RECOVERY_DISABLED=%s) ===", config_name, os.environ["SECURECLAW_RECOVERY_DISABLED"])

    infra_dir = config_dir / "_infra"

    with SecureClawInfra(infra_dir) as infra:
        os.environ.update(infra.env_patch)

        per_attack: dict[str, dict[str, Any]] = {}

        for attack_type, scenarios in sampled.items():
            csv_path = config_dir / f"{attack_type}.csv"
            _ensure_csv(csv_path)

            n = len(scenarios)
            log.info("  %s  (%d rows) ...", attack_type, n)

            done = 0
            for scenario in scenarios:
                try:
                    messages, extra = _run_secureclaw_case(scenario, model)
                except Exception as exc:
                    log.warning("    row error (%s / %s): %s", scenario.agent_name, scenario.attack_tool.tool_name, exc)
                    messages = [{"role": "assistant", "content": f"ERROR: {type(exc).__name__}: {exc}", "tool_calls": []}]
                _append_csv_row(csv_path, scenario=scenario, messages=messages)
                done += 1
                if done % 5 == 0 or done == n:
                    log.info("    %d/%d", done, n)

            summary = _summarize_csv(csv_path)
            per_attack[attack_type] = summary
            log.info("    => ASR=%.1f%%  Utility=%.1f%%  RR=%.1f%%",
                      100 * summary.get("attack_success_rate", 0),
                      100 * summary.get("utility_success_rate", 0),
                      100 * summary.get("refuse_rate", 0))

    # Aggregate
    total_rows = sum(int(s.get("rows", 0)) for s in per_attack.values())
    total_attack = sum(int(s.get("attack_success_count", 0)) for s in per_attack.values())
    total_utility = sum(int(s.get("utility_success_count", 0)) for s in per_attack.values())
    total_refuse = sum(int(s.get("refuse_count", 0)) for s in per_attack.values())
    total_blocked = total_rows - total_attack  # attacks denied

    # Post-denial utility: task succeeded AND attack was blocked
    # We need to re-read CSVs to compute this
    post_denial_success = 0
    for attack_type in sampled:
        csv_path = config_dir / f"{attack_type}.csv"
        if not csv_path.exists():
            continue
        with csv_path.open("r", encoding="utf-8", errors="replace") as fh:
            for row in csv.DictReader(fh):
                attack_ok = int(str(row.get("Attack Successful") or "0"))
                utility_ok = int(str(row.get("Original Task Successful") or "0"))
                if attack_ok == 0 and utility_ok == 1:
                    post_denial_success += 1

    overall = {
        "rows": total_rows,
        "attack_success_count": total_attack,
        "attack_success_rate": (total_attack / total_rows) if total_rows else 0.0,
        "utility_success_count": total_utility,
        "utility_success_rate": (total_utility / total_rows) if total_rows else 0.0,
        "refuse_count": total_refuse,
        "refuse_rate": (total_refuse / total_rows) if total_rows else 0.0,
        "blocked_count": total_blocked,
        "post_denial_utility_count": post_denial_success,
        "post_denial_utility_rate": (post_denial_success / total_blocked) if total_blocked else 0.0,
    }

    return {"per_attack": per_attack, "overall": overall}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not api_key:
        log.error("OPENROUTER_API_KEY not set")
        sys.exit(1)
    # Route through OpenRouter
    os.environ["OPENAI_API_KEY"] = api_key
    os.environ["OPENAI_BASE_URL"] = "https://openrouter.ai/api/v1"

    model = MODEL
    n_per_attack = N_PER_ATTACK
    attack_types = DEFAULT_ATTACK_TYPES

    out_dir = REPO_ROOT / "artifact_out" / "recovery_ablation"
    out_dir.mkdir(parents=True, exist_ok=True)

    log.info("Loading scenarios (task_num=1, attack_types=%s) ...", attack_types)
    all_scenarios = load_scenarios(attack_types=attack_types, task_num=1)
    log.info("  Total scenarios loaded: %d", len(all_scenarios))

    sampled = _sample_scenarios(all_scenarios, n_per_attack=n_per_attack, attack_types=attack_types)
    total_sampled = sum(len(v) for v in sampled.values())
    for at, sc_list in sampled.items():
        log.info("  %s: %d rows", at, len(sc_list))
    log.info("  Total sampled: %d", total_sampled)

    configs = [
        ("secureclaw_full", False),
        ("secureclaw_no_recovery", True),
    ]

    results: dict[str, Any] = {}
    for config_name, recovery_disabled in configs:
        results[config_name] = run_config(
            config_name,
            sampled=sampled,
            model=model,
            out_dir=out_dir,
            recovery_disabled=recovery_disabled,
        )

    # Build report
    report = {
        "experiment": "recovery_ablation",
        "model": model,
        "n_per_attack": n_per_attack,
        "attack_types": list(attack_types),
        "total_rows_per_config": total_sampled,
        "seed": SEED,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "configs": results,
    }
    report_path = out_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    log.info("Report written to %s", report_path)

    # Print summary
    print()
    print("=" * 72)
    print("  Recovery Ablation Results")
    print("=" * 72)
    print(f"  Model: {model}   Rows/config: {total_sampled}   Seed: {SEED}")
    print()
    hdr = f"{'Config':<28} {'N':>4}  {'ASR':>7}  {'Utility':>7}  {'PostDen':>7}  {'Refuse':>7}"
    print(hdr)
    print("-" * len(hdr))
    for config_name, _ in configs:
        o = results[config_name]["overall"]
        print(
            f"{config_name:<28} {o['rows']:>4}  "
            f"{100*o['attack_success_rate']:>6.1f}%  "
            f"{100*o['utility_success_rate']:>6.1f}%  "
            f"{100*o['post_denial_utility_rate']:>6.1f}%  "
            f"{100*o['refuse_rate']:>6.1f}%"
        )
    print()

    # Per-attack detail
    for config_name, _ in configs:
        print(f"--- {config_name} per-attack ---")
        pa = results[config_name]["per_attack"]
        for at in attack_types:
            s = pa.get(at, {})
            print(
                f"  {at:<22}  N={int(s.get('rows',0)):>3}  "
                f"ASR={100*s.get('attack_success_rate',0):>5.1f}%  "
                f"Util={100*s.get('utility_success_rate',0):>5.1f}%  "
                f"RR={100*s.get('refuse_rate',0):>5.1f}%"
            )
        print()

    # Delta summary
    full_o = results["secureclaw_full"]["overall"]
    norec_o = results["secureclaw_no_recovery"]["overall"]
    util_delta = 100 * (full_o["utility_success_rate"] - norec_o["utility_success_rate"])
    pd_delta = 100 * (full_o["post_denial_utility_rate"] - norec_o["post_denial_utility_rate"])
    print("Delta (full - no_recovery):")
    print(f"  Utility:             {util_delta:>+.1f} pp")
    print(f"  Post-denial utility: {pd_delta:>+.1f} pp")
    print(f"  ASR delta:           {100*(full_o['attack_success_rate'] - norec_o['attack_success_rate']):>+.1f} pp")
    print()


if __name__ == "__main__":
    main()
