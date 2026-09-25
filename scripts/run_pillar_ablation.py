#!/usr/bin/env python3
"""
Three-pillar ablation study for SecureClaw.

Tests four configurations by toggling the two security pillars:
  - Full:  EXECUTOR_INSECURE_ALLOW=0, SECURECLAW_SM_DISABLED=0  (baseline)
  - -NBE:  EXECUTOR_INSECURE_ALLOW=1, SECURECLAW_SM_DISABLED=0  (no executor authorization)
  - -SM:   EXECUTOR_INSECURE_ALLOW=0, SECURECLAW_SM_DISABLED=1  (no handle-first confinement)
  - -Both: EXECUTOR_INSECURE_ALLOW=1, SECURECLAW_SM_DISABLED=1  (neither pillar)

Each configuration spawns policy servers, executor, and gateway, then runs the
selected benchmark(s) against them.  Results are collected into a structured
JSON output and a summary Markdown report.

Usage:
    python scripts/run_pillar_ablation.py --benchmarks paper_eval --output-dir artifact_out
    python scripts/run_pillar_ablation.py --benchmarks paper_eval,agentdojo --dry-run
"""
from __future__ import annotations

import argparse
import json
import math
import os
import secrets
import socket
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# ---------------------------------------------------------------------------
# Ablation configurations
# ---------------------------------------------------------------------------

ABLATION_CONFIGS: List[Dict[str, Any]] = [
    {
        "name": "full",
        "label": "Full SecureClaw",
        "description": "Both pillars enabled (baseline)",
        "env": {
            "EXECUTOR_INSECURE_ALLOW": "0",
            "SECURECLAW_SM_DISABLED": "0",
        },
    },
    {
        "name": "no_nbe",
        "label": "-NBE",
        "description": "No executor authorization; handle-first confinement still active",
        "env": {
            "EXECUTOR_INSECURE_ALLOW": "1",
            "SECURECLAW_SM_DISABLED": "0",
        },
    },
    {
        "name": "no_sm",
        "label": "-SM",
        "description": "No handle-first confinement; executor authorization still active",
        "env": {
            "EXECUTOR_INSECURE_ALLOW": "0",
            "SECURECLAW_SM_DISABLED": "1",
        },
    },
    {
        "name": "no_both",
        "label": "-Both",
        "description": "Neither pillar enabled",
        "env": {
            "EXECUTOR_INSECURE_ALLOW": "1",
            "SECURECLAW_SM_DISABLED": "1",
        },
    },
]

KNOWN_BENCHMARKS = ("paper_eval", "agentdojo", "agentleak")

# ---------------------------------------------------------------------------
# Utility helpers (same patterns as artifact_report.py / paper_eval.py)
# ---------------------------------------------------------------------------


def _pick_port() -> int:
    s = socket.socket()
    s.bind(("", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def _wait_http_ok(url: str, tries: int = 160) -> None:
    import requests

    for _ in range(int(tries)):
        try:
            r = requests.get(url, timeout=0.5)
            if int(r.status_code) == 200:
                return
        except Exception:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"health check failed: {url}")


def _wilson_ci(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n <= 0:
        return 0.0, 0.0
    phat = successes / n
    denom = 1.0 + (z * z / n)
    center = (phat + (z * z) / (2 * n)) / denom
    margin = (z / denom) * math.sqrt((phat * (1 - phat) / n) + ((z * z) / (4 * n * n)))
    lo = max(0.0, center - margin)
    hi = min(1.0, center + margin)
    return lo, hi


# ---------------------------------------------------------------------------
# Infrastructure lifecycle: start / stop policy + executor + gateway servers
# ---------------------------------------------------------------------------


class AblationInfra:
    """
    Context manager that starts the two policy servers, the executor server,
    and optionally a gateway HTTP server, all configured with the given
    ablation environment overrides.

    Follows the same patterns as ``SecureClawInfra`` in
    ``scripts/run_agentdojo_native_plain_secureclaw.py`` and the server
    startup block in ``scripts/artifact_report.py``.
    """

    def __init__(
        self,
        *,
        config_name: str,
        ablation_env: Dict[str, str],
        run_dir: Path,
    ) -> None:
        self.config_name = config_name
        self.ablation_env = dict(ablation_env)
        self.run_dir = run_dir
        self.procs: list[subprocess.Popen[str]] = []
        self.env_common: dict[str, str] = {}
        self.policy0_url = ""
        self.policy1_url = ""
        self.executor_url = ""
        self.gw_http_url = ""

    def __enter__(self) -> "AblationInfra":
        self.run_dir.mkdir(parents=True, exist_ok=True)
        runtime_state_dir = self.run_dir / "runtime_state"
        runtime_state_dir.mkdir(parents=True, exist_ok=True)

        p0_port = _pick_port()
        p1_port = _pick_port()
        ex_port = _pick_port()
        gw_port = _pick_port()

        self.policy0_url = f"http://127.0.0.1:{p0_port}"
        self.policy1_url = f"http://127.0.0.1:{p1_port}"
        self.executor_url = f"http://127.0.0.1:{ex_port}"
        self.gw_http_url = f"http://127.0.0.1:{gw_port}"

        policy0_mac_key = os.getenv("POLICY0_MAC_KEY", secrets.token_hex(32))
        policy1_mac_key = os.getenv("POLICY1_MAC_KEY", secrets.token_hex(32))
        request_binding_key = os.getenv("SECURECLAW_REQUEST_BINDING_KEY_HEX", secrets.token_hex(32))
        confirm_token_key = os.getenv("SECURECLAW_CONFIRM_TOKEN_KEY_HEX", secrets.token_hex(32))

        base_env = os.environ.copy()
        base_env["PYTHONPATH"] = str(REPO_ROOT)
        base_env["POLICY0_URL"] = self.policy0_url
        base_env["POLICY1_URL"] = self.policy1_url
        base_env["EXECUTOR_URL"] = self.executor_url
        base_env["POLICY0_MAC_KEY"] = policy0_mac_key
        base_env["POLICY1_MAC_KEY"] = policy1_mac_key
        base_env["SECURECLAW_REQUEST_BINDING_KEY_HEX"] = request_binding_key
        base_env["SECURECLAW_CONFIRM_TOKEN_KEY_HEX"] = confirm_token_key
        base_env["EXECUTOR_REPLAY_DB_PATH"] = str(runtime_state_dir / "executor_replay.sqlite")
        base_env["SIGNED_PIR"] = "1"
        base_env["MIRAGE_POLICY_BYPASS"] = "0"
        base_env["SINGLE_SERVER_POLICY"] = "0"
        base_env["USE_POLICY_BUNDLE"] = base_env.get("USE_POLICY_BUNDLE", "1")
        base_env["DLP_MODE"] = base_env.get("DLP_MODE", "dfa")
        base_env["MIRAGE_SESSION_ID"] = f"pillar-ablation-{self.config_name}-{secrets.token_hex(4)}"
        # SecureClaw runtime defaults appropriate for benchmark evaluation.
        base_env.setdefault("SECURECLAW_SESSION_SCOPE", "per_turn")
        base_env.setdefault("SECURECLAW_STRICT_SINK_BINDING", "1")
        base_env.setdefault("SECURECLAW_DENY_UNMAPPED_EFFECT", "0")
        base_env.setdefault("SECURECLAW_ALLOW_LOCAL_STATE_EFFECTS", "1")
        base_env.setdefault("SECURECLAW_INTENT_CONTRACT_MODE", "intent_v1")
        base_env.setdefault("SECURECLAW_MAX_TOOL_ITERS", "35")
        base_env.setdefault("SECURECLAW_LOCAL_RECIPIENT", "alice@example.com")
        base_env.setdefault("SECURECLAW_LOCAL_DOMAIN", "local.invalid")
        base_env.setdefault("SECURECLAW_ENFORCE_COMMIT_PATH", "1")
        base_env.setdefault("SECURECLAW_AUTO_USER_CONFIRM", "1")
        # Output gate: disable final-output confirmation gate for non-interactive benchmarks.
        base_env.setdefault("MIRAGE_ENFORCE_FINAL_OUTPUT_GATE", "0")
        base_env.setdefault("MIRAGE_FINAL_OUTPUT_CONFIRM_ALWAYS", "0")
        # Auth target source: "contextual" for paper-consistent behavior (query + tool-output
        # targets authorize recipients), "query_only" for hardened mode.
        base_env.setdefault("SECURECLAW_AUTH_TARGET_SOURCE", "contextual")
        base_env.setdefault("SECURECLAW_HANDLEIZE_READ_OUTPUT", "1")
        base_env.setdefault("SECURECLAW_READ_HANDLE_SENSITIVITY", "HIGH")
        base_env.setdefault("SECURECLAW_READ_HANDLE_TTL_S", "900")
        base_env.setdefault("SECURECLAW_READ_OUTPUT_MODE", "sanitized_summary")
        base_env.setdefault("SECURECLAW_READ_SUMMARY_MAX_ITEMS", "8")
        base_env.setdefault("SECURECLAW_READ_SUMMARY_MAX_CHARS", "512")
        base_env["LEAKAGE_BUDGET_DB_PATH"] = str(runtime_state_dir / "leakage_budget.sqlite")
        base_env["MEMORY_DB_PATH"] = str(runtime_state_dir / "memory.sqlite")
        base_env["INTER_AGENT_DB_PATH"] = str(runtime_state_dir / "inter_agent.sqlite")

        # Apply the ablation-specific env overrides.
        base_env.update(self.ablation_env)

        self.env_common = base_env

        # Build policy databases.
        subprocess.run(
            [sys.executable, "-m", "policy_server.build_dbs"],
            check=True,
            cwd=str(REPO_ROOT),
            env=base_env,
        )

        # Start policy server 0.
        env0 = base_env.copy()
        env0.pop("SECURECLAW_REQUEST_BINDING_KEY_HEX", None)
        env0.pop("SECURECLAW_CONFIRM_TOKEN_KEY_HEX", None)
        env0.pop("EXECUTOR_REPLAY_DB_PATH", None)
        env0["SERVER_ID"] = "0"
        env0["PORT"] = str(p0_port)
        env0["POLICY_MAC_KEY"] = policy0_mac_key
        p0_proc = subprocess.Popen(
            [sys.executable, "-m", "policy_server.server"],
            cwd=str(REPO_ROOT),
            env=env0,
            text=True,
        )
        self.procs.append(p0_proc)

        # Start policy server 1.
        env1 = base_env.copy()
        env1.pop("SECURECLAW_REQUEST_BINDING_KEY_HEX", None)
        env1.pop("SECURECLAW_CONFIRM_TOKEN_KEY_HEX", None)
        env1.pop("EXECUTOR_REPLAY_DB_PATH", None)
        env1["SERVER_ID"] = "1"
        env1["PORT"] = str(p1_port)
        env1["POLICY_MAC_KEY"] = policy1_mac_key
        p1_proc = subprocess.Popen(
            [sys.executable, "-m", "policy_server.server"],
            cwd=str(REPO_ROOT),
            env=env1,
            text=True,
        )
        self.procs.append(p1_proc)

        # Start executor server.
        envx = base_env.copy()
        envx["EXECUTOR_PORT"] = str(ex_port)
        ex_proc = subprocess.Popen(
            [sys.executable, "-m", "executor_server.server"],
            cwd=str(REPO_ROOT),
            env=envx,
            text=True,
        )
        self.procs.append(ex_proc)

        # Start gateway HTTP server.
        envg = base_env.copy()
        envg["MIRAGE_HTTP_BIND"] = "127.0.0.1"
        envg["MIRAGE_HTTP_PORT"] = str(gw_port)
        gw_proc = subprocess.Popen(
            [sys.executable, "-m", "gateway.http_server"],
            cwd=str(REPO_ROOT),
            env=envg,
            text=True,
        )
        self.procs.append(gw_proc)

        # Wait for all servers to become healthy.
        _wait_http_ok(f"{self.policy0_url}/health")
        _wait_http_ok(f"{self.policy1_url}/health")
        _wait_http_ok(f"{self.executor_url}/health")
        _wait_http_ok(f"{self.gw_http_url}/health")

        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        for p in self.procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in self.procs:
            try:
                p.wait(timeout=3)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# Benchmark runners
# ---------------------------------------------------------------------------


def _run_paper_eval(
    infra: AblationInfra,
    config: Dict[str, Any],
    run_dir: Path,
    seed: int,
    n_attack: int,
    n_benign: int,
) -> Dict[str, Any]:
    """
    Run the paper_eval benchmark (same as scripts/paper_eval.py) under the
    given ablation configuration.  Uses the MCP gateway for evaluation.
    """
    from agent.mcp_client import McpStdioClient
    from scripts.paper_eval import (
        EvalCase,
        build_cases,
        run_case,
        summarize_mode,
    )

    skill_root = run_dir / "skills"
    skill_root.mkdir(parents=True, exist_ok=True)

    cases = build_cases(
        seed=seed,
        n_attack_per_cat=n_attack,
        n_benign_per_cat=n_benign,
        skill_root=skill_root,
    )

    mcp_env = infra.env_common.copy()
    eval_caller = (os.getenv("EVAL_CALLER", "artifact") or "artifact").strip()
    rows: list[dict[str, Any]] = []

    with McpStdioClient([sys.executable, "-m", "gateway.mcp_server"], env=mcp_env) as mcp:
        mcp.initialize()
        for case in cases:
            blocked, dt, reason, cost_units = run_case(
                mcp, case, caller=eval_caller, skill_root=skill_root,
            )
            rows.append({
                "config": str(config["name"]),
                "case_id": case.case_id,
                "kind": case.kind,
                "category": case.category,
                "blocked": bool(blocked),
                "latency_s": float(dt),
                "reason_code": reason,
                "cost_units": int(cost_units),
            })

    summary = summarize_mode(rows)

    # Persist row-level CSV.
    csv_path = run_dir / "rows.csv"
    with csv_path.open("w", encoding="utf-8") as f:
        f.write("config,case_id,kind,category,blocked,latency_s,reason_code,cost_units\n")
        for r in rows:
            f.write(
                f"{r['config']},{r['case_id']},{r['kind']},{r['category']},"
                f"{int(bool(r['blocked']))},{r['latency_s']:.6f},"
                f"{str(r['reason_code']).replace(',', ';')},{int(r['cost_units'])}\n"
            )

    return {
        "benchmark": "paper_eval",
        "config": str(config["name"]),
        "n_cases": len(cases),
        "rows_path": str(csv_path),
        "summary": summary,
    }


def _run_agentdojo(
    infra: AblationInfra,
    config: Dict[str, Any],
    run_dir: Path,
    model: str,
    benchmark_version: str,
    suites: List[str],
) -> Dict[str, Any]:
    """
    Run AgentDojo benchmark under the given ablation configuration.

    Delegates to the IPIGuard eval.py harness, patching environment so the
    SecureClaw gateway connects through the ablation-configured infrastructure.
    """
    ipiguard_dir = REPO_ROOT / "third_party" / "ipiguard"
    results: dict[str, Any] = {}
    logs_dir = run_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    env_extra: dict[str, str] = {}
    env_extra.update(infra.env_common)
    env_extra["AGENTDOJO_SECURECLAW_BASE_URL"] = infra.gw_http_url
    env_extra["AGENTDOJO_SECURECLAW_TIMEOUT_S"] = str(os.getenv("AGENTDOJO_SECURECLAW_TIMEOUT_S", "30"))
    env_extra["SECURECLAW_LOCAL_EXECUTOR"] = "0"
    env_extra["PYTHONPATH"] = (
        f"{REPO_ROOT}:{ipiguard_dir}:{ipiguard_dir / 'agentdojo' / 'src'}"
        f":{env_extra.get('PYTHONPATH', '')}"
    )
    env_extra["PYTHONUNBUFFERED"] = "1"
    env_extra["OPENAI_API_KEY"] = str(os.getenv("OPENAI_API_KEY", ""))
    env_extra["OPENAI_BASE_URL"] = str(os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"))

    for mode in ("benign", "under_attack"):
        for suite in suites:
            key = f"{mode}/{suite}"
            out_dir = run_dir / mode / suite
            out_dir.mkdir(parents=True, exist_ok=True)
            log_path = logs_dir / f"secureclaw_{mode}_{suite}.log"

            cmd = [
                sys.executable,
                "run/eval.py",
                "--benchmark_version", str(benchmark_version),
                "--suite_name", str(suite),
                "--agent_model", str(model),
                "--attack_name", "important_instructions",
                "--defense_name", "secureclaw",
                "--output_dir", str(out_dir),
                "--mode", str(mode),
                "--uid", "0",
                "--iid", "0",
            ]
            with log_path.open("a", encoding="utf-8") as lf:
                lf.write(f"\n[ablation:{config['name']}] mode={mode} suite={suite}\n")
                lf.flush()
                p = subprocess.run(
                    cmd,
                    cwd=str(ipiguard_dir),
                    env=env_extra,
                    stdout=lf,
                    stderr=lf,
                    text=True,
                    check=False,
                )
            results_path = out_dir / "results.jsonl"
            n_rows = 0
            if results_path.exists():
                n_rows = sum(
                    1 for ln in results_path.read_text(encoding="utf-8", errors="replace").splitlines()
                    if ln.strip()
                )
            results[key] = {
                "status": "OK" if int(p.returncode) == 0 else "ERROR",
                "returncode": int(p.returncode),
                "rows": int(n_rows),
                "log": str(log_path),
            }

    return {
        "benchmark": "agentdojo",
        "config": str(config["name"]),
        "model": str(model),
        "benchmark_version": str(benchmark_version),
        "suites": suites,
        "results": results,
    }


def _run_agentleak(
    infra: AblationInfra,
    config: Dict[str, Any],
    run_dir: Path,
    model: str,
    n_scenarios: int,
    seed: int,
) -> Dict[str, Any]:
    """
    Run AgentLeak parity evaluation under the given ablation configuration.

    Delegates to the paper_parity_agentleak_eval.py harness.
    """
    logs_dir = run_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / "agentleak.log"

    env_extra = infra.env_common.copy()
    env_extra["PYTHONUNBUFFERED"] = "1"
    env_extra["OPENAI_API_KEY"] = str(os.getenv("OPENAI_API_KEY", ""))
    env_extra["OPENAI_BASE_URL"] = str(os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"))

    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "paper_parity_agentleak_eval.py"),
        "--out", str(run_dir),
        "--model", str(model),
        "--n", str(n_scenarios),
        "--seed", str(seed),
        "--modes", "secureclaw",
    ]

    with log_path.open("a", encoding="utf-8") as lf:
        lf.write(f"\n[ablation:{config['name']}] agentleak n={n_scenarios}\n")
        lf.flush()
        p = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            env=env_extra,
            stdout=lf,
            stderr=lf,
            text=True,
            check=False,
        )

    rows_path = run_dir / "paper_parity_agentleak_eval" / "rows_secureclaw.jsonl"
    n_rows = 0
    if rows_path.exists():
        n_rows = sum(
            1 for ln in rows_path.read_text(encoding="utf-8", errors="replace").splitlines()
            if ln.strip()
        )

    return {
        "benchmark": "agentleak",
        "config": str(config["name"]),
        "model": str(model),
        "n_scenarios": int(n_scenarios),
        "rows": int(n_rows),
        "status": "OK" if int(p.returncode) == 0 else "ERROR",
        "returncode": int(p.returncode),
        "log": str(log_path),
    }


# ---------------------------------------------------------------------------
# Metrics extraction
# ---------------------------------------------------------------------------


def _extract_key_metrics(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pull the headline numbers from a benchmark result so they can populate
    the summary table: ASR (attack success rate), utility, leak rate.
    """
    benchmark = str(result.get("benchmark", ""))
    metrics: dict[str, Any] = {}

    if benchmark == "paper_eval":
        summary = result.get("summary") or {}
        atk_block = float(summary.get("attack_block_rate", 0.0))
        asr = 1.0 - atk_block
        utility = float(summary.get("benign_allow_rate", 0.0))
        fp = float(summary.get("false_positive_rate", 0.0))
        by_cat = summary.get("by_category") or {}
        # Leak rate: defined as 1 - blocked_rate on DLP/path categories.
        leak_cats = ("dlp_secret", "path_bypass")
        leak_n, leak_passed = 0, 0
        for cat in leak_cats:
            cat_info = by_cat.get(cat, {})
            n = int(cat_info.get("n", 0))
            br = float(cat_info.get("blocked_rate", 0.0))
            leak_n += n
            leak_passed += int(round(n * (1.0 - br)))
        leak_rate = (float(leak_passed) / float(leak_n)) if leak_n > 0 else 0.0
        metrics = {
            "asr": asr,
            "asr_ci95": [1.0 - hi for hi in reversed(summary.get("attack_block_rate_ci95", [0.0, 0.0]))],
            "utility": utility,
            "fp_rate": fp,
            "leak_rate": leak_rate,
            "latency_p50_ms": float(summary.get("latency_p50_ms", 0.0)),
            "latency_p95_ms": float(summary.get("latency_p95_ms", 0.0)),
            "n_total": int(summary.get("n_total", 0)),
        }

    elif benchmark == "agentdojo":
        # Aggregate across suites from results.jsonl files.
        total_attack = 0
        total_attack_success = 0
        total_benign = 0
        total_benign_ok = 0
        for key, info in (result.get("results") or {}).items():
            if not isinstance(info, dict):
                continue
            # We count rows; detailed ASR extraction requires parsing results.jsonl.
            if "under_attack" in key:
                total_attack += int(info.get("rows", 0))
            elif "benign" in key:
                total_benign += int(info.get("rows", 0))
        metrics = {
            "total_attack_rows": total_attack,
            "total_benign_rows": total_benign,
            "note": "Detailed ASR requires post-hoc parsing of results.jsonl files.",
        }

    elif benchmark == "agentleak":
        metrics = {
            "rows": int(result.get("rows", 0)),
            "note": "Detailed leak/utility rates require post-hoc parsing of rows_secureclaw.jsonl.",
        }

    return metrics


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def _generate_markdown_report(
    all_results: Dict[str, Dict[str, Any]],
    output_path: Path,
) -> str:
    """
    Generate a summary Markdown table showing key metrics per ablation config.
    Returns the Markdown text.
    """
    lines: list[str] = []
    lines.append("# SecureClaw Three-Pillar Ablation Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")

    # Configuration summary.
    lines.append("## Configurations")
    lines.append("")
    lines.append("| Config | EXECUTOR_INSECURE_ALLOW | SECURECLAW_SM_DISABLED | Description |")
    lines.append("|--------|------------------------|-----------------------|-------------|")
    for cfg in ABLATION_CONFIGS:
        lines.append(
            f"| {cfg['label']} | {cfg['env']['EXECUTOR_INSECURE_ALLOW']} "
            f"| {cfg['env']['SECURECLAW_SM_DISABLED']} | {cfg['description']} |"
        )
    lines.append("")

    # Per-benchmark results tables.
    benchmarks_seen: set[str] = set()
    for config_name, config_results in all_results.items():
        for bench_name, result in config_results.items():
            benchmarks_seen.add(bench_name)

    for bench in sorted(benchmarks_seen):
        lines.append(f"## {bench}")
        lines.append("")

        if bench == "paper_eval":
            lines.append("| Config | ASR | Utility | FP Rate | Leak Rate | P50 (ms) | P95 (ms) | N |")
            lines.append("|--------|-----|---------|---------|-----------|----------|----------|---|")
            for cfg in ABLATION_CONFIGS:
                result = (all_results.get(cfg["name"]) or {}).get(bench, {})
                m = _extract_key_metrics(result)
                if not m:
                    lines.append(f"| {cfg['label']} | - | - | - | - | - | - | - |")
                    continue
                lines.append(
                    f"| {cfg['label']} "
                    f"| {m.get('asr', 0.0):.3f} "
                    f"| {m.get('utility', 0.0):.3f} "
                    f"| {m.get('fp_rate', 0.0):.3f} "
                    f"| {m.get('leak_rate', 0.0):.3f} "
                    f"| {m.get('latency_p50_ms', 0.0):.1f} "
                    f"| {m.get('latency_p95_ms', 0.0):.1f} "
                    f"| {m.get('n_total', 0)} |"
                )
            lines.append("")

            # Delta table vs full baseline.
            full_metrics = _extract_key_metrics(
                (all_results.get("full") or {}).get(bench, {})
            )
            if full_metrics.get("n_total", 0) > 0:
                lines.append("### Delta vs Full (positive = worse)")
                lines.append("")
                lines.append("| Config | dASR | dUtility | dLeak |")
                lines.append("|--------|------|----------|-------|")
                for cfg in ABLATION_CONFIGS:
                    if cfg["name"] == "full":
                        continue
                    m = _extract_key_metrics(
                        (all_results.get(cfg["name"]) or {}).get(bench, {})
                    )
                    if not m:
                        lines.append(f"| {cfg['label']} | - | - | - |")
                        continue
                    d_asr = m.get("asr", 0.0) - full_metrics.get("asr", 0.0)
                    d_util = full_metrics.get("utility", 0.0) - m.get("utility", 0.0)
                    d_leak = m.get("leak_rate", 0.0) - full_metrics.get("leak_rate", 0.0)
                    lines.append(
                        f"| {cfg['label']} | {d_asr:+.3f} | {d_util:+.3f} | {d_leak:+.3f} |"
                    )
                lines.append("")

        elif bench == "agentdojo":
            lines.append("| Config | Attack Rows | Benign Rows | Note |")
            lines.append("|--------|-------------|-------------|------|")
            for cfg in ABLATION_CONFIGS:
                result = (all_results.get(cfg["name"]) or {}).get(bench, {})
                m = _extract_key_metrics(result)
                lines.append(
                    f"| {cfg['label']} "
                    f"| {m.get('total_attack_rows', 0)} "
                    f"| {m.get('total_benign_rows', 0)} "
                    f"| {m.get('note', '-')} |"
                )
            lines.append("")

        elif bench == "agentleak":
            lines.append("| Config | Rows | Status | Note |")
            lines.append("|--------|------|--------|------|")
            for cfg in ABLATION_CONFIGS:
                result = (all_results.get(cfg["name"]) or {}).get(bench, {})
                m = _extract_key_metrics(result)
                status = str(result.get("status", "-"))
                lines.append(
                    f"| {cfg['label']} "
                    f"| {m.get('rows', 0)} "
                    f"| {status} "
                    f"| {m.get('note', '-')} |"
                )
            lines.append("")

    lines.append("## Interpretation Guide")
    lines.append("")
    lines.append("- **ASR** (Attack Success Rate): fraction of attacks that bypass all defenses (lower = better).")
    lines.append("- **Utility**: fraction of benign requests allowed through (higher = better).")
    lines.append("- **Leak Rate**: fraction of DLP/path-bypass attacks that leak sensitive data (lower = better).")
    lines.append("- **FP Rate**: fraction of benign requests incorrectly blocked (lower = better).")
    lines.append("")
    lines.append("If removing a pillar (-NBE or -SM) causes ASR/leak to increase, that pillar contributes")
    lines.append("independently to the defense.  If -Both is worse than max(-NBE, -SM), the pillars interact")
    lines.append("(super-additive defense).")
    lines.append("")

    md_text = "\n".join(lines) + "\n"
    output_path.write_text(md_text, encoding="utf-8")
    return md_text


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------


def main() -> None:
    ap = argparse.ArgumentParser(
        description="SecureClaw three-pillar ablation study orchestrator.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scripts/run_pillar_ablation.py --benchmarks paper_eval --output-dir artifact_out\n"
            "  python scripts/run_pillar_ablation.py --benchmarks paper_eval,agentdojo --dry-run\n"
            "  python scripts/run_pillar_ablation.py --configs full,no_nbe --benchmarks paper_eval\n"
        ),
    )
    ap.add_argument(
        "--benchmarks",
        default="paper_eval",
        help=f"Comma-separated benchmarks to run. Choices: {', '.join(KNOWN_BENCHMARKS)} (default: paper_eval).",
    )
    ap.add_argument(
        "--configs",
        default="",
        help=(
            "Comma-separated config names to run (default: all). "
            "Choices: full, no_nbe, no_sm, no_both."
        ),
    )
    ap.add_argument(
        "--output-dir",
        default="artifact_out",
        help="Root output directory (default: artifact_out).",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Print configurations and exit without running benchmarks.",
    )
    ap.add_argument("--seed", type=int, default=42, help="Random seed for paper_eval and agentleak (default: 42).")
    ap.add_argument("--n-attack", type=int, default=30, help="Attacks per category for paper_eval (default: 30).")
    ap.add_argument("--n-benign", type=int, default=30, help="Benign per category for paper_eval (default: 30).")
    ap.add_argument("--model", default="gpt-4o-mini-2024-07-18", help="Model for agentdojo/agentleak benchmarks.")
    ap.add_argument("--benchmark-version", default="v1.1.2", help="AgentDojo benchmark version (default: v1.1.2).")
    ap.add_argument("--agentdojo-suites", default="banking,slack,travel,workspace", help="AgentDojo suites.")
    ap.add_argument("--agentleak-n", type=int, default=100, help="Number of AgentLeak scenarios (default: 100).")
    args = ap.parse_args()

    benchmarks = [b.strip() for b in str(args.benchmarks).split(",") if b.strip()]
    for b in benchmarks:
        if b not in KNOWN_BENCHMARKS:
            raise SystemExit(f"Unknown benchmark: {b}.  Choices: {', '.join(KNOWN_BENCHMARKS)}")

    # Select configs to run.
    selected_config_names: set[str] = set()
    if args.configs:
        for name in args.configs.split(","):
            name = name.strip()
            if name and name not in {c["name"] for c in ABLATION_CONFIGS}:
                raise SystemExit(
                    f"Unknown config: {name}.  Choices: {', '.join(c['name'] for c in ABLATION_CONFIGS)}"
                )
            if name:
                selected_config_names.add(name)
    configs_to_run = [
        c for c in ABLATION_CONFIGS
        if not selected_config_names or c["name"] in selected_config_names
    ]

    output_dir = Path(str(args.output_dir)).expanduser().resolve()
    ablation_dir = output_dir / "pillar_ablation"

    # --dry-run: print configs and exit.
    if args.dry_run:
        print("=== Pillar Ablation Dry Run ===")
        print(f"Output directory: {ablation_dir}")
        print(f"Benchmarks:      {', '.join(benchmarks)}")
        print(f"Seed:            {args.seed}")
        print()
        for cfg in configs_to_run:
            print(f"  Config: {cfg['name']}  ({cfg['label']})")
            print(f"    {cfg['description']}")
            for k, v in cfg["env"].items():
                print(f"    {k}={v}")
            print()
        print(f"Total runs: {len(configs_to_run)} configs x {len(benchmarks)} benchmarks = {len(configs_to_run) * len(benchmarks)}")
        return

    ablation_dir.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # Run each (config, benchmark) pair.
    # -----------------------------------------------------------------------
    all_results: dict[str, dict[str, Any]] = {}
    run_metadata: dict[str, Any] = {
        "start_time": datetime.now(timezone.utc).isoformat(),
        "benchmarks": benchmarks,
        "configs": [c["name"] for c in configs_to_run],
        "seed": args.seed,
        "n_attack": args.n_attack,
        "n_benign": args.n_benign,
        "model": args.model,
    }

    suites = [s.strip() for s in str(args.agentdojo_suites).split(",") if s.strip()]

    for cfg in configs_to_run:
        config_name = str(cfg["name"])
        config_run_dir = ablation_dir / config_name
        config_run_dir.mkdir(parents=True, exist_ok=True)
        all_results[config_name] = {}

        print(f"\n{'='*60}")
        print(f"Config: {cfg['label']} ({config_name})")
        print(f"  EXECUTOR_INSECURE_ALLOW={cfg['env']['EXECUTOR_INSECURE_ALLOW']}")
        print(f"  SECURECLAW_SM_DISABLED={cfg['env']['SECURECLAW_SM_DISABLED']}")
        print(f"{'='*60}")

        try:
            with AblationInfra(
                config_name=config_name,
                ablation_env=cfg["env"],
                run_dir=config_run_dir / "infra",
            ) as infra:
                for bench in benchmarks:
                    bench_run_dir = config_run_dir / bench
                    bench_run_dir.mkdir(parents=True, exist_ok=True)
                    print(f"\n  Running {bench} under {cfg['label']}...")
                    t0 = time.time()

                    try:
                        if bench == "paper_eval":
                            result = _run_paper_eval(
                                infra=infra,
                                config=cfg,
                                run_dir=bench_run_dir,
                                seed=args.seed,
                                n_attack=args.n_attack,
                                n_benign=args.n_benign,
                            )
                        elif bench == "agentdojo":
                            result = _run_agentdojo(
                                infra=infra,
                                config=cfg,
                                run_dir=bench_run_dir,
                                model=args.model,
                                benchmark_version=args.benchmark_version,
                                suites=suites,
                            )
                        elif bench == "agentleak":
                            result = _run_agentleak(
                                infra=infra,
                                config=cfg,
                                run_dir=bench_run_dir,
                                model=args.model,
                                n_scenarios=args.agentleak_n,
                                seed=args.seed,
                            )
                        else:
                            result = {"error": f"Unknown benchmark: {bench}"}

                        dt = time.time() - t0
                        result["wall_time_s"] = round(dt, 2)
                        all_results[config_name][bench] = result
                        print(f"  Completed {bench} in {dt:.1f}s")

                    except Exception as e:
                        dt = time.time() - t0
                        all_results[config_name][bench] = {
                            "benchmark": bench,
                            "config": config_name,
                            "status": "ERROR",
                            "error": str(e)[:500],
                            "wall_time_s": round(dt, 2),
                        }
                        print(f"  ERROR in {bench}: {e}")

        except Exception as e:
            print(f"  INFRA ERROR for {cfg['label']}: {e}")
            for bench in benchmarks:
                all_results[config_name][bench] = {
                    "benchmark": bench,
                    "config": config_name,
                    "status": "INFRA_ERROR",
                    "error": str(e)[:500],
                }

        # Write incremental results after each config completes.
        _write_results(ablation_dir, all_results, run_metadata)

    # -----------------------------------------------------------------------
    # Final output
    # -----------------------------------------------------------------------
    run_metadata["end_time"] = datetime.now(timezone.utc).isoformat()
    run_metadata["status"] = "OK"
    _write_results(ablation_dir, all_results, run_metadata)

    # Generate top-level copies at the requested output paths.
    json_out = output_dir / "pillar_ablation_results.json"
    json_out.write_text(
        json.dumps(
            {"metadata": run_metadata, "results": all_results},
            indent=2,
            ensure_ascii=True,
            default=str,
        )
        + "\n",
        encoding="utf-8",
    )

    md_out = output_dir.parent / "PILLAR_ABLATION_REPORT.md"
    md_text = _generate_markdown_report(all_results, md_out)

    print(f"\nResults JSON: {json_out}")
    print(f"Report MD:    {md_out}")
    print("\nDone.")


def _write_results(
    ablation_dir: Path,
    all_results: Dict[str, Dict[str, Any]],
    run_metadata: Dict[str, Any],
) -> None:
    """Write incremental results checkpoint."""
    out_path = ablation_dir / "pillar_ablation_results.json"
    out_path.write_text(
        json.dumps(
            {"metadata": run_metadata, "results": all_results},
            indent=2,
            ensure_ascii=True,
            default=str,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
