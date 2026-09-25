#!/usr/bin/env python3
"""Progent-core adapter for the exact AgentDojo v1.1.2 (629+97) harness.

The official Progent fork labels its suite ``v1.1.2`` but contains only 589
attacked rows because travel injection_task_2 and injection_task_6 are absent.
This adapter loads the current upstream AgentDojo tasks/scorers, then executes
Progent's *official* SecAgent core and the official per-suite task_suite.py
wiring (including its manual policies) without modifying either repository.
See BASELINE_FAITHFULNESS.md before interpreting results as head-to-head.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import runpy
import subprocess
import sys
from pathlib import Path

from baseline_common import (
    ATTACK,
    BENCHMARK_VERSION,
    SUITES,
    RowSelection,
    SuiteInventory,
    assert_manifest_rows,
    dump_summary,
    export_canonical_rows,
    git_head,
    group_attack_rows,
    group_benign_rows,
    load_manifest_contract,
    select_rows,
    summarize_result_tree,
    write_manifest,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PROGENT_ROOT = REPO_ROOT / "third_party" / "progent"
CURRENT_AGENTDOJO_ROOT = REPO_ROOT / "third_party" / "agentdojo"
CURRENT_AGENTDOJO_SRC = REPO_ROOT / "third_party" / "agentdojo" / "src"
PROGENT_AGENTDOJO_SRC = PROGENT_ROOT / "agentdojo" / "src"
EXPECTED_PROGENT_COMMIT = "9befb41cbf992b49dbf035cbd3d53eb953d3b351"
DEFAULT_AGENT_MODEL = "openai/gpt-4o-mini-2024-07-18"
DEFAULT_POLICY_MODE = "generated"
RUNNER_ID = "progent-core-agentdojo-exact-adapter"
EXACT_ADAPTER_STATUS = (
    "conditional: official SecAgent core + official policy/wrapper source, "
    "transplanted onto current AgentDojo task/scorer inventory"
)


def _source_paths() -> dict[str, Path]:
    return {
        "runner": Path(__file__).resolve(),
        "baseline_common": Path(__file__).with_name("baseline_common.py").resolve(),
    }


def _evaluation_role(policy_mode: str) -> str:
    return "formal_baseline" if policy_mode == "generated" else "diagnostic_only"


def _configuration(args: argparse.Namespace) -> dict[str, object]:
    return {
        "policy_mode": args.policy_mode,
        "policy_update": args.update_policy,
        "agent_model": args.agent_model,
        "policy_model": args.policy_model,
        "transport": "OpenRouter OpenAI-compatible API",
        "attack": ATTACK,
        "temperature": 0,
        "faithfulness_status": EXACT_ADAPTER_STATUS,
        "evaluation_role": _evaluation_role(args.policy_mode),
        "policy_enforcement_scope": "target_agent_pipeline_only",
        "attack_construction": "unwrapped_exact_agentdojo_suite",
    }


def _require_policy_role(args: argparse.Namespace) -> None:
    if (
        args.policy_mode == "manual"
        and args.command != "gate"
        and not args.diagnostic_manual
    ):
        raise SystemExit(
            "manual policy mode is diagnostic-only; pass --diagnostic-manual "
            "to acknowledge that it is not the formal Progent baseline"
        )


def _inventory_from_python(python: str, pythonpath: str) -> tuple[SuiteInventory, ...]:
    code = """
import json
from agentdojo.task_suite import get_suite
out = []
for name in ("workspace", "banking", "travel", "slack"):
    suite = get_suite("v1.1.2", name)
    out.append({"suite": name, "user_tasks": list(suite.user_tasks), "injection_tasks": list(suite.injection_tasks)})
print("INVENTORY=" + json.dumps(out, sort_keys=True))
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = pythonpath
    completed = subprocess.run(
        [python, "-c", code],
        check=True,
        capture_output=True,
        text=True,
        env=env,
        cwd=REPO_ROOT,
    )
    line = next(
        value
        for value in completed.stdout.splitlines()
        if value.startswith("INVENTORY=")
    )
    values = json.loads(line.split("=", 1)[1])
    return tuple(
        SuiteInventory(
            suite=value["suite"],
            user_tasks=tuple(value["user_tasks"]),
            injection_tasks=tuple(value["injection_tasks"]),
        )
        for value in values
    )


def faithfulness_gate() -> dict:
    current = _inventory_from_python(sys.executable, str(CURRENT_AGENTDOJO_SRC))
    native = _inventory_from_python(
        sys.executable, f"{PROGENT_AGENTDOJO_SRC}:{PROGENT_ROOT}"
    )
    current_attack = sum(item.attack_rows for item in current)
    native_attack = sum(item.attack_rows for item in native)
    current_ids = {
        (item.suite, user, injection)
        for item in current
        for user in item.user_tasks
        for injection in item.injection_tasks
    }
    native_ids = {
        (item.suite, user, injection)
        for item in native
        for user in item.user_tasks
        for injection in item.injection_tasks
    }
    return {
        "progent_commit": git_head(PROGENT_ROOT),
        "expected_progent_commit": EXPECTED_PROGENT_COMMIT,
        "current_agentdojo_commit": git_head(CURRENT_AGENTDOJO_ROOT),
        "benchmark_version": BENCHMARK_VERSION,
        "current_harness": {
            "attack_rows": current_attack,
            "benign_rows": sum(item.benign_rows for item in current),
        },
        "progent_native_fork": {
            "attack_rows": native_attack,
            "benign_rows": sum(item.benign_rows for item in native),
        },
        "native_missing_from_current": [
            {"suite": suite, "user_task_id": user, "injection_task_id": injection}
            for suite, user, injection in sorted(current_ids - native_ids)
        ],
        "native_exact_same_harness": current_ids == native_ids,
        "exact_adapter_status": EXACT_ADAPTER_STATUS,
    }


def _load_rows(path: Path) -> RowSelection:
    data = json.loads(path.read_text())["rows"]
    return RowSelection(
        benchmark_version=data["benchmark_version"],
        selection=data["selection"],
        seed=data["seed"],
        attack_rows=tuple(
            (row["suite"], row["user_task_id"], row["injection_task_id"])
            for row in data["attack_rows"]
        ),
        benign_rows=tuple(
            (row["suite"], row["user_task_id"]) for row in data["benign_rows"]
        ),
    )


def _suite_pair_with_official_progent_wiring(suite_name: str, policy_mode: str):
    """Return the evaluated SecAgent suite and a clean suite for attack GT.

    AgentDojo constructs attack injections by executing each user task's
    ground-truth pipeline before it runs the evaluated agent.  Those
    benchmark-internal calls must use the original AgentDojo tools: applying
    SecAgent there would let a policy generated for the previous evaluated
    row reject ground-truth calls for the next row.  The returned suites share
    the exact tasks, data, version, and environment type; only the evaluated
    suite has Progent's official secure tool wrappers.
    """

    generate_policy = policy_mode == "generated"
    # Upstream reads this switch into a module global at import time, so the
    # environment must be set before importing secagent.
    os.environ["SECAGENT_GENERATE"] = str(generate_policy)
    sys.path.insert(0, str(CURRENT_AGENTDOJO_SRC))
    sys.path.insert(1, str(PROGENT_ROOT))
    from agentdojo.task_suite import get_suite
    import secagent
    import secagent.tool as secagent_tool

    # Also synchronize an already-imported module (tests and multi-suite
    # workers can reuse the same interpreter).
    secagent_tool.generate_policy = generate_policy
    secagent_tool.available_tools.clear()
    secagent.update_security_policy(None)
    os.environ["SECAGENT_SUITE"] = suite_name
    official_source = (
        PROGENT_AGENTDOJO_SRC
        / "agentdojo"
        / "default_suites"
        / "v1"
        / suite_name
        / "task_suite.py"
    )
    namespace = runpy.run_path(str(official_source))
    wrapped = namespace["task_suite"]
    exact = get_suite(BENCHMARK_VERSION, suite_name)
    wrapped._user_tasks = exact._user_tasks
    wrapped._injection_tasks = exact._injection_tasks
    wrapped.data_path = exact.data_path
    wrapped.benchmark_version = exact.benchmark_version
    if [tool.name for tool in wrapped.tools] != [tool.name for tool in exact.tools]:
        raise RuntimeError(
            f"Progent tool inventory drift for {suite_name}: wrapped and exact "
            "AgentDojo suites do not match"
        )

    attack_construction_suite = copy.copy(wrapped)
    attack_construction_suite.tools = list(exact.tools)
    return wrapped, attack_construction_suite


def _suite_with_official_progent_wiring(suite_name: str, policy_mode: str):
    """Backward-compatible accessor for the evaluated SecAgent suite."""

    return _suite_pair_with_official_progent_wiring(suite_name, policy_mode)[0]


def _make_pipeline(agent_model: str, policy_mode: str, update_policy: bool):
    import openai
    import secagent
    from agentdojo import agent_pipeline
    from agentdojo.agent_pipeline.agent_pipeline import load_system_message

    class ProgentInitQuery(agent_pipeline.BasePipelineElement):
        def query(self, query, runtime, env, messages=(), extra_args=None):
            secagent.generate_security_policy(query)
            init = agent_pipeline.InitQuery()
            return init.query(query, runtime, env, messages, extra_args or {})

    class ProgentToolsExecutor(agent_pipeline.ToolsExecutor):
        def query(self, query, runtime, env, messages=(), extra_args=None):
            before = len(messages)
            result = super().query(query, runtime, env, messages, extra_args or {})
            updated_messages = result[3]
            tool_messages = [
                message
                for message in updated_messages[before:]
                if isinstance(message, dict) and message.get("role") == "tool"
            ]
            if update_policy and tool_messages:
                calls = [
                    {
                        "name": message["tool_call"].function,
                        "args": message["tool_call"].args,
                    }
                    for message in tool_messages
                ]
                outputs = [
                    message.get("error") or str(message.get("content"))
                    for message in tool_messages
                ]
                secagent.generate_update_security_policy(
                    calls, str(outputs), manual_check=False
                )
            return result

    client = openai.OpenAI(
        api_key=os.environ["OPENROUTER_API_KEY"],
        base_url="https://openrouter.ai/api/v1",
    )
    llm = agent_pipeline.OpenAILLM(client, agent_model, temperature=0.0)
    llm.name = agent_model.split("/", 1)[-1]
    loop = agent_pipeline.ToolsExecutionLoop([ProgentToolsExecutor(), llm])
    pipeline = agent_pipeline.AgentPipeline(
        [
            agent_pipeline.SystemMessage(load_system_message(None)),
            ProgentInitQuery(),
            llm,
            loop,
        ]
    )
    pipeline.name = f"progent-{policy_mode}-{agent_model.split('/', 1)[-1]}"
    return pipeline


def _worker(args: argparse.Namespace) -> None:
    if "OPENROUTER_API_KEY" not in os.environ:
        raise SystemExit("OPENROUTER_API_KEY is required")
    os.environ["OPENAI_API_KEY"] = os.environ["OPENROUTER_API_KEY"]
    os.environ["OPENAI_BASE_URL"] = "https://openrouter.ai/api/v1"
    os.environ["SECAGENT_POLICY_MODEL"] = args.policy_model
    os.environ["SECAGENT_UPDATE"] = str(args.update_policy)
    os.environ["SECAGENT_IGNORE_UPDATE_ERROR"] = "False"
    os.environ["SECAGENT_GENERATE"] = str(args.policy_mode == "generated")

    sys.path.insert(0, str(CURRENT_AGENTDOJO_SRC))
    sys.path.insert(1, str(PROGENT_ROOT))
    from agentdojo import attacks, benchmark
    from agentdojo.logging import OutputLogger

    rows = _load_rows(args.out / "manifest.json")
    suite, attack_construction_suite = _suite_pair_with_official_progent_wiring(
        args.suite, args.policy_mode
    )
    pipeline = _make_pipeline(args.agent_model, args.policy_mode, args.update_policy)
    log_root = args.out / "logs"
    benign_users = group_benign_rows(rows.benign_rows).get(args.suite, ())
    attack_users = group_attack_rows(rows.attack_rows).get(args.suite, {})
    attack = attacks.load_attack(ATTACK, attack_construction_suite, pipeline)
    with OutputLogger(str(log_root)):
        if benign_users:
            benchmark.benchmark_suite_without_injections(
                pipeline,
                suite,
                user_tasks=benign_users,
                logdir=log_root,
                force_rerun=args.force_rerun,
            )
        for user, injection_ids in attack_users.items():
            benchmark.benchmark_suite_with_injections(
                pipeline,
                suite,
                attack,
                user_tasks=(user,),
                injection_tasks=injection_ids,
                logdir=log_root,
                force_rerun=args.force_rerun,
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=("gate", "plan", "run", "summarize", "_worker")
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--selection", choices=("pilot", "full"), default="pilot")
    parser.add_argument("--seed", type=int, default=3179)
    parser.add_argument(
        "--policy-mode",
        choices=("manual", "generated"),
        default=DEFAULT_POLICY_MODE,
    )
    parser.add_argument("--agent-model", default=DEFAULT_AGENT_MODEL)
    parser.add_argument("--policy-model", default=DEFAULT_AGENT_MODEL)
    parser.add_argument("--update-policy", action="store_true")
    parser.add_argument(
        "--diagnostic-manual",
        action="store_true",
        help="Acknowledge that --policy-mode manual is diagnostic-only.",
    )
    parser.add_argument("--force-rerun", action="store_true")
    parser.add_argument("--suite", choices=SUITES)
    args = parser.parse_args()
    args.out = args.out.resolve()
    _require_policy_role(args)

    configuration = _configuration(args)
    manifest_path = args.out / "manifest.json"
    manifest_payload = None
    if args.command not in {"gate", "plan"}:
        manifest_payload = load_manifest_contract(
            manifest_path,
            runner=RUNNER_ID,
            source_paths=_source_paths(),
            configuration=configuration,
            selection=args.selection,
            seed=args.seed,
        )

    gate = faithfulness_gate()
    if gate["progent_commit"] != EXPECTED_PROGENT_COMMIT:
        raise SystemExit("Progent faithfulness gate failed: unexpected upstream commit")
    if args.command == "gate":
        args.out.mkdir(parents=True, exist_ok=True)
        dump_summary(args.out / "faithfulness_gate.json", gate)
        print(args.out / "faithfulness_gate.json")
        return
    current = _inventory_from_python(sys.executable, str(CURRENT_AGENTDOJO_SRC))
    if sum(item.attack_rows for item in current) != 629:
        raise SystemExit("exact adapter gate failed: current harness is not 629 rows")
    expected_rows = select_rows(current, args.selection, seed=args.seed)
    if args.command == "plan":
        write_manifest(
            manifest_path,
            runner=RUNNER_ID,
            upstream={
                "repository": "sunblaze-ucb/progent",
                "commit": EXPECTED_PROGENT_COMMIT,
                "agentdojo_commit": gate["current_agentdojo_commit"],
                "benchmark_version": BENCHMARK_VERSION,
                "native_exact_same_harness": str(gate["native_exact_same_harness"]),
            },
            inventories=current,
            rows=expected_rows,
            configuration=configuration,
            source_paths=_source_paths(),
        )
        dump_summary(args.out / "faithfulness_gate.json", gate)
        print(args.out / "manifest.json")
        return
    assert manifest_payload is not None
    assert_manifest_rows(manifest_payload, expected_rows)
    if args.command == "_worker":
        if args.suite is None:
            raise SystemExit("--suite is required for _worker")
        _worker(args)
        return
    rows = _load_rows(manifest_path)
    pipeline_name = f"progent-{args.policy_mode}-{args.agent_model.split('/', 1)[-1]}"
    if args.command == "summarize":
        summary = summarize_result_tree(args.out / "logs", pipeline_name, rows)
        summary["faithfulness"] = gate
        dump_summary(args.out / "summary.json", summary)
        export_canonical_rows(
            args.out / "canonical_rows.jsonl",
            log_root=args.out / "logs",
            pipeline_name=pipeline_name,
            expected=rows,
            system=(
                "Progent-generated"
                if args.policy_mode == "generated"
                else "Progent-manual-diagnostic"
            ),
        )
        print(args.out / "summary.json")
        return
    if "OPENROUTER_API_KEY" not in os.environ:
        raise SystemExit("OPENROUTER_API_KEY is required for run")
    for suite in SUITES:
        command = [
            sys.executable,
            str(Path(__file__).resolve()),
            "_worker",
            "--out",
            str(args.out),
            "--suite",
            suite,
            "--policy-mode",
            args.policy_mode,
            "--agent-model",
            args.agent_model,
            "--policy-model",
            args.policy_model,
            "--selection",
            args.selection,
            "--seed",
            str(args.seed),
        ]
        if args.update_policy:
            command.append("--update-policy")
        if args.force_rerun:
            command.append("--force-rerun")
        if args.diagnostic_manual:
            command.append("--diagnostic-manual")
        subprocess.run(command, check=True, env=os.environ.copy(), cwd=REPO_ROOT)
        # Detect source edits between or during suite workers.
        load_manifest_contract(
            manifest_path,
            runner=RUNNER_ID,
            source_paths=_source_paths(),
            configuration=configuration,
            selection=args.selection,
            seed=args.seed,
        )


if __name__ == "__main__":
    main()
