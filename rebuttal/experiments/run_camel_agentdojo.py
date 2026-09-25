#!/usr/bin/env python3
"""Faithful two-stage CaMeL runner for AgentDojo v1.1.2.

The official artifact's outer CLI hard-codes benchmark ``v1.2``.  This wrapper
keeps its pipeline, attack, logging, replay, interpreter, and security-policy
engines unchanged, while selecting the submission's exact ``v1.1.2`` suite.
Stage 1 generates ``+camel`` traces; stage 2 replays those traces as
``+camel+secpol`` without another model call.
"""

from __future__ import annotations

import argparse
import json
import os
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
    migrate_legacy_manifest_sources,
    select_rows,
    summarize_result_tree,
    write_manifest,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CAMEL_ROOT = REPO_ROOT / "third_party" / "camel-prompt-injection"
CAMEL_SRC = CAMEL_ROOT / "src"
CURRENT_AGENTDOJO_ROOT = REPO_ROOT / "third_party" / "agentdojo"
CURRENT_AGENTDOJO_SRC = CURRENT_AGENTDOJO_ROOT / "src"
EXPECTED_CAMEL_COMMIT = "f083b6b396399d3b3c7f2ddaf613a5945eaf32d8"
DEFAULT_AGENT_MODEL = "openai/gpt-4o-mini-2024-07-18"
RUNNER_ID = "camel-agentdojo-two-stage"


def _source_paths() -> dict[str, Path]:
    return {
        "runner": Path(__file__).resolve(),
        "baseline_common": Path(__file__).with_name("baseline_common.py").resolve(),
    }


def _configuration(args: argparse.Namespace) -> dict[str, object]:
    return {
        "agent_model": args.agent_model,
        "q_model": args.q_model,
        "transport": "OpenRouter OpenAI-compatible API",
        "attack": ATTACK,
        "temperature": 0,
        "stage1": "+camel",
        "stage2": "+camel+secpol replay",
    }


def _import_upstream():
    # Current AgentDojo first gives both baselines the exact same task/scorer
    # implementation; CaMeL itself is imported untouched from its artifact.
    sys.path.insert(0, str(CAMEL_SRC))
    sys.path.insert(0, str(CURRENT_AGENTDOJO_SRC))
    from agentdojo import attacks, benchmark, logging
    from agentdojo import agent_pipeline
    from agentdojo.task_suite import get_suite
    from camel.interpreter.interpreter import MetadataEvalMode
    from camel.pipeline_elements.privileged_llm import PrivilegedLLM
    from camel.pipeline_elements.replay_privileged_llm import (
        PrivilegedLLMReplayer,
        UserInjectionTasksGetter,
    )
    from camel.pipeline_elements.security_policies import (
        ADNoSecurityPolicyEngine,
        BankingSecurityPolicyEngine,
        SlackSecurityPolicyEngine,
        TravelSecurityPolicyEngine,
        WorkspaceSecurityPolicyEngine,
    )

    return {
        "attacks": attacks,
        "benchmark": benchmark,
        "logging": logging,
        "agent_pipeline": agent_pipeline,
        "get_suite": get_suite,
        "MetadataEvalMode": MetadataEvalMode,
        "PrivilegedLLM": PrivilegedLLM,
        "PrivilegedLLMReplayer": PrivilegedLLMReplayer,
        "UserInjectionTasksGetter": UserInjectionTasksGetter,
        "engines": {
            "workspace": WorkspaceSecurityPolicyEngine,
            "banking": BankingSecurityPolicyEngine,
            "travel": TravelSecurityPolicyEngine,
            "slack": SlackSecurityPolicyEngine,
        },
        "no_policy_engine": ADNoSecurityPolicyEngine,
    }


def inventories(upstream: dict) -> tuple[SuiteInventory, ...]:
    result = []
    for suite_name in SUITES:
        suite = upstream["get_suite"](BENCHMARK_VERSION, suite_name)
        result.append(
            SuiteInventory(
                suite=suite_name,
                user_tasks=tuple(suite.user_tasks),
                injection_tasks=tuple(suite.injection_tasks),
            )
        )
    return tuple(result)


def _pipeline_names(agent_model: str) -> tuple[str, str]:
    display = agent_model.split("/", 1)[-1]
    return f"{display}+camel", f"{display}+camel+secpol"


def build_stage1_pipeline(upstream: dict, agent_model: str, q_model: str):
    import openai

    model_name = agent_model.split("/", 1)[-1]
    client = openai.OpenAI(
        api_key=os.environ["OPENROUTER_API_KEY"],
        base_url="https://openrouter.ai/api/v1",
    )
    llm = upstream["agent_pipeline"].OpenAILLM(client, agent_model)
    llm.name = model_name
    pipeline = upstream["agent_pipeline"].AgentPipeline(
        [
            upstream["agent_pipeline"].InitQuery(),
            upstream["PrivilegedLLM"](
                llm,
                upstream["no_policy_engine"],
                f"openrouter:{q_model}",
            ),
        ]
    )
    pipeline.name = f"{model_name}+camel"
    return pipeline


def build_stage2_pipeline(
    upstream: dict, suite: str, stage1_name: str, stage2_name: str
):
    pipeline = upstream["agent_pipeline"].AgentPipeline(
        [
            upstream["agent_pipeline"].InitQuery(),
            upstream["UserInjectionTasksGetter"](),
            upstream["PrivilegedLLMReplayer"](
                stage1_name,
                ATTACK,
                upstream["engines"][suite],
                upstream["MetadataEvalMode"].NORMAL,
            ),
        ]
    )
    pipeline.name = stage2_name
    return pipeline


def _run_rows(
    upstream: dict,
    *,
    stage: int,
    rows: RowSelection,
    log_root: Path,
    agent_model: str,
    q_model: str,
    force_rerun: bool,
) -> None:
    attack_groups = group_attack_rows(rows.attack_rows)
    benign_groups = group_benign_rows(rows.benign_rows)
    stage1_name, stage2_name = _pipeline_names(agent_model)

    old_cwd = Path.cwd()
    # Upstream replay resolves traces relative to ./logs.
    run_root = log_root.parent
    run_root.mkdir(parents=True, exist_ok=True)
    os.chdir(run_root)
    try:
        for suite_name in SUITES:
            suite = upstream["get_suite"](BENCHMARK_VERSION, suite_name)
            if stage == 1:
                pipeline = build_stage1_pipeline(upstream, agent_model, q_model)
            else:
                pipeline = build_stage2_pipeline(
                    upstream, suite_name, stage1_name, stage2_name
                )
            attack = upstream["attacks"].load_attack(ATTACK, suite, pipeline)
            with upstream["logging"].OutputLogger(str(log_root)):
                benign_users = benign_groups.get(suite_name, ())
                if benign_users:
                    upstream["benchmark"].benchmark_suite_without_injections(
                        pipeline,
                        suite,
                        logdir=log_root,
                        force_rerun=force_rerun,
                        user_tasks=benign_users,
                    )
                for user, injection_ids in attack_groups.get(suite_name, {}).items():
                    upstream["benchmark"].benchmark_suite_with_injections(
                        pipeline,
                        suite,
                        attack,
                        logdir=log_root,
                        force_rerun=force_rerun,
                        user_tasks=(user,),
                        injection_tasks=injection_ids,
                    )
    finally:
        os.chdir(old_cwd)


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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("plan", "migrate-manifest", "stage1", "stage2", "summarize"),
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--selection", choices=("pilot", "full"), default="pilot")
    parser.add_argument("--seed", type=int, default=3179)
    parser.add_argument("--agent-model", default=DEFAULT_AGENT_MODEL)
    parser.add_argument("--q-model", default=DEFAULT_AGENT_MODEL)
    parser.add_argument("--force-rerun", action="store_true")
    parser.add_argument(
        "--migration-note",
        default="",
        help=(
            "Required only for migrate-manifest; records why legacy raw stage-1 "
            "outputs may be adopted without modifying them."
        ),
    )
    args = parser.parse_args()

    out = args.out.resolve()
    manifest = out / "manifest.json"
    log_root = out / "logs"
    configuration = _configuration(args)
    manifest_payload = None
    if args.command not in {"plan", "migrate-manifest"}:
        manifest_payload = load_manifest_contract(
            manifest,
            runner=RUNNER_ID,
            source_paths=_source_paths(),
            configuration=configuration,
            selection=args.selection,
            seed=args.seed,
        )

    if git_head(CAMEL_ROOT) != EXPECTED_CAMEL_COMMIT:
        raise SystemExit("CaMeL faithfulness gate failed: unexpected upstream commit")
    upstream = _import_upstream()
    inventory = inventories(upstream)
    if sum(item.attack_rows for item in inventory) != 629:
        raise SystemExit("CaMeL faithfulness gate failed: v1.1.2 is not 629 rows")
    if sum(item.benign_rows for item in inventory) != 97:
        raise SystemExit("CaMeL faithfulness gate failed: v1.1.2 is not 97 benign rows")
    expected_rows = select_rows(inventory, args.selection, seed=args.seed)

    if args.command == "plan":
        write_manifest(
            manifest,
            runner=RUNNER_ID,
            upstream={
                "repository": "google-research/camel-prompt-injection",
                "commit": EXPECTED_CAMEL_COMMIT,
                "agentdojo_repository": "ethz-spylab/agentdojo",
                "agentdojo_commit": git_head(CURRENT_AGENTDOJO_ROOT),
                "benchmark_version": BENCHMARK_VERSION,
            },
            inventories=inventory,
            rows=expected_rows,
            configuration=configuration,
            source_paths=_source_paths(),
        )
        print(manifest)
        return
    if args.command == "migrate-manifest":
        legacy_payload = json.loads(manifest.read_text(encoding="utf-8"))
        assert_manifest_rows(legacy_payload, expected_rows)
        migrate_legacy_manifest_sources(
            manifest,
            runner=RUNNER_ID,
            source_paths=_source_paths(),
            configuration=configuration,
            selection=args.selection,
            seed=args.seed,
            note=args.migration_note,
        )
        print(manifest)
        return
    assert manifest_payload is not None
    assert_manifest_rows(manifest_payload, expected_rows)
    rows = _load_rows(manifest)
    stage1_name, stage2_name = _pipeline_names(args.agent_model)
    if args.command == "summarize":
        summary = summarize_result_tree(log_root, stage2_name, rows)
        dump_summary(out / "summary.json", summary)
        export_canonical_rows(
            out / "canonical_rows.jsonl",
            log_root=log_root,
            pipeline_name=stage2_name,
            expected=rows,
            system="CaMeL",
        )
        print(out / "summary.json")
        return
    if args.command == "stage1" and "OPENROUTER_API_KEY" not in os.environ:
        raise SystemExit("OPENROUTER_API_KEY is required for stage1")
    _run_rows(
        upstream,
        stage=1 if args.command == "stage1" else 2,
        rows=rows,
        log_root=log_root,
        agent_model=args.agent_model,
        q_model=args.q_model,
        force_rerun=args.force_rerun,
    )
    # Detect edits made while the long-running process was executing.
    load_manifest_contract(
        manifest,
        runner=RUNNER_ID,
        source_paths=_source_paths(),
        configuration=configuration,
        selection=args.selection,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
