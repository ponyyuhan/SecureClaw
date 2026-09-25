#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
IPIGUARD_DIR = REPO_ROOT / "third_party" / "ipiguard"
FARAMESH_SRC = REPO_ROOT / "third_party" / "faramesh-core" / "src"


@dataclass(frozen=True)
class ResumeInfo:
    has_summary: bool
    unique_rows: int
    next_uid: int
    next_iid: int
    max_user: int
    max_iid: int


def _pick_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_http_ok(url: str, *, timeout_s: float = 30.0) -> None:
    deadline = time.time() + timeout_s
    last_err = ""
    while time.time() < deadline:
        try:
            resp = requests.get(url, timeout=2)
            if resp.ok:
                return
            last_err = f"http {resp.status_code}"
        except Exception as exc:
            last_err = f"{type(exc).__name__}: {exc}"
        time.sleep(0.5)
    raise RuntimeError(f"timeout waiting for {url}: {last_err}")


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


def _resume_info(mode: str, results_path: Path) -> ResumeInfo:
    if not results_path.exists():
        return ResumeInfo(False, 0, 0, 0, -1, -1)

    seen: set[tuple[int, int | None]] = set()
    has_summary = False
    max_user = -1
    max_iid = -1
    for obj in _iter_json_objects(results_path):
        if not isinstance(obj, dict):
            continue
        if "Suite" in obj and "ASR" in obj:
            has_summary = True
        if mode == "under_attack":
            if "user_task_id" not in obj or obj.get("injection_task_id") is None:
                continue
            try:
                uid = int(obj.get("user_task_id"))
                iid = int(obj.get("injection_task_id"))
            except Exception:
                continue
            seen.add((uid, iid))
            if uid > max_user or (uid == max_user and iid > max_iid):
                max_user, max_iid = uid, iid
        else:
            if "user_task_id" not in obj or obj.get("injection_task_id") is not None:
                continue
            try:
                uid = int(obj.get("user_task_id"))
            except Exception:
                continue
            seen.add((uid, None))
            if uid > max_user:
                max_user = uid

    task_rows = len(seen)
    next_uid = 0
    next_iid = 0
    if task_rows > 0:
        if mode == "under_attack":
            next_uid = max_user
            next_iid = max_iid + 1
        else:
            next_uid = max_user + 1
    return ResumeInfo(has_summary, task_rows, next_uid, next_iid, max_user, max_iid)


def _compute_expected_rows(benchmark_version: str, suites: list[str]) -> dict[str, dict[str, int]]:
    src_root = IPIGUARD_DIR / "agentdojo" / "src"
    if str(src_root) not in sys.path:
        sys.path.insert(0, str(src_root))
    from agentdojo.task_suite.load_suites import get_suite  # type: ignore

    out: dict[str, dict[str, int]] = {}
    for suite_name in suites:
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


def _ensure_faramesh_ipiguard_integration() -> None:
    patch_path = REPO_ROOT / "scripts" / "ipiguard_faramesh_integration.patch"
    agent_pipeline = REPO_ROOT / "third_party" / "ipiguard" / "agentdojo" / "src" / "agentdojo" / "agent_pipeline" / "agent_pipeline.py"
    tool_execution = REPO_ROOT / "third_party" / "ipiguard" / "agentdojo" / "src" / "agentdojo" / "agent_pipeline" / "tool_execution.py"
    agent_text = agent_pipeline.read_text(encoding="utf-8", errors="replace")
    tool_text = tool_execution.read_text(encoding="utf-8", errors="replace")
    if "FarameshToolsExecutor" in agent_text and "class FarameshToolsExecutor" in tool_text:
        return
    subprocess.run(["git", "-C", str(REPO_ROOT / "third_party" / "ipiguard"), "apply", "--whitespace=nowarn", str(patch_path)], check=True)
    subprocess.run([sys.executable, "-m", "py_compile", str(agent_pipeline), str(tool_execution)], check=True)



class FarameshInfra:
    def __init__(self, *, run_dir: Path, benchmark_version: str, suites: list[str]):
        self.run_dir = run_dir
        self.benchmark_version = benchmark_version
        self.suites = suites
        self.proc: subprocess.Popen[str] | None = None
        self.log_fh = None
        self.env_patch: dict[str, str] = {}

    @staticmethod
    def _looks_iban(value: str) -> bool:
        return bool(re.fullmatch(r"[A-Z]{2}[0-9]{2}[0-9A-Z]{10,30}", str(value or "").strip().upper()))

    def _discover_policy_entities_from_env(self) -> tuple[set[str], set[str]]:
        recipients: set[str] = set()
        domains: set[str] = set()
        src_root = IPIGUARD_DIR / "agentdojo" / "src"
        if str(src_root) not in sys.path:
            sys.path.insert(0, str(src_root))
        try:
            from agentdojo.task_suite.load_suites import get_suite  # type: ignore
        except Exception:
            return recipients, domains

        key_hints_exact = {
            "recipient", "recipients", "sender", "to", "user", "user_email", "email", "participants",
            "channel", "channels", "domain", "url", "iban", "account", "payee", "company",
            "restaurant", "hotel", "contact_information", "account_email", "owner",
        }
        key_hints_substr = {
            "recipient", "sender", "email", "channel", "domain", "url", "iban", "account",
            "participant", "contact", "company", "restaurant", "hotel", "payee",
        }

        def add_scalar(key: str, raw: Any) -> None:
            if not isinstance(raw, (str, int, float, bool)):
                return
            text = str(raw or "").strip()
            if not text or text.lower() in {"me", "self", "myself"}:
                return
            lowered_key = str(key or "").strip().lower()
            scan = text if len(text) <= 8192 else text[:8192]
            for email in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", scan):
                recipients.add(email)
                domains.add(email.rsplit("@", 1)[1].strip().lower())
            for iban in re.findall(r"\b[A-Z]{2}[0-9]{2}[0-9A-Z]{10,30}\b", scan.upper()):
                recipients.add(iban)
            if len(text) > 256:
                return
            if "url" in lowered_key:
                parsed = urlparse(text if "://" in text else f"https://{text}")
                domain = str(parsed.netloc or "").strip().lower()
                if domain:
                    domains.add(domain)
                return
            if "@" in text and re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
                recipients.add(text)
                domains.add(text.rsplit("@", 1)[1].strip().lower())
                return
            if self._looks_iban(text):
                recipients.add(text.upper())
                return
            if "domain" in lowered_key and "." in text and " " not in text:
                domains.add(text.lower())
                return
            if any(h in lowered_key for h in ("recipient", "sender", "channel", "user", "to", "payee", "account", "iban", "company", "restaurant", "hotel", "owner")):
                if len(text) <= 96:
                    recipients.add(text)

        def walk(obj: Any, depth: int = 0) -> None:
            if obj is None or depth > 8:
                return
            if isinstance(obj, dict):
                for key, value in obj.items():
                    lowered_key = str(key or "").strip().lower()
                    if lowered_key in key_hints_exact or any(h in lowered_key for h in key_hints_substr):
                        if isinstance(value, (list, tuple, set)):
                            for item in value:
                                add_scalar(lowered_key, item)
                        else:
                            add_scalar(lowered_key, value)
                    if isinstance(value, (list, tuple, set)):
                        for item in value:
                            add_scalar("", item)
                    else:
                        add_scalar("", value)
                    if isinstance(value, (dict, list, tuple, set)) or hasattr(value, "__dict__"):
                        walk(value, depth + 1)
                return
            if isinstance(obj, (list, tuple, set)):
                for item in obj:
                    walk(item, depth + 1)
                return
            try:
                attrs = vars(obj)
            except Exception:
                attrs = {}
            if isinstance(attrs, dict):
                walk(attrs, depth + 1)

        for suite_name in self.suites:
            try:
                suite = get_suite(self.benchmark_version, suite_name)
                base_env = suite.load_and_inject_default_environment({})
                for user_task in suite.user_tasks.values():
                    prompt = str(getattr(user_task, "PROMPT", "") or "")
                    if prompt:
                        add_scalar("prompt", prompt)
                    env = user_task.init_environment(base_env)
                    walk(env, 0)
            except Exception:
                continue
        return recipients, domains

    def _build_policy(self) -> Path:
        recipients, domains = self._discover_policy_entities_from_env()
        local_recipient = str(os.getenv("SECURECLAW_LOCAL_RECIPIENT", "alice@example.com")).strip()
        local_domain = str(os.getenv("SECURECLAW_LOCAL_DOMAIN", "local.invalid")).strip().lower()
        if local_recipient:
            recipients.add(local_recipient)
            if "@" in local_recipient:
                domains.add(local_recipient.rsplit("@", 1)[1].strip().lower())
        if local_domain:
            domains.add(local_domain)

        rules: list[dict[str, Any]] = [
            {"match": {"tool": "readonly", "op": "*"}, "allow": True, "description": "Allow non-effectful tools", "risk": "low"},
            {"match": {"tool": "local_state", "op": "*"}, "allow": True, "description": "Allow local-state benchmark tools", "risk": "low"},
        ]
        for recipient in sorted(recipients):
            if not recipient:
                continue
            rules.append({"match": {"field": "recipient", "value": recipient}, "allow": True, "description": "Allow benchmark-local recipient", "risk": "low"})
            rules.append({"match": {"pattern": re.escape(recipient)}, "allow": True, "description": "Allow benchmark-local recipient pattern", "risk": "low"})
        for domain in sorted(domains):
            if not domain:
                continue
            rules.append({"match": {"field": "domain", "value": domain}, "allow": True, "description": "Allow benchmark-local domain", "risk": "low"})
            rules.append({"match": {"pattern": re.escape(domain)}, "allow": True, "description": "Allow benchmark-local domain pattern", "risk": "low"})
        rules.append({"match": {"tool": "*", "op": "*"}, "deny": True, "description": "Default deny for unmatched effectful actions", "risk": "high"})
        policy = {"rules": rules, "risk": {"rules": []}}
        out_path = self.run_dir / "faramesh.policy.yaml"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(yaml.safe_dump(policy, sort_keys=False, allow_unicode=False), encoding="utf-8")
        (self.run_dir / "faramesh.policy.meta.json").write_text(json.dumps({"allow_recipients": sorted(recipients), "allow_domains": sorted(domains)}, indent=2) + "\n", encoding="utf-8")
        return out_path

    def __enter__(self):
        self.run_dir.mkdir(parents=True, exist_ok=True)
        runtime_state_dir = self.run_dir / "runtime_state"
        runtime_state_dir.mkdir(parents=True, exist_ok=True)
        port = _pick_port()
        policy_path = self._build_policy()
        log_path = self.run_dir / "faramesh_server.log"
        self.log_fh = log_path.open("a", encoding="utf-8")
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{FARAMESH_SRC}:{REPO_ROOT}:{env.get('PYTHONPATH', '')}"
        env["FARA_POLICY_FILE"] = str(policy_path)
        env["FARA_SQLITE_PATH"] = str(runtime_state_dir / "faramesh_actions.sqlite")
        env["FARAMESH_PROFILE_FILE"] = str(runtime_state_dir / "disabled.profile.yaml")
        env["FARAMESH_ENABLE_CORS"] = "0"
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "faramesh.server.main:app", "--host", "127.0.0.1", "--port", str(port)],
            cwd=str(REPO_ROOT),
            env=env,
            stdout=self.log_fh,
            stderr=self.log_fh,
            text=True,
        )
        _wait_http_ok(f"http://127.0.0.1:{port}/health")
        self.env_patch = {
            "AGENTDOJO_FARAMESH_BASE_URL": f"http://127.0.0.1:{port}",
            "AGENTDOJO_FARAMESH_AGENT_ID": str(os.getenv("AGENTDOJO_FARAMESH_AGENT_ID", "agentdojo-faramesh")),
            "PYTHONPATH": f"{FARAMESH_SRC}:{REPO_ROOT}:{os.getenv('PYTHONPATH', '')}",
        }
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.proc is not None:
            try:
                self.proc.terminate()
            except Exception:
                pass
            try:
                self.proc.wait(timeout=3)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        if self.log_fh is not None:
            try:
                self.log_fh.close()
            except Exception:
                pass


def _run_one(*, mode: str, suite: str, model: str, benchmark_version: str, attack_name: str, out_dir: Path, logs_dir: Path, env_extra: dict[str, str], expected_rows: int) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "results.jsonl"
    exp = int(expected_rows)
    ri = _resume_info(mode, results_path)
    if ri.has_summary and ri.unique_rows >= exp and exp > 0:
        return {"status": "SKIP_COMPLETE", "rows": ri.unique_rows, "expected_rows": exp}
    log_path = logs_dir / f"faramesh_{mode}_{suite}.log"
    cmd = [
        sys.executable, "run/eval.py", "--benchmark_version", str(benchmark_version), "--suite_name", str(suite),
        "--agent_model", str(model), "--attack_name", str(attack_name), "--defense_name", "faramesh",
        "--output_dir", str(out_dir), "--mode", str(mode), "--uid", str(ri.next_uid), "--iid", str(ri.next_iid),
    ]
    env = os.environ.copy()
    env.update(env_extra)
    env["PYTHONPATH"] = f"{IPIGUARD_DIR}:{IPIGUARD_DIR / 'agentdojo' / 'src'}:{FARAMESH_SRC}:{REPO_ROOT}:{env.get('PYTHONPATH', '')}"
    env["OPENAI_BASE_URL"] = str(env.get("OPENAI_BASE_URL", "https://api.openai.com/v1"))
    with log_path.open("a", encoding="utf-8") as log_fh:
        proc = subprocess.run(cmd, cwd=str(IPIGUARD_DIR), env=env, stdout=log_fh, stderr=log_fh, text=True)
    ri2 = _resume_info(mode, results_path)
    status = "OK" if proc.returncode == 0 else ("PARTIAL" if ri2.unique_rows > 0 else "ERROR")
    return {
        "status": status,
        "returncode": int(proc.returncode),
        "rows": ri2.unique_rows,
        "expected_rows": exp,
        "has_summary": ri2.has_summary,
        "resume": {"next_uid": ri2.next_uid, "next_iid": ri2.next_iid, "max_user": ri2.max_user, "max_iid": ri2.max_iid},
        "log": str(log_path),
        "out_dir": str(out_dir),
    }


def main() -> None:
    _ensure_faramesh_ipiguard_integration()
    ap = argparse.ArgumentParser(description="Run AgentDojo Faramesh baseline with resume.")
    ap.add_argument("--out-root", required=True)
    ap.add_argument("--model", default="gpt-4o-mini-2024-07-18")
    ap.add_argument("--benchmark-version", default="v1.1.2")
    ap.add_argument("--attack-name", default="important_instructions")
    ap.add_argument("--suites", default="banking,slack,travel,workspace")
    ap.add_argument("--modes", default="benign,under_attack")
    args = ap.parse_args()

    out_root = Path(str(args.out_root)).expanduser().resolve()
    logs_dir = out_root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    suites = [s.strip() for s in str(args.suites).split(",") if s.strip()]
    modes = [m.strip() for m in str(args.modes).split(",") if m.strip()]
    expected_rows = _compute_expected_rows(str(args.benchmark_version), suites)
    report: dict[str, Any] = {
        "status": "RUNNING",
        "benchmark": f"AgentDojo-{str(args.benchmark_version)}-faramesh",
        "model": str(args.model),
        "benchmark_version": str(args.benchmark_version),
        "out_root": str(out_root),
        "expected_rows": expected_rows,
        "faramesh": {},
    }
    with FarameshInfra(run_dir=out_root / "infra", benchmark_version=str(args.benchmark_version), suites=suites) as infra:
        env_base = {
            "OPENAI_API_KEY": str(os.getenv("OPENAI_API_KEY", "")),
            "OPENAI_BASE_URL": str(os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")),
            "IPIGUARD_OPENAI_TIMEOUT_S": str(os.getenv("IPIGUARD_OPENAI_TIMEOUT_S", "120")),
            "IPIGUARD_OPENAI_MAX_RETRIES": str(os.getenv("IPIGUARD_OPENAI_MAX_RETRIES", "0")),
            "IPIGUARD_LLM_RETRY_ATTEMPTS": str(os.getenv("IPIGUARD_LLM_RETRY_ATTEMPTS", "3")),
            "IPIGUARD_LLM_RETRY_MAX_WAIT_S": str(os.getenv("IPIGUARD_LLM_RETRY_MAX_WAIT_S", "40")),
            "IPIGUARD_LLM_RETRY_BACKOFF_S": str(os.getenv("IPIGUARD_LLM_RETRY_BACKOFF_S", "2")),
            "IPIGUARD_LLM_RETRY_HINT_SCALE": str(os.getenv("IPIGUARD_LLM_RETRY_HINT_SCALE", os.getenv("IPIGUARD_LLM_RETRY_MULTIPLIER", "1.0"))),
            "IPIGUARD_LLM_RETRY_HINT_JITTER_S": str(os.getenv("IPIGUARD_LLM_RETRY_HINT_JITTER_S", "0.5")),
            "PYTHONUNBUFFERED": "1",
        }
        env_base.update(infra.env_patch)
        for mode in modes:
            for suite in suites:
                key = f"{mode}/{suite}"
                rec = _run_one(mode=mode, suite=suite, model=str(args.model), benchmark_version=str(args.benchmark_version), attack_name=str(args.attack_name), out_dir=out_root / "faramesh" / mode / suite, logs_dir=logs_dir, env_extra=env_base, expected_rows=int(expected_rows.get(suite, {}).get(mode, 0)))
                report["faramesh"][key] = rec
                (out_root / "agentdojo_faramesh_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    fairness: dict[str, Any] = {"status": "ok", "reasons": []}
    for suite in suites:
        for mode in modes:
            key = f"{mode}/{suite}"
            exp = int(expected_rows.get(suite, {}).get(mode, 0))
            got = int(report.get("faramesh", {}).get(key, {}).get("rows") or 0)
            if exp > 0 and got != exp:
                fairness["status"] = "invalid"
                fairness["reasons"].append(f"rows_not_expected:{mode}:{suite}:faramesh={got},expected={exp}")
    report["fairness"] = fairness
    report["status"] = "OK" if fairness["status"] == "ok" else "ERROR_FAIRNESS"
    out_path = out_root / "agentdojo_faramesh_report.json"
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(str(out_path))


if __name__ == "__main__":
    main()
