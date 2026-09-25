from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
IPIGUARD_DIR = REPO_ROOT / "third_party" / "ipiguard"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

SUITES = ("banking", "slack", "travel", "workspace")


@dataclass(frozen=True)
class ResumeInfo:
    has_summary: bool
    unique_rows: int
    next_uid: int
    next_iid: int


def _model_uses_openai(model: str) -> bool:
    name = str(model or "").strip().lower()
    if not name:
        return False
    return name.startswith(("gpt-", "chatgpt-", "o1", "o3", "o4"))


def _require_runtime_credentials(model: str) -> None:
    if not _model_uses_openai(model):
        return
    api_key = str(os.getenv("OPENAI_API_KEY", "")).strip()
    if api_key:
        return
    raise SystemExit(
        f"OPENAI_API_KEY is required for model '{model}'. Refusing to run to avoid polluted benchmark results."
    )


def _compute_expected_rows(
    benchmark_version: str,
    suites: list[str],
) -> dict[str, dict[str, int]]:
    """
    Compute expected row counts from AgentDojo suite metadata instead of hardcoding
    version-specific constants.
    """
    src_root = IPIGUARD_DIR / "agentdojo" / "src"
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
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
            injections = getattr(suite, "injection_tasks", {}) or {}
            inj_n = int(len(injections))
            under_attack = benign * inj_n
        out[suite_name] = {"benign": benign, "under_attack": under_attack}
    return out


def _pick_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
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


def _wait_path_ok(path: Path, tries: int = 200) -> None:
    for _ in range(int(tries)):
        if path.exists():
            return
        time.sleep(0.1)
    raise RuntimeError(f"path not ready: {path}")


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
        return ResumeInfo(False, 0, 0, 0)

    has_summary = False
    seen: set[tuple[int, int | None]] = set()
    max_uid = -1
    max_iid = -1
    for obj in _iter_json_objects(results_path):
        if not isinstance(obj, dict):
            continue
        if "Suite" in obj and "ASR" in obj:
            has_summary = True
        if mode == "under_attack":
            if "user_task_id" in obj and obj.get("injection_task_id") is not None:
                try:
                    uid = int(obj.get("user_task_id", -1))
                    iid = int(obj.get("injection_task_id", -1))
                except Exception:
                    continue
                seen.add((uid, iid))
                if uid > max_uid or (uid == max_uid and iid > max_iid):
                    max_uid, max_iid = uid, iid
        else:
            if "user_task_id" in obj and ("injection_task_id" not in obj or obj.get("injection_task_id") is None):
                try:
                    uid = int(obj.get("user_task_id", -1))
                except Exception:
                    continue
                seen.add((uid, None))
                if uid > max_uid:
                    max_uid = uid

    rows = len(seen)
    if rows <= 0:
        return ResumeInfo(has_summary, 0, 0, 0)
    if mode == "under_attack":
        return ResumeInfo(has_summary, rows, max_uid, max_iid + 1)
    return ResumeInfo(has_summary, rows, max_uid + 1, 0)


class SecureClawInfra:
    def __init__(self, run_dir: Path, *, benchmark_version: str = "v1.1.2", suites: list[str] | None = None) -> None:
        self.run_dir = run_dir
        self.benchmark_version = str(benchmark_version)
        self.suites = list(suites or SUITES)
        self.procs: list[subprocess.Popen[str]] = []
        self.env_patch: dict[str, str] = {}
        self.policy_config_path: Path | None = None

    @staticmethod
    def _looks_iban(s: str) -> bool:
        return bool(re.fullmatch(r"[A-Z]{2}[0-9]{2}[0-9A-Z]{10,30}", str(s or "").strip().upper()))

    def _discover_policy_entities_from_env(self) -> tuple[set[str], set[str]]:
        """
        Generic environment-entity discovery for allowlist bootstrap.

        This discovery reads only structured runtime environment objects and does
        not consume benchmark labels or ground-truth action trajectories.
        """
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
            "recipient",
            "recipients",
            "sender",
            "to",
            "user",
            "user_email",
            "email",
            "participants",
            "channel",
            "channels",
            "domain",
            "url",
            "iban",
            "account",
            "payee",
            "company",
            "restaurant",
            "hotel",
            "contact_information",
            "account_email",
            "owner",
        }
        key_hints_substr = {
            "recipient",
            "sender",
            "email",
            "channel",
            "domain",
            "url",
            "iban",
            "account",
            "participant",
            "contact",
            "company",
            "restaurant",
            "hotel",
            "payee",
        }

        def _add_from_scalar(key: str, raw: Any) -> None:
            if not isinstance(raw, (str, int, float, bool)):
                return
            s = str(raw or "").strip()
            if not s:
                return
            k = str(key or "").strip().lower()
            if s.lower() in {"me", "self", "myself"}:
                return

            # Extract identity-like atoms from mixed content strings.
            scan = s if len(s) <= 8192 else s[:8192]
            for em in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", scan):
                recipients.add(em)
                domains.add(em.rsplit("@", 1)[1].strip().lower())
            for ib in re.findall(r"\b[A-Z]{2}[0-9]{2}[0-9A-Z]{10,30}\b", scan.upper()):
                recipients.add(ib)

            # For very long strings, keep only high-confidence pattern extraction above.
            if len(s) > 256:
                return

            if "url" in k:
                parsed = urlparse(s if "://" in s else f"https://{s}")
                dom = str(parsed.netloc or "").strip().lower()
                if dom:
                    domains.add(dom)
                return
            if "@" in s and re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", s):
                recipients.add(s)
                domains.add(s.rsplit("@", 1)[1].strip().lower())
                return
            if self._looks_iban(s):
                recipients.add(s.upper())
                return
            if "domain" in k and "." in s and " " not in s:
                domains.add(s.lower())
                return
            if any(h in k for h in ("recipient", "sender", "channel", "user", "to", "payee", "account", "iban", "company", "restaurant", "hotel", "owner")):
                if len(s) <= 96:
                    recipients.add(s)

        def _walk(obj: Any, depth: int = 0) -> None:
            if obj is None or depth > 8:
                return
            if isinstance(obj, dict):
                for k, v in obj.items():
                    ks = str(k or "").strip().lower()
                    if ks in key_hints_exact or any(h in ks for h in key_hints_substr):
                        if isinstance(v, (list, tuple, set)):
                            for x in v:
                                _add_from_scalar(ks, x)
                        else:
                            _add_from_scalar(ks, v)
                    # High-confidence global scan: collect explicit sink identifiers
                    # (email/IBAN/URL/domain patterns) even when key names are generic.
                    if isinstance(v, (list, tuple, set)):
                        for x in v:
                            _add_from_scalar("", x)
                    else:
                        _add_from_scalar("", v)
                    if isinstance(v, (dict, list, tuple, set)) or hasattr(v, "__dict__"):
                        _walk(v, depth + 1)
                return
            if isinstance(obj, (list, tuple, set)):
                for x in obj:
                    _add_from_scalar("", x)
                    _walk(x, depth + 1)
                return
            if isinstance(obj, (str, bytes, int, float, bool)):
                return
            try:
                attrs = vars(obj)
            except Exception:
                attrs = {}
            if isinstance(attrs, dict):
                _walk(attrs, depth + 1)

        for suite_name in self.suites:
            try:
                suite = get_suite(self.benchmark_version, suite_name)
                base_env = suite.load_and_inject_default_environment({})
                for ut in suite.user_tasks.values():
                    prompt = str(getattr(ut, "PROMPT", "") or "")
                    if prompt:
                        _add_from_scalar("prompt", prompt)
                    env = ut.init_environment(base_env)
                    _walk(env, 0)
            except Exception:
                continue
        return recipients, domains

    def _resolve_policy_config(self) -> Path:
        """
        Resolve policy config without benchmark-oracle expansion.

        Optional generic override:
        - `SECURECLAW_POLICY_OVERRIDE_PATH`: YAML file with keys to merge into base config.
        """
        base_raw = str(os.getenv("POLICY_CONFIG_PATH", "")).strip()
        base_path = Path(base_raw).expanduser().resolve() if base_raw else (REPO_ROOT / "policy_server" / "policy.yaml")
        if not base_path.exists():
            raise FileNotFoundError(f"policy config not found: {base_path}")

        ov_raw = str(os.getenv("SECURECLAW_POLICY_OVERRIDE_PATH", "")).strip()
        base_cfg = yaml.safe_load(base_path.read_text(encoding="utf-8")) or {}
        if not isinstance(base_cfg, dict):
            raise ValueError("policy config must be a YAML mapping")

        merged = dict(base_cfg)
        used_override = False
        if ov_raw:
            ov_path = Path(ov_raw).expanduser().resolve()
            if not ov_path.exists():
                raise FileNotFoundError(f"policy override not found: {ov_path}")
            ov_cfg = yaml.safe_load(ov_path.read_text(encoding="utf-8")) or {}
            if not isinstance(ov_cfg, dict):
                raise ValueError("policy override must be a YAML mapping")
            for k, v in ov_cfg.items():
                if k in {"allow_recipients", "allow_domains"}:
                    base_vals = merged.get(k) if isinstance(merged.get(k), list) else []
                    ov_vals = v if isinstance(v, list) else []
                    merged[k] = sorted({str(x).strip() for x in [*base_vals, *ov_vals] if str(x).strip()})
                else:
                    merged[k] = v
            used_override = True

        discovery_mode = str(os.getenv("SECURECLAW_POLICY_DISCOVERY", "off")).strip().lower()
        used_discovery = False
        if discovery_mode not in {"off", "0", "disabled", "none"}:
            recs, doms = self._discover_policy_entities_from_env()
            if recs:
                prev = merged.get("allow_recipients") if isinstance(merged.get("allow_recipients"), list) else []
                merged["allow_recipients"] = sorted({str(x).strip() for x in [*prev, *sorted(recs)] if str(x).strip()})
            if doms:
                prev = merged.get("allow_domains") if isinstance(merged.get("allow_domains"), list) else []
                merged["allow_domains"] = sorted({str(x).strip().lower() for x in [*prev, *sorted(doms)] if str(x).strip()})
            used_discovery = bool(recs or doms)

        if not used_override and not used_discovery:
            self.policy_config_path = base_path
            return base_path

        out_path = self.run_dir / "policy.runtime.yaml"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(yaml.safe_dump(merged, sort_keys=False, allow_unicode=False), encoding="utf-8")
        self.policy_config_path = out_path
        return out_path

    def __enter__(self):
        self.run_dir.mkdir(parents=True, exist_ok=True)
        runtime_state_dir = self.run_dir / "runtime_state"
        runtime_state_dir.mkdir(parents=True, exist_ok=True)
        socket_dir = Path("/tmp") / f"sc_{secrets.token_hex(4)}"
        socket_dir.mkdir(parents=True, exist_ok=True)
        p0_sock = socket_dir / "p0.sock"
        p1_sock = socket_dir / "p1.sock"
        p0_port = _pick_port()
        p1_port = _pick_port()
        ex_port = _pick_port()
        gw_port = _pick_port()
        for sock in (p0_sock, p1_sock):
            try:
                sock.unlink()
            except FileNotFoundError:
                pass
            except Exception:
                pass

        base_env = os.environ.copy()
        base_env["PYTHONPATH"] = str(REPO_ROOT)
        base_env["POLICY0_URL"] = f"http://127.0.0.1:{p0_port}"
        base_env["POLICY1_URL"] = f"http://127.0.0.1:{p1_port}"
        base_env["POLICY0_UDS_PATH"] = ""
        base_env["POLICY1_UDS_PATH"] = ""
        base_env["EXECUTOR_URL"] = f"http://127.0.0.1:{ex_port}"
        base_env["POLICY0_MAC_KEY"] = base_env.get("POLICY0_MAC_KEY", secrets.token_hex(32))
        base_env["POLICY1_MAC_KEY"] = base_env.get("POLICY1_MAC_KEY", secrets.token_hex(32))
        # Request binding key is shared by gateway + executor only (not policy servers),
        # so policy-side transcript observers cannot run offline dictionary guesses.
        base_env["SECURECLAW_REQUEST_BINDING_KEY_HEX"] = base_env.get(
            "SECURECLAW_REQUEST_BINDING_KEY_HEX", secrets.token_hex(32)
        )
        # Confirm-token key: shared by gateway (minting) + executor (verification).
        base_env["SECURECLAW_CONFIRM_TOKEN_KEY_HEX"] = base_env.get(
            "SECURECLAW_CONFIRM_TOKEN_KEY_HEX", secrets.token_hex(32)
        )
        # Durable replay guard: per-run sqlite so executor can detect replays across restarts.
        base_env["EXECUTOR_REPLAY_DB_PATH"] = base_env.get(
            "EXECUTOR_REPLAY_DB_PATH", str(runtime_state_dir / "executor_replay.sqlite")
        )
        base_env["SIGNED_PIR"] = "1"
        base_env["MIRAGE_POLICY_BYPASS"] = "0"
        base_env["SINGLE_SERVER_POLICY"] = "0"
        base_env["MIRAGE_ENFORCE_FINAL_OUTPUT_GATE"] = base_env.get("MIRAGE_ENFORCE_FINAL_OUTPUT_GATE", "0")
        base_env["MIRAGE_FINAL_OUTPUT_CONFIRM_ALWAYS"] = base_env.get("MIRAGE_FINAL_OUTPUT_CONFIRM_ALWAYS", "0")
        # Auth target source: "contextual" uses both query + tool-output-derived targets
        # for recipient/domain authorization (matches paper evaluation).
        base_env["SECURECLAW_AUTH_TARGET_SOURCE"] = base_env.get("SECURECLAW_AUTH_TARGET_SOURCE", "contextual")
        base_env["USE_POLICY_BUNDLE"] = base_env.get("USE_POLICY_BUNDLE", "1")
        base_env["DLP_MODE"] = base_env.get("DLP_MODE", "dfa")
        base_env["LEAKAGE_BUDGET_ENABLED"] = base_env.get("LEAKAGE_BUDGET_ENABLED", "0")
        base_env["MIRAGE_SESSION_ID"] = base_env.get("MIRAGE_SESSION_ID", "agentdojo-secureclaw")
        base_env["SECURECLAW_SESSION_SCOPE"] = base_env.get("SECURECLAW_SESSION_SCOPE", "per_turn")
        base_env["SECURECLAW_STRICT_SINK_BINDING"] = base_env.get("SECURECLAW_STRICT_SINK_BINDING", "1")
        base_env["SECURECLAW_DENY_UNMAPPED_EFFECT"] = base_env.get("SECURECLAW_DENY_UNMAPPED_EFFECT", "0")
        base_env["SECURECLAW_ALLOW_LOCAL_STATE_EFFECTS"] = base_env.get("SECURECLAW_ALLOW_LOCAL_STATE_EFFECTS", "1")
        base_env["SECURECLAW_INTENT_CONTRACT_MODE"] = base_env.get("SECURECLAW_INTENT_CONTRACT_MODE", "intent_v1")
        base_env["SECURECLAW_MAX_TOOL_ITERS"] = base_env.get("SECURECLAW_MAX_TOOL_ITERS", "35")
        base_env["SECURECLAW_LOCAL_RECIPIENT"] = base_env.get("SECURECLAW_LOCAL_RECIPIENT", "alice@example.com")
        base_env["SECURECLAW_LOCAL_DOMAIN"] = base_env.get("SECURECLAW_LOCAL_DOMAIN", "local.invalid")
        base_env["SECURECLAW_ENFORCE_COMMIT_PATH"] = base_env.get("SECURECLAW_ENFORCE_COMMIT_PATH", "1")
        # AgentDojo runs are non-interactive; default to auto-confirm so REQUIRE_CONFIRM
        # does not collapse utility due missing UI confirmation channel.
        base_env["SECURECLAW_AUTO_USER_CONFIRM"] = base_env.get("SECURECLAW_AUTO_USER_CONFIRM", "1")
        base_env["SECURECLAW_HANDLEIZE_READ_OUTPUT"] = base_env.get("SECURECLAW_HANDLEIZE_READ_OUTPUT", "1")
        base_env["SECURECLAW_READ_HANDLE_SENSITIVITY"] = base_env.get("SECURECLAW_READ_HANDLE_SENSITIVITY", "HIGH")
        base_env["SECURECLAW_READ_HANDLE_TTL_S"] = base_env.get("SECURECLAW_READ_HANDLE_TTL_S", "900")
        base_env["SECURECLAW_READ_OUTPUT_MODE"] = base_env.get("SECURECLAW_READ_OUTPUT_MODE", "sanitized_summary")
        base_env["SECURECLAW_READ_SUMMARY_MAX_ITEMS"] = base_env.get("SECURECLAW_READ_SUMMARY_MAX_ITEMS", "8")
        base_env["SECURECLAW_READ_SUMMARY_MAX_CHARS"] = base_env.get("SECURECLAW_READ_SUMMARY_MAX_CHARS", "512")
        base_env["LEAKAGE_BUDGET_DB_PATH"] = str(runtime_state_dir / "leakage_budget.sqlite")
        base_env["MEMORY_DB_PATH"] = str(runtime_state_dir / "memory.sqlite")
        base_env["INTER_AGENT_DB_PATH"] = str(runtime_state_dir / "inter_agent.sqlite")

        for p in (
            Path(base_env["LEAKAGE_BUDGET_DB_PATH"]),
            Path(base_env["MEMORY_DB_PATH"]),
            Path(base_env["INTER_AGENT_DB_PATH"]),
        ):
            try:
                p.unlink()
            except FileNotFoundError:
                pass
            except Exception:
                pass

        policy_cfg = self._resolve_policy_config()
        base_env["POLICY_CONFIG_PATH"] = str(policy_cfg)

        if bool(int(base_env.get("SECURECLAW_NO_LISTEN", "0") or "0")):
            self.env_patch = {
                "POLICY_CONFIG_PATH": str(base_env["POLICY_CONFIG_PATH"]),
                "MIRAGE_SESSION_ID": str(base_env["MIRAGE_SESSION_ID"]),
                "SECURECLAW_LOCAL_EXECUTOR": "1",
                "SECURECLAW_AUTO_USER_CONFIRM": str(base_env["SECURECLAW_AUTO_USER_CONFIRM"]),
                "SECURECLAW_HANDLEIZE_READ_OUTPUT": str(base_env["SECURECLAW_HANDLEIZE_READ_OUTPUT"]),
                "SECURECLAW_READ_OUTPUT_MODE": str(base_env["SECURECLAW_READ_OUTPUT_MODE"]),
                "SECURECLAW_READ_SUMMARY_MAX_ITEMS": str(base_env["SECURECLAW_READ_SUMMARY_MAX_ITEMS"]),
                "SECURECLAW_READ_SUMMARY_MAX_CHARS": str(base_env["SECURECLAW_READ_SUMMARY_MAX_CHARS"]),
                "SECURECLAW_ALLOW_LOCAL_STATE_EFFECTS": str(base_env["SECURECLAW_ALLOW_LOCAL_STATE_EFFECTS"]),
                "SECURECLAW_DENY_UNMAPPED_EFFECT": str(base_env["SECURECLAW_DENY_UNMAPPED_EFFECT"]),
                "SECURECLAW_MAX_TOOL_ITERS": str(base_env["SECURECLAW_MAX_TOOL_ITERS"]),
                "SECURECLAW_LOCAL_RECIPIENT": str(base_env["SECURECLAW_LOCAL_RECIPIENT"]),
                "SECURECLAW_LOCAL_DOMAIN": str(base_env["SECURECLAW_LOCAL_DOMAIN"]),
                "DLP_MODE": str(base_env["DLP_MODE"]),
            }
            return self

        subprocess.run(
            [sys.executable, "-m", "policy_server.build_dbs"],
            check=True,
            cwd=str(REPO_ROOT),
            env=base_env,
        )

        env0 = base_env.copy()
        env0.pop("SECURECLAW_REQUEST_BINDING_KEY_HEX", None)
        env0.pop("SECURECLAW_CONFIRM_TOKEN_KEY_HEX", None)
        env0.pop("EXECUTOR_REPLAY_DB_PATH", None)
        env0["SERVER_ID"] = "0"
        env0.pop("POLICY_UDS_PATH", None)
        env0["PORT"] = str(p0_port)
        env0["POLICY_MAC_KEY"] = env0["POLICY0_MAC_KEY"]
        p0_proc = subprocess.Popen([sys.executable, "-m", "policy_server.server"], cwd=str(REPO_ROOT), env=env0, text=True)
        self.procs.append(p0_proc)

        env1 = base_env.copy()
        env1.pop("SECURECLAW_REQUEST_BINDING_KEY_HEX", None)
        env1.pop("SECURECLAW_CONFIRM_TOKEN_KEY_HEX", None)
        env1.pop("EXECUTOR_REPLAY_DB_PATH", None)
        env1["SERVER_ID"] = "1"
        env1.pop("POLICY_UDS_PATH", None)
        env1["PORT"] = str(p1_port)
        env1["POLICY_MAC_KEY"] = env1["POLICY1_MAC_KEY"]
        p1_proc = subprocess.Popen([sys.executable, "-m", "policy_server.server"], cwd=str(REPO_ROOT), env=env1, text=True)
        self.procs.append(p1_proc)
        _wait_http_ok(f"{base_env['POLICY0_URL']}/health")
        _wait_http_ok(f"{base_env['POLICY1_URL']}/health")

        envx = base_env.copy()
        envx["EXECUTOR_PORT"] = str(ex_port)
        ex_proc = subprocess.Popen([sys.executable, "-m", "executor_server.server"], cwd=str(REPO_ROOT), env=envx, text=True)
        self.procs.append(ex_proc)
        _wait_http_ok(f"http://127.0.0.1:{ex_port}/health")

        envg = base_env.copy()
        envg["MIRAGE_HTTP_BIND"] = "127.0.0.1"
        envg["MIRAGE_HTTP_PORT"] = str(gw_port)
        gw_proc = subprocess.Popen([sys.executable, "-m", "gateway.http_server"], cwd=str(REPO_ROOT), env=envg, text=True)
        self.procs.append(gw_proc)
        _wait_http_ok(f"http://127.0.0.1:{gw_port}/health")

        self.env_patch = {
            "POLICY0_URL": str(base_env["POLICY0_URL"]),
            "POLICY1_URL": str(base_env["POLICY1_URL"]),
            "POLICY0_UDS_PATH": str(base_env["POLICY0_UDS_PATH"]),
            "POLICY1_UDS_PATH": str(base_env["POLICY1_UDS_PATH"]),
            "EXECUTOR_URL": str(base_env["EXECUTOR_URL"]),
            "AGENTDOJO_SECURECLAW_BASE_URL": f"http://127.0.0.1:{gw_port}",
            "AGENTDOJO_SECURECLAW_TIMEOUT_S": str(os.getenv("AGENTDOJO_SECURECLAW_TIMEOUT_S", "30")),
            "SECURECLAW_LOCAL_EXECUTOR": "0",
            "POLICY0_MAC_KEY": str(base_env["POLICY0_MAC_KEY"]),
            "POLICY1_MAC_KEY": str(base_env["POLICY1_MAC_KEY"]),
            "SECURECLAW_REQUEST_BINDING_KEY_HEX": str(base_env["SECURECLAW_REQUEST_BINDING_KEY_HEX"]),
            "SECURECLAW_CONFIRM_TOKEN_KEY_HEX": str(base_env["SECURECLAW_CONFIRM_TOKEN_KEY_HEX"]),
            "EXECUTOR_REPLAY_DB_PATH": str(base_env["EXECUTOR_REPLAY_DB_PATH"]),
            "SIGNED_PIR": "1",
            "MIRAGE_POLICY_BYPASS": "0",
            "SINGLE_SERVER_POLICY": "0",
            "MIRAGE_ENFORCE_FINAL_OUTPUT_GATE": str(base_env["MIRAGE_ENFORCE_FINAL_OUTPUT_GATE"]),
            "MIRAGE_FINAL_OUTPUT_CONFIRM_ALWAYS": str(base_env["MIRAGE_FINAL_OUTPUT_CONFIRM_ALWAYS"]),
            "USE_POLICY_BUNDLE": str(base_env["USE_POLICY_BUNDLE"]),
            "DLP_MODE": str(base_env["DLP_MODE"]),
            "LEAKAGE_BUDGET_ENABLED": str(base_env["LEAKAGE_BUDGET_ENABLED"]),
            "MIRAGE_SESSION_ID": str(base_env["MIRAGE_SESSION_ID"]),
            "SECURECLAW_SESSION_SCOPE": str(base_env["SECURECLAW_SESSION_SCOPE"]),
            "SECURECLAW_STRICT_SINK_BINDING": str(base_env["SECURECLAW_STRICT_SINK_BINDING"]),
            "SECURECLAW_DENY_UNMAPPED_EFFECT": str(base_env["SECURECLAW_DENY_UNMAPPED_EFFECT"]),
            "SECURECLAW_ALLOW_LOCAL_STATE_EFFECTS": str(base_env["SECURECLAW_ALLOW_LOCAL_STATE_EFFECTS"]),
            "SECURECLAW_INTENT_CONTRACT_MODE": str(base_env["SECURECLAW_INTENT_CONTRACT_MODE"]),
            "SECURECLAW_MAX_TOOL_ITERS": str(base_env["SECURECLAW_MAX_TOOL_ITERS"]),
            "SECURECLAW_LOCAL_RECIPIENT": str(base_env["SECURECLAW_LOCAL_RECIPIENT"]),
            "SECURECLAW_LOCAL_DOMAIN": str(base_env["SECURECLAW_LOCAL_DOMAIN"]),
            "SECURECLAW_ENFORCE_COMMIT_PATH": str(base_env["SECURECLAW_ENFORCE_COMMIT_PATH"]),
            "SECURECLAW_AUTO_USER_CONFIRM": str(base_env["SECURECLAW_AUTO_USER_CONFIRM"]),
            "SECURECLAW_HANDLEIZE_READ_OUTPUT": str(base_env["SECURECLAW_HANDLEIZE_READ_OUTPUT"]),
            "SECURECLAW_READ_HANDLE_SENSITIVITY": str(base_env["SECURECLAW_READ_HANDLE_SENSITIVITY"]),
            "SECURECLAW_READ_HANDLE_TTL_S": str(base_env["SECURECLAW_READ_HANDLE_TTL_S"]),
            "SECURECLAW_READ_OUTPUT_MODE": str(base_env["SECURECLAW_READ_OUTPUT_MODE"]),
            "SECURECLAW_READ_SUMMARY_MAX_ITEMS": str(base_env["SECURECLAW_READ_SUMMARY_MAX_ITEMS"]),
            "SECURECLAW_READ_SUMMARY_MAX_CHARS": str(base_env["SECURECLAW_READ_SUMMARY_MAX_CHARS"]),
            "LEAKAGE_BUDGET_DB_PATH": str(base_env["LEAKAGE_BUDGET_DB_PATH"]),
            "MEMORY_DB_PATH": str(base_env["MEMORY_DB_PATH"]),
            "INTER_AGENT_DB_PATH": str(base_env["INTER_AGENT_DB_PATH"]),
            "POLICY_CONFIG_PATH": str(base_env["POLICY_CONFIG_PATH"]),
        }
        return self

    def __exit__(self, exc_type, exc, tb):
        for p in self.procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in self.procs:
            try:
                p.wait(timeout=2)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        for sock in self.run_dir.glob("runtime_state/*.sock"):
            try:
                sock.unlink()
            except Exception:
                pass


def _run_one(
    *,
    mode: str,
    suite: str,
    defense: str,
    model: str,
    benchmark_version: str,
    attack_name: str,
    out_dir: Path,
    logs_dir: Path,
    env_extra: dict[str, str],
    expected_rows: int,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "results.jsonl"

    exp = int(expected_rows)
    ri = _resume_info(mode, results_path)
    if ri.has_summary and ri.unique_rows >= exp and exp > 0:
        return {"status": "SKIP_COMPLETE", "rows": ri.unique_rows, "expected_rows": exp}

    log_path = logs_dir / f"{defense}_{mode}_{suite}.log"
    cmd = [
        sys.executable,
        "run/eval.py",
        "--benchmark_version",
        str(benchmark_version),
        "--suite_name",
        str(suite),
        "--agent_model",
        str(model),
        "--attack_name",
        str(attack_name),
        "--defense_name",
        str(defense),
        "--output_dir",
        str(out_dir),
        "--mode",
        str(mode),
        "--uid",
        str(ri.next_uid),
        "--iid",
        str(ri.next_iid),
    ]
    env = os.environ.copy()
    env.update(env_extra)
    env["PYTHONPATH"] = f"{REPO_ROOT}:{IPIGUARD_DIR}:{IPIGUARD_DIR / 'agentdojo' / 'src'}:{env.get('PYTHONPATH','')}"

    with log_path.open("a", encoding="utf-8") as lf:
        lf.write(
            f"\n[launch] defense={defense} mode={mode} suite={suite} resume_uid={ri.next_uid} resume_iid={ri.next_iid} rows={ri.unique_rows}/{exp}\n"
        )
        lf.flush()
        p = subprocess.run(
            cmd,
            cwd=str(IPIGUARD_DIR),
            env=env,
            stdout=lf,
            stderr=lf,
            text=True,
            check=False,
        )

    ri2 = _resume_info(mode, results_path)
    return {
        "status": "OK" if int(p.returncode) == 0 else "ERROR",
        "rc": int(p.returncode),
        "rows": int(ri2.unique_rows),
        "expected_rows": int(exp),
        "has_summary": bool(ri2.has_summary),
        "log": str(log_path),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Run AgentDojo native plain/secureclaw baselines with resume.")
    ap.add_argument("--out-root", required=True)
    ap.add_argument("--model", default="gpt-4o-mini-2024-07-18")
    ap.add_argument("--benchmark-version", default="v1.1.2")
    ap.add_argument("--attack-name", default="important_instructions")
    ap.add_argument("--suites", default="banking,slack,travel,workspace")
    ap.add_argument("--modes", default="benign,under_attack")
    ap.add_argument("--run-plain", type=int, default=1)
    ap.add_argument("--run-secureclaw", type=int, default=1)
    args = ap.parse_args()

    out_root = Path(str(args.out_root)).expanduser().resolve()
    logs_dir = out_root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    suites = [s.strip() for s in str(args.suites).split(",") if s.strip()]
    modes = [m.strip() for m in str(args.modes).split(",") if m.strip()]
    _require_runtime_credentials(str(args.model))
    expected_rows = _compute_expected_rows(str(args.benchmark_version), suites)

    report: dict[str, Any] = {
        "status": "RUNNING",
        "benchmark": f"AgentDojo-{str(args.benchmark_version)}-native",
        "model": str(args.model),
        "benchmark_version": str(args.benchmark_version),
        "out_root": str(out_root),
        "expected_rows": expected_rows,
        "eval_config": {
            "uses_benchmark_ground_truth_policy_expansion": False,
            "policy_config_path_env": str(os.getenv("POLICY_CONFIG_PATH", "")),
            "policy_override_path_env": str(os.getenv("SECURECLAW_POLICY_OVERRIDE_PATH", "")),
            "intent_contract_mode": str(os.getenv("SECURECLAW_INTENT_CONTRACT_MODE", "intent_v1")),
            "uses_label_for_decision": False,
        },
        "plain": {},
        "secureclaw": {},
    }

    plain_root = out_root / "plain"
    secure_root = out_root / "secureclaw"

    env_base = {
        "OPENAI_API_KEY": str(os.getenv("OPENAI_API_KEY", "")),
        "OPENAI_BASE_URL": str(os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")),
        "IPIGUARD_OPENAI_TIMEOUT_S": str(os.getenv("IPIGUARD_OPENAI_TIMEOUT_S", "120")),
        "IPIGUARD_OPENAI_MAX_RETRIES": str(os.getenv("IPIGUARD_OPENAI_MAX_RETRIES", "0")),
        "IPIGUARD_LLM_RETRY_ATTEMPTS": str(os.getenv("IPIGUARD_LLM_RETRY_ATTEMPTS", "1")),
        "IPIGUARD_LLM_RETRY_MAX_WAIT_S": str(os.getenv("IPIGUARD_LLM_RETRY_MAX_WAIT_S", "10")),
        "IPIGUARD_LLM_RETRY_MULTIPLIER": str(os.getenv("IPIGUARD_LLM_RETRY_MULTIPLIER", "1")),
        "PYTHONUNBUFFERED": "1",
    }

    if int(args.run_plain):
        for mode in modes:
            for suite in suites:
                key = f"{mode}/{suite}"
                rec = _run_one(
                    mode=mode,
                    suite=suite,
                    defense="None",
                    model=str(args.model),
                    benchmark_version=str(args.benchmark_version),
                    attack_name=str(args.attack_name),
                    out_dir=plain_root / mode / suite,
                    logs_dir=logs_dir,
                    env_extra=env_base,
                    expected_rows=int(expected_rows.get(suite, {}).get(mode, 0)),
                )
                report["plain"][key] = rec
                (out_root / "agentdojo_native_plain_secureclaw_report.json").write_text(
                    json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
                )

    if int(args.run_secureclaw):
        with SecureClawInfra(
            run_dir=secure_root / "infra",
            benchmark_version=str(args.benchmark_version),
            suites=suites,
        ) as infra:
            env_sc = dict(env_base)
            env_sc.update(infra.env_patch)
            for mode in modes:
                for suite in suites:
                    key = f"{mode}/{suite}"
                    rec = _run_one(
                        mode=mode,
                        suite=suite,
                        defense="secureclaw",
                        model=str(args.model),
                        benchmark_version=str(args.benchmark_version),
                        attack_name=str(args.attack_name),
                        out_dir=secure_root / mode / suite,
                        logs_dir=logs_dir,
                        env_extra=env_sc,
                        expected_rows=int(expected_rows.get(suite, {}).get(mode, 0)),
                    )
                    report["secureclaw"][key] = rec
                    (out_root / "agentdojo_native_plain_secureclaw_report.json").write_text(
                        json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
                    )

    fairness: dict[str, Any] = {"status": "ok", "under_attack": {}}
    fairness_reasons: list[str] = []
    for suite in suites:
        key = f"under_attack/{suite}"
        exp = int(expected_rows.get(suite, {}).get("under_attack", 0))
        p = report.get("plain", {}).get(key, {}) if isinstance(report.get("plain"), dict) else {}
        s = report.get("secureclaw", {}).get(key, {}) if isinstance(report.get("secureclaw"), dict) else {}
        p_rows = int((p or {}).get("rows") or 0)
        s_rows = int((s or {}).get("rows") or 0)
        fairness["under_attack"][suite] = {
            "expected_rows": exp,
            "plain_rows": p_rows,
            "secureclaw_rows": s_rows,
            "rows_equal": bool(p_rows == s_rows),
            "rows_match_expected": bool(exp > 0 and p_rows == exp and s_rows == exp),
        }
        if p_rows != s_rows:
            fairness_reasons.append(f"rows_mismatch:{suite}:{p_rows}!={s_rows}")
        if exp > 0 and (p_rows != exp or s_rows != exp):
            fairness_reasons.append(f"rows_not_expected:{suite}:plain={p_rows},secureclaw={s_rows},expected={exp}")
    if fairness_reasons:
        fairness["status"] = "invalid"
        fairness["reasons"] = fairness_reasons
        report["status"] = "ERROR_FAIRNESS"
    else:
        report["status"] = "OK"
    report["fairness"] = fairness
    out_path = out_root / "agentdojo_native_plain_secureclaw_report.json"
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(str(out_path))


if __name__ == "__main__":
    main()
