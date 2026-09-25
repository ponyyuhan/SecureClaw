from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple
from concurrent.futures import ThreadPoolExecutor
import ast
from pathlib import Path

import requests
import yaml

from common.canonical import request_sha256_v1, sha256_hex
from common.sanitize import (
    PATCH_CLAMP_LEN,
    PATCH_NOOP,
    PATCH_REWRITE_DOMAIN_TO_PROXY,
    SanitizePatch,
)
from .capabilities import get_effective_capabilities
from .fss_pir import PirClient
from .guardrails import fourgram_indices, stable_idx
from .handles import HandleStore
from .tx_store import TxStore
from .policy_unified import UnifiedPolicyEngine
from .http_session import session_for


_HTTP_POOL = ThreadPoolExecutor(max_workers=8)


def _hash_context_from_constraints(constraints: Dict[str, Any] | None) -> dict[str, Any]:
    auth_ctx = (constraints or {}).get("_auth_ctx") if isinstance((constraints or {}).get("_auth_ctx"), dict) else {}
    out: dict[str, Any] = {}
    external_principal = str((auth_ctx or {}).get("external_principal") or "").strip()
    delegation_jti = str((auth_ctx or {}).get("delegation_jti") or "").strip()
    if external_principal:
        out["external_principal"] = external_principal
    if delegation_jti:
        out["delegation_jti"] = delegation_jti
    raw_targets = (constraints or {}).get("contextual_targets") if isinstance((constraints or {}).get("contextual_targets"), list) else []
    normalized_targets = sorted({str(x or "").strip().lower() for x in raw_targets if str(x or "").strip()})
    if normalized_targets:
        out["contextual_targets_sha256"] = sha256_hex("|".join(normalized_targets).encode("utf-8"))
    # Task capsule: bind the user-mentioned principal set hash into the request digest
    # so it cannot be modified after preview (Proposition 6 / prop:capsule).
    capsule_hash = str((constraints or {}).get("capsule_hash") or "").strip()
    if capsule_hash:
        out["capsule_hash"] = capsule_hash
    return out


@dataclass(frozen=True, slots=True)
class Gate:
    op: str
    out: int
    a: int | None = None
    b: int | None = None
    value: int | None = None


@dataclass(frozen=True, slots=True)
class Circuit:
    n_wires: int
    gates: List[Gate]
    inputs: Dict[str, int]
    outputs: Dict[str, int]
    and_gate_indices: List[int]


class _CircuitBuilder:
    def __init__(self) -> None:
        self._w = 0
        self.inputs: Dict[str, int] = {}
        self.gates: List[Gate] = []
        self.and_gate_indices: List[int] = []

    def input(self, name: str) -> int:
        if name in self.inputs:
            return int(self.inputs[name])
        wi = self._w
        self._w += 1
        self.inputs[str(name)] = wi
        return wi

    def const(self, value: int) -> int:
        wi = self._w
        self._w += 1
        self.gates.append(Gate(op="CONST", out=wi, value=int(value) & 1))
        return wi

    def xor(self, a: int, b: int) -> int:
        wi = self._w
        self._w += 1
        self.gates.append(Gate(op="XOR", out=wi, a=int(a), b=int(b)))
        return wi

    def not_(self, a: int) -> int:
        wi = self._w
        self._w += 1
        self.gates.append(Gate(op="NOT", out=wi, a=int(a)))
        return wi

    def and_(self, a: int, b: int) -> int:
        wi = self._w
        self._w += 1
        self.and_gate_indices.append(len(self.gates))
        self.gates.append(Gate(op="AND", out=wi, a=int(a), b=int(b)))
        return wi


def build_egress_v1_circuit() -> Circuit:
    """
    Unified egress policy circuit used for intent shadowing.

    Inputs (all secret-shared bits):
    - intent_send, intent_fetch, intent_webhook (one-hot)
    - cap_send, cap_fetch, cap_webhook
    - recipient_ok, domain_ok
    - dlp_hit
    - high_handle_present

    Outputs (secret-shared bits):
    - allow_pre
    - need_confirm
    - patch0, patch1  (2-bit patch_id, little-endian)
    """
    b = _CircuitBuilder()
    intent_send = b.input("intent_send")
    intent_fetch = b.input("intent_fetch")
    intent_webhook = b.input("intent_webhook")

    cap_send = b.input("cap_send")
    cap_fetch = b.input("cap_fetch")
    cap_webhook = b.input("cap_webhook")

    recipient_ok = b.input("recipient_ok")
    domain_ok = b.input("domain_ok")
    dlp_hit = b.input("dlp_hit")
    high_handle = b.input("high_handle_present")

    not_high = b.not_(high_handle)

    # allow_pre per intent
    allow_send_pre = b.and_(cap_send, recipient_ok)
    allow_send_pre = b.and_(allow_send_pre, not_high)

    allow_fetch_pre = b.and_(cap_fetch, domain_ok)

    allow_webhook_pre = b.and_(cap_webhook, domain_ok)
    allow_webhook_pre = b.and_(allow_webhook_pre, not_high)

    # select by (secret) intent one-hot bits
    term_send = b.and_(intent_send, allow_send_pre)
    term_fetch = b.and_(intent_fetch, allow_fetch_pre)
    term_webhook = b.and_(intent_webhook, allow_webhook_pre)
    allow_pre = b.xor(b.xor(term_send, term_fetch), term_webhook)

    # need_confirm only for send/webhook: need_confirm = intent_send&dlp_hit XOR intent_webhook&dlp_hit
    conf_send = b.and_(intent_send, dlp_hit)
    conf_webhook = b.and_(intent_webhook, dlp_hit)
    need_confirm = b.xor(conf_send, conf_webhook)

    # Patch id: REDACT (1) when need_confirm else NOOP.
    # patch bits are outputs so executor can enforce sanitize.
    patch0 = need_confirm
    patch1 = b.const(0)

    outputs = {
        "allow_pre": allow_pre,
        "need_confirm": need_confirm,
        "patch0": patch0,
        "patch1": patch1,
    }
    return Circuit(n_wires=b._w, gates=b.gates, inputs=b.inputs, outputs=outputs, and_gate_indices=b.and_gate_indices)


def _load_policy_config() -> dict[str, Any]:
    cfg_path = os.getenv("POLICY_CONFIG_PATH", "").strip()
    if not cfg_path:
        repo_root = Path(__file__).resolve().parents[1]
        p = repo_root / "policy_server" / "policy.yaml"
        if p.exists():
            cfg_path = str(p)
    if not cfg_path:
        return {}
    try:
        cfg = yaml.safe_load(Path(cfg_path).read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    return cfg if isinstance(cfg, dict) else {}


def build_egress_v1_circuit_from_policy(cfg: dict[str, Any]) -> Circuit | None:
    programs = cfg.get("policy_programs") if isinstance(cfg, dict) else None
    if not isinstance(programs, dict):
        return None
    prog = programs.get("egress_v1")
    if not isinstance(prog, dict):
        return None
    intents = prog.get("intents")
    if not isinstance(intents, dict):
        return None

    b = _CircuitBuilder()

    # Inputs must exist even if some intent expressions do not use them (intent shadowing).
    for nm in [
        "intent_send",
        "intent_fetch",
        "intent_webhook",
        "cap_send",
        "cap_fetch",
        "cap_webhook",
        "recipient_ok",
        "domain_ok",
        "dlp_hit",
        "high_handle_present",
    ]:
        b.input(nm)

    def compile_expr(expr: str) -> int:
        s = str(expr or "").strip()
        if not s:
            s = "0"
        node = ast.parse(s, mode="eval").body

        def _c(n: ast.AST) -> int:
            if isinstance(n, ast.Name):
                name = str(n.id)
                if name not in b.inputs:
                    raise ValueError(f"unknown var: {name}")
                return int(b.inputs[name])
            if isinstance(n, ast.Constant):
                if isinstance(n.value, bool):
                    return b.const(1 if n.value else 0)
                if isinstance(n.value, int):
                    return b.const(int(n.value) & 1)
                raise ValueError("bad constant")
            if isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Invert):
                return b.not_(_c(n.operand))
            if isinstance(n, ast.BinOp):
                if isinstance(n.op, ast.BitAnd):
                    return b.and_(_c(n.left), _c(n.right))
                if isinstance(n.op, ast.BitXor):
                    return b.xor(_c(n.left), _c(n.right))
                if isinstance(n.op, ast.BitOr):
                    a = _c(n.left)
                    c = _c(n.right)
                    ax = b.xor(a, c)
                    an = b.and_(a, c)
                    return b.xor(ax, an)
            raise ValueError("unsupported expression")

        return _c(node)

    # Per-intent formulas compiled from DSL.
    def intent_bit_for(name: str) -> str:
        if name == "SendMessage":
            return "intent_send"
        if name == "FetchResource":
            return "intent_fetch"
        if name == "PostWebhook":
            return "intent_webhook"
        raise ValueError(f"unsupported intent in policy_programs.egress_v1: {name}")

    allow_terms: list[int] = []
    conf_terms: list[int] = []
    patch0_terms: list[int] = []
    patch1_terms: list[int] = []

    for intent_name, icfg in intents.items():
        if not isinstance(icfg, dict):
            continue
        intent_name = str(intent_name)
        ib = int(b.inputs[intent_bit_for(intent_name)])

        allow_i = compile_expr(str(icfg.get("allow_pre") or "0"))
        conf_i = compile_expr(str(icfg.get("need_confirm") or "0"))
        patch0_i = compile_expr(str(icfg.get("patch0") or "0"))
        patch1_i = compile_expr(str(icfg.get("patch1") or "0"))

        allow_terms.append(b.and_(ib, allow_i))
        conf_terms.append(b.and_(ib, conf_i))
        patch0_terms.append(b.and_(ib, patch0_i))
        patch1_terms.append(b.and_(ib, patch1_i))

    def xor_reduce(ws: list[int]) -> int:
        if not ws:
            return b.const(0)
        acc = int(ws[0])
        for w in ws[1:]:
            acc = b.xor(acc, int(w))
        return acc

    allow_pre = xor_reduce(allow_terms)
    need_confirm = xor_reduce(conf_terms)
    patch0 = xor_reduce(patch0_terms)
    patch1 = xor_reduce(patch1_terms)

    outputs = {
        "allow_pre": allow_pre,
        "need_confirm": need_confirm,
        "patch0": patch0,
        "patch1": patch1,
    }
    return Circuit(n_wires=b._w, gates=b.gates, inputs=b.inputs, outputs=outputs, and_gate_indices=b.and_gate_indices)


def _share_bit(x: int) -> Tuple[int, int]:
    r = secrets.randbits(1) & 1
    return r, (r ^ (int(x) & 1)) & 1


class EgressPolicyEngine:
    def __init__(self, *, pir: PirClient, handles: HandleStore, tx_store: TxStore, domain_size: int, max_tokens: int):
        self.pir = pir
        self.handles = handles
        self.tx = tx_store
        self.domain_size = int(domain_size)
        self.max_tokens = int(max_tokens)

        self.unified_policy = bool(int(os.getenv("UNIFIED_POLICY", "1")))

        # Policy knobs
        self.signed_pir = bool(int(os.getenv("SIGNED_PIR", "1")))
        self.dlp_mode = (os.getenv("DLP_MODE", "fourgram") or "fourgram").strip().lower()
        self.intent_shadowing = bool(int(os.getenv("INTENT_SHADOWING", "1")))
        self.use_bundle = bool(int(os.getenv("USE_POLICY_BUNDLE", "1")))
        # Baseline knobs (never enable in full security mode).
        self.policy_bypass = bool(int(os.getenv("MIRAGE_POLICY_BYPASS", "0")))
        self.single_server_cleartext = bool(int(os.getenv("SINGLE_SERVER_POLICY", "0")))
        self.single_server_id = int(os.getenv("SINGLE_SERVER_ID", "0") or "0")

        self._bundle_cache: dict[str, Any] | None = None
        cfg = _load_policy_config()
        self._circuit = build_egress_v1_circuit_from_policy(cfg) or build_egress_v1_circuit()
        self._unified: UnifiedPolicyEngine | None = None
        if self.unified_policy:
            # Unified program hides intent category at the policy server by using a
            # single constant-shape MPC program + a single bundled PIR surface.
            self._unified = UnifiedPolicyEngine(pir=pir, handles=handles, tx_store=tx_store, domain_size=domain_size, max_tokens=max_tokens)

    def _query_bits_signed_or_single_server(
        self,
        *,
        db_name: str,
        idxs: list[int],
        action_id: str,
        domain_size: int | None = None,
    ) -> tuple[list[int], dict[str, Any]]:
        if self.single_server_cleartext:
            return self.pir.query_bits_single_server_cleartext_signed(
                db_name,
                idxs,
                action_id=action_id,
                server_id=self.single_server_id,
                domain_size=domain_size,
            )
        return self.pir.query_bits_signed(db_name, idxs, action_id=action_id, domain_size=domain_size)

    def _load_bundle(self) -> dict[str, Any] | None:
        if self._bundle_cache is not None:
            return self._bundle_cache
        if not self.use_bundle:
            self._bundle_cache = None
            return None
        try:
            u0 = str(self.pir.policy0_url).rstrip("/")
            meta = session_for(u0).get(f"{u0}/meta", timeout=2.0).json()
        except Exception:
            self._bundle_cache = None
            return None
        b = (meta.get("bundle") or {}) if isinstance(meta, dict) else {}
        if not isinstance(b, dict) or not b.get("enabled"):
            self._bundle_cache = None
            return None
        self._bundle_cache = b
        return b

    def _bundle_idx(self, *, logical: str, raw_idx: int, bundle_env: str) -> tuple[str, int, int | None]:
        """
        Return (db_name, idx, domain_size_override).

        If bundle is enabled, returns a bundled db name and shifted idx inside the bundle domain.
        """
        b = self._load_bundle()
        if not b:
            return logical, int(raw_idx), None
        base_ds = int(b.get("base_domain_size") or self.domain_size)
        bundles = b.get("bundles") or {"default": 0}
        if not isinstance(bundles, dict):
            bundles = {"default": 0}
        bundle_name = (os.getenv(bundle_env, "default") or "default").strip()
        bid = int(bundles.get(bundle_name, 0))
        stride = int(b.get("bundle_stride") or 0)
        offs = b.get("logical_offsets") or {}
        if not isinstance(offs, dict):
            offs = {}
        loff = int(offs.get(str(logical), 0))
        idx = (bid * stride) + loff + (int(raw_idx) % base_ds)
        dom = int(b.get("bundle_domain_size") or 0) or None
        return str(b.get("db") or "policy_bundle"), int(idx), dom

    def _contains_high_handle(self, artifacts: List[Dict[str, Any]], *, session: str, caller: str) -> tuple[bool, str]:
        for a in artifacts or []:
            hid = a.get("handle") if isinstance(a, dict) else None
            if not hid:
                continue
            rec = self.handles.get(str(hid))
            if not rec:
                continue
            if rec.session != session:
                return True, "HANDLE_SESSION_MISMATCH"
            if rec.caller != caller:
                return True, "HANDLE_CALLER_MISMATCH"
            if rec.sensitivity.upper() == "HIGH":
                return True, "HIGH_HANDLE_BLOCKED"
        return False, ""

    def _mpc_init_two_party(self, *, action_id: str, program_id: str, request_sha256: str, input0: dict[int, int], input1: dict[int, int]) -> None:
        gates = [{"op": g.op, "out": int(g.out), "a": g.a, "b": g.b, "value": g.value} for g in self._circuit.gates]
        payload0 = {
            "action_id": action_id,
            "program_id": program_id,
            "request_sha256": request_sha256,
            "n_wires": int(self._circuit.n_wires),
            "gates": gates,
            "input_shares": {str(k): int(v) & 1 for k, v in (input0 or {}).items()},
            "outputs": {k: int(v) for k, v in self._circuit.outputs.items()},
            "ttl_seconds": int(os.getenv("MPC_SESSION_TTL_S", "30")),
        }
        payload1 = dict(payload0)
        payload1["input_shares"] = {str(k): int(v) & 1 for k, v in (input1 or {}).items()}

        u0 = str(self.pir.policy0_url).rstrip("/")
        u1 = str(self.pir.policy1_url).rstrip("/")
        f0 = _HTTP_POOL.submit(session_for(u0).post, f"{u0}/mpc/init", json=payload0, timeout=10)
        f1 = _HTTP_POOL.submit(session_for(u1).post, f"{u1}/mpc/init", json=payload1, timeout=10)
        r0 = f0.result()
        r1 = f1.result()
        r0.raise_for_status()
        r1.raise_for_status()
        if not r0.json().get("ok") or not r1.json().get("ok"):
            raise RuntimeError("mpc_init_failed")

    def _mpc_eval_and_gates(self, *, action_id: str) -> None:
        u0 = str(self.pir.policy0_url).rstrip("/")
        u1 = str(self.pir.policy1_url).rstrip("/")
        for gi in self._circuit.and_gate_indices:
            # Beaver triple (a,b,c=a&b) secret shared across parties.
            a = secrets.randbits(1) & 1
            b = secrets.randbits(1) & 1
            c = (a & b) & 1
            a0, a1 = _share_bit(a)
            b0, b1 = _share_bit(b)
            c0, c1 = _share_bit(c)

            m0 = {"action_id": action_id, "gate_index": int(gi), "a_share": a0, "b_share": b0, "c_share": c0}
            m1 = {"action_id": action_id, "gate_index": int(gi), "a_share": a1, "b_share": b1, "c_share": c1}
            f0 = _HTTP_POOL.submit(session_for(u0).post, f"{u0}/mpc/and_mask", json=m0, timeout=10)
            f1 = _HTTP_POOL.submit(session_for(u1).post, f"{u1}/mpc/and_mask", json=m1, timeout=10)
            r0 = f0.result()
            r1 = f1.result()
            r0.raise_for_status()
            r1.raise_for_status()
            j0 = r0.json()
            j1 = r1.json()
            d = (int(j0.get("d_share", 0)) ^ int(j1.get("d_share", 0))) & 1
            e = (int(j0.get("e_share", 0)) ^ int(j1.get("e_share", 0))) & 1

            fin = {"action_id": action_id, "gate_index": int(gi), "d": int(d), "e": int(e)}
            f0 = _HTTP_POOL.submit(session_for(u0).post, f"{u0}/mpc/and_finish", json=fin, timeout=10)
            f1 = _HTTP_POOL.submit(session_for(u1).post, f"{u1}/mpc/and_finish", json=fin, timeout=10)
            r0 = f0.result()
            r1 = f1.result()
            r0.raise_for_status()
            r1.raise_for_status()
            # z_shares are stored server-side; no need to read.

    def _mpc_finalize(self, *, action_id: str) -> dict[str, Any]:
        payload = {"action_id": action_id}
        u0 = str(self.pir.policy0_url).rstrip("/")
        u1 = str(self.pir.policy1_url).rstrip("/")
        f0 = _HTTP_POOL.submit(session_for(u0).post, f"{u0}/mpc/finalize", json=payload, timeout=10)
        f1 = _HTTP_POOL.submit(session_for(u1).post, f"{u1}/mpc/finalize", json=payload, timeout=10)
        r0 = f0.result()
        r1 = f1.result()
        r0.raise_for_status()
        r1.raise_for_status()
        j0 = r0.json()
        j1 = r1.json()
        if not j0.get("ok") or not j1.get("ok"):
            raise RuntimeError("mpc_finalize_failed")
        return {"policy0": j0.get("proof"), "policy1": j1.get("proof")}

    def preview(
        self,
        *,
        intent_id: str,
        inputs: Dict[str, Any],
        constraints: Dict[str, Any],
        session: str,
        caller: str,
    ) -> Dict[str, Any]:
        """Run PREVIEW for a side-effect intent and return a tx_id to commit later."""
        if self._unified is not None:
            return self._unified.preview_egress(intent_id=intent_id, inputs=inputs, constraints=constraints, session=session, caller=caller)
        auth_ctx = (constraints or {}).get("_auth_ctx") if isinstance((constraints or {}).get("_auth_ctx"), dict) else {}
        external_principal = str((auth_ctx or {}).get("external_principal") or "")
        delegation_jti = str((auth_ctx or {}).get("delegation_jti") or "")
        hash_ctx: dict[str, Any] = {}
        if external_principal:
            hash_ctx["external_principal"] = external_principal
        if delegation_jti:
            hash_ctx["delegation_jti"] = delegation_jti
        intent = str(intent_id)
        if intent not in ("SendMessage", "FetchResource", "PostWebhook", "CheckMessagePolicy", "CheckWebhookPolicy", "CheckFetchPolicy"):
            raise ValueError("unsupported intent for egress policy preview")

        # Normalize all egress-like intents into a unified policy request surface.
        # This lets us hide intent_id from policy servers by always issuing a fixed-shape set of PIR queries
        # and evaluating a fixed circuit (intent shadowing).
        is_send = 1 if intent in ("SendMessage", "CheckMessagePolicy") else 0
        is_fetch = 1 if intent in ("FetchResource", "CheckFetchPolicy") else 0
        is_webhook = 1 if intent in ("PostWebhook", "CheckWebhookPolicy") else 0

        recipient_real = str(inputs.get("recipient", ""))
        text_real = str(inputs.get("text", ""))
        domain_real = str(inputs.get("domain", "example.com"))
        channel_real = str(inputs.get("channel", "email"))
        resource_id_real = str(inputs.get("resource_id", "example"))
        path_real = str(inputs.get("path", "/"))

        # Dummy values for shadowed fields (do not affect selected intent semantics).
        dummy_recipient = os.getenv("DUMMY_RECIPIENT", "alice@example.com")
        dummy_domain = os.getenv("DUMMY_DOMAIN", "example.com")
        dummy_text = os.getenv("DUMMY_TEXT", "hello world")

        recipient = recipient_real if is_send else str(dummy_recipient)
        text = text_real if (is_send or is_webhook) else str(dummy_text)
        domain = domain_real if (is_fetch or is_webhook) else str(dummy_domain)

        artifacts = inputs.get("artifacts", []) or []
        bad_handle, bad_code = self._contains_high_handle(list(artifacts) if isinstance(artifacts, list) else [], session=session, caller=caller)
        if bad_handle:
            # Hard-stop in gateway: handle-flow is a Level-1 property (handles live inside gateway TCB).
            return {
                "allow_pre": False,
                "need_confirm": False,
                "patch": SanitizePatch(PATCH_NOOP, {}).to_dict(),
                "reason_code": bad_code,
                "details": "Sensitive handle cannot be externalized.",
                "evidence": {},
                "tx_id": None,
            }

        # Capabilities (caller projection) is secret-shared into the MPC inputs.
        caps = get_effective_capabilities(caller, external_principal=(external_principal or None))
        cap_send = 1 if caps.egress_ok(kind="send_message") else 0
        cap_fetch = 1 if caps.egress_ok(kind="fetch_resource") else 0
        cap_webhook = 1 if caps.egress_ok(kind="post_webhook") else 0

        # Always issue the same set of PIR queries (recipient + domain + tokens) to reduce intent leakage.
        action_id = f"a_{secrets.token_urlsafe(12)}"

        # Bind commit tokens to the *effectful* inputs only. Commit-phase flags like user_confirm are excluded.
        canonical_intent = ("SendMessage" if is_send else ("FetchResource" if is_fetch else "PostWebhook"))
        # Include effectful fields in the request binding hash. Shadowed/dummy fields are included explicitly
        # (the executor replays the same hash computation).
        sha_inputs: dict[str, Any] = {"recipient": recipient, "domain": domain, "text": text}
        if canonical_intent == "SendMessage":
            sha_inputs["channel"] = channel_real
        elif canonical_intent == "FetchResource":
            sha_inputs["resource_id"] = resource_id_real
        else:
            sha_inputs["path"] = path_real
            sha_inputs["body"] = text

        request_sha = request_sha256_v1(
            intent_id=canonical_intent,
            caller=caller,
            session=session,
            inputs=sha_inputs,
            context=hash_ctx,
        )

        # Baseline-only insecure mode: bypass policy checks and PIR/MPC entirely.
        # This is used for ablations such as "sandbox-only".
        if self.policy_bypass:
            patch = SanitizePatch(PATCH_NOOP, {})
            preview = {
                "program_id": "egress_v1",
                "action_id": action_id,
                "request_sha256": request_sha,
                "auth_context": hash_ctx,
                "allow_pre": True,
                "need_confirm": False,
                "patch": patch.to_dict(),
                "pir_evidence": {},
                "commit_evidence": {},
                "baseline_mode": "policy_bypass",
            }
            tx_rec = self.tx.mint(
                intent_id=str(intent_id),
                action_id=action_id,
                request_sha256=request_sha,
                caller=caller,
                session=session,
                preview=preview,
                ttl_seconds=int(os.getenv("TX_TTL_S", "120")),
            )
            return {
                "allow_pre": True,
                "need_confirm": False,
                "patch": patch.to_dict(),
                "reason_code": "ALLOW_INSECURE_POLICY_BYPASS",
                "details": "",
                "evidence": {"commit": {}, "pir": {}},
                "tx_id": tx_rec.tx_id,
                "action_id": action_id,
                "request_sha256": request_sha,
            }

        # Shaping/ablation knob for leakage evaluation:
        # - fixed-shape (default): always issue recipient + domain + token queries (dummy-filled when irrelevant)
        # - unshaped: issue only the minimal queries needed for the selected intent (leaks intent class via transcript)
        fixed_shape = bool(int(os.getenv("SHAPE_EGRESS_FIXED", "1")))
        do_rec = fixed_shape or bool(is_send)
        do_dom = fixed_shape or bool(is_fetch or is_webhook)
        do_tok = fixed_shape or bool(is_send or is_webhook)

        if not self.signed_pir:
            raise RuntimeError("FULL policy engine requires SIGNED_PIR=1 (demo)")

        # 1) Recipient allowlist bit (oblivious)
        rbits: list[int] = [1]
        ev_rec: dict[str, Any] | None = None
        if do_rec:
            ridx_raw = stable_idx(recipient, self.domain_size)
            db_rec, ridx, dom_rec = self._bundle_idx(logical="allow_recipients", raw_idx=ridx_raw, bundle_env="POLICY_BUNDLE_EGRESS")
            rbits, ev_rec = self._query_bits_signed_or_single_server(
                db_name=db_rec,
                idxs=[ridx],
                action_id=action_id,
                domain_size=dom_rec,
            )

        # 2) Domain allowlist bit (oblivious)
        dbits: list[int] = [1]
        ev_dom: dict[str, Any] | None = None
        if do_dom:
            didx_raw = stable_idx(domain, self.domain_size)
            db_dom, didx, dom_dom = self._bundle_idx(logical="allow_domains", raw_idx=didx_raw, bundle_env="POLICY_BUNDLE_NET")
            dbits, ev_dom = self._query_bits_signed_or_single_server(
                db_name=db_dom,
                idxs=[didx],
                action_id=action_id,
                domain_size=dom_dom,
            )

        # 3) DLP token hits (oblivious). We only feed an aggregated hit bit into MPC for now.
        hits: list[int] = []
        ev_tok: dict[str, Any] | None = None
        coarse_hit = 0
        if do_tok:
            idxs_raw = fourgram_indices(text, self.domain_size, self.max_tokens)
            db_tok, _idx0, _dom_tok = self._bundle_idx(logical="banned_tokens", raw_idx=0, bundle_env="POLICY_BUNDLE_EGRESS")
            if db_tok == "banned_tokens":
                idxs2 = idxs_raw
                dom2 = None
            else:
                # bundle idx shift per token
                b = self._load_bundle() or {}
                base_ds = int(b.get("base_domain_size") or self.domain_size)
                bundles = b.get("bundles") or {"default": 0}
                if not isinstance(bundles, dict):
                    bundles = {"default": 0}
                bundle_name = (os.getenv("POLICY_BUNDLE_EGRESS", "default") or "default").strip()
                bid = int(bundles.get(bundle_name, 0))
                stride = int(b.get("bundle_stride") or 0)
                offs = b.get("logical_offsets") or {}
                loff = int((offs or {}).get("banned_tokens", 0))
                idxs2 = [(bid * stride) + loff + (int(x) % base_ds) for x in idxs_raw]
                dom2 = int(b.get("bundle_domain_size") or 0) or None
            hits, ev_tok = self._query_bits_signed_or_single_server(
                db_name=db_tok,
                idxs=idxs2,
                action_id=action_id,
                domain_size=dom2,
            )
            coarse_hit = 1 if any(int(h) == 1 for h in hits) else 0

        # Optional confirm stage: keep existing dfa knob semantics.
        confirmed = coarse_hit
        dfa_ev = None
        if coarse_hit and self.dlp_mode == "dfa":
            # Use the existing oblivious DFA transition DB (Aho-Corasick) if present.
            # For the MPC program we only need the final confirmed bit (still secret-shared).
            from .guardrails import ObliviousGuardrails  # local import to avoid cycles

            tmp = ObliviousGuardrails(pir=self.pir, handles=self.handles, domain_size=self.domain_size, max_tokens=self.max_tokens, dlp_mode="dfa", signed_pir=True)
            matched, dfa_ev = tmp._dfa_match(text, action_id=action_id)
            confirmed = 1 if matched else 0

        # Secret-share MPC inputs.
        in0: dict[int, int] = {}
        in1: dict[int, int] = {}

        def set_in(name: str, share0: int, share1: int) -> None:
            wi = int(self._circuit.inputs[name])
            in0[wi] = int(share0) & 1
            in1[wi] = int(share1) & 1

        # intent one-hot (secret-shared)
        for nm, bit in [("intent_send", is_send), ("intent_fetch", is_fetch), ("intent_webhook", is_webhook)]:
            s0, s1 = _share_bit(bit)
            set_in(nm, s0, s1)
        for nm, bit in [("cap_send", cap_send), ("cap_fetch", cap_fetch), ("cap_webhook", cap_webhook)]:
            s0, s1 = _share_bit(bit)
            set_in(nm, s0, s1)

        # allowlist bits: use PIR answer shares from the signed evidence (already secret shares)
        # proof format: {a0, a1, ...}
        rec_a0 = (ev_rec or {}).get("a0") or [0]
        rec_a1 = (ev_rec or {}).get("a1") or [0]
        dom_a0 = (ev_dom or {}).get("a0") or [0]
        dom_a1 = (ev_dom or {}).get("a1") or [0]
        set_in("recipient_ok", int(rec_a0[0]) & 1, int(rec_a1[0]) & 1)
        set_in("domain_ok", int(dom_a0[0]) & 1, int(dom_a1[0]) & 1)

        # dlp_hit: secret-share the (possibly confirmed) hit bit.
        d0, d1 = _share_bit(int(confirmed) & 1)
        set_in("dlp_hit", d0, d1)

        # high_handle_present: already checked as hard-stop; provide 0 to MPC.
        set_in("high_handle_present", 0, 0)

        program_id = "egress_v1"
        self._mpc_init_two_party(action_id=action_id, program_id=program_id, request_sha256=request_sha, input0=in0, input1=in1)

        self._mpc_eval_and_gates(action_id=action_id)
        commit_ev = self._mpc_finalize(action_id=action_id)

        # Reconstruct outputs (gateway is trusted; reconstruction happens only here).
        p0 = (commit_ev.get("policy0") or {}) if isinstance(commit_ev, dict) else {}
        p1 = (commit_ev.get("policy1") or {}) if isinstance(commit_ev, dict) else {}
        o0 = p0.get("outputs") or {}
        o1 = p1.get("outputs") or {}
        allow_pre = (int(o0.get("allow_pre", 0)) ^ int(o1.get("allow_pre", 0))) & 1
        need_confirm = (int(o0.get("need_confirm", 0)) ^ int(o1.get("need_confirm", 0))) & 1
        patch0 = (int(o0.get("patch0", 0)) ^ int(o1.get("patch0", 0))) & 1
        patch1 = (int(o0.get("patch1", 0)) ^ int(o1.get("patch1", 0))) & 1
        patch_id = (patch0 | (patch1 << 1)) & 3

        patch_params: dict[str, Any] = {}
        if patch_id == PATCH_CLAMP_LEN:
            patch_params["max_chars"] = int(os.getenv("PATCH_CLAMP_MAX_CHARS", "256"))
        if patch_id == PATCH_REWRITE_DOMAIN_TO_PROXY:
            patch_params["proxy_domain"] = os.getenv("PATCH_PROXY_DOMAIN", "proxy.example.com")
        patch = SanitizePatch(int(patch_id), patch_params)

        # Coarse reason code (gateway knows the clear allowlist bits from PIR reconstruction).
        reason = "ALLOW"
        if allow_pre != 1:
            if int(rbits[0]) != 1 and is_send:
                reason = "RECIPIENT_NOT_ALLOWED"
            elif int(dbits[0]) != 1 and (is_fetch or is_webhook):
                reason = "DOMAIN_NOT_ALLOWED"
            else:
                reason = "POLICY_DENY"
        elif need_confirm == 1:
            reason = "REQUIRE_CONFIRM"

        preview = {
            "program_id": program_id,
            "action_id": action_id,
            "request_sha256": request_sha,
            "auth_context": hash_ctx,
            "allow_pre": bool(allow_pre == 1),
            "need_confirm": bool(need_confirm == 1),
            "patch": patch.to_dict(),
            "pir_evidence": {
                "allow_recipients": ev_rec,
                "allow_domains": ev_dom,
                "banned_tokens": ev_tok,
                "dfa": dfa_ev,
            },
            "commit_evidence": commit_ev,
        }

        tx_rec = self.tx.mint(
            intent_id=str(intent_id),
            action_id=action_id,
            request_sha256=request_sha,
            caller=caller,
            session=session,
            preview=preview,
            ttl_seconds=int(os.getenv("TX_TTL_S", "120")),
        )

        return {
            "allow_pre": bool(allow_pre == 1),
            "need_confirm": bool(need_confirm == 1),
            "patch": patch.to_dict(),
            "reason_code": reason,
            "details": "",
            "evidence": {
                "commit": commit_ev,
                "pir": {
                    "allow_recipients": ev_rec,
                    "allow_domains": ev_dom,
                    "banned_tokens": ev_tok,
                    "dfa": dfa_ev,
                },
            },
            "tx_id": tx_rec.tx_id,
            "action_id": action_id,
            "request_sha256": request_sha,
        }

    def commit_from_tx(self, *, tx_id: str, intent_id: str, constraints: Dict[str, Any], session: str, caller: str) -> Dict[str, Any]:
        rec = self.tx.get(str(tx_id))
        if not rec:
            return {"status": "DENY", "summary": "Invalid or expired tx_id.", "data": {}, "artifacts": [], "reason_code": "TX_INVALID"}
        if rec.session != session:
            return {"status": "DENY", "summary": "tx_id bound to a different session.", "data": {}, "artifacts": [], "reason_code": "TX_SESSION_MISMATCH"}
        if rec.caller != caller:
            return {"status": "DENY", "summary": "tx_id bound to a different caller.", "data": {}, "artifacts": [], "reason_code": "TX_CALLER_MISMATCH"}

        pv = rec.preview or {}
        auth_ctx = _hash_context_from_constraints(constraints)
        expected_ctx = pv.get("auth_context") if isinstance(pv.get("auth_context"), dict) else {}
        if expected_ctx:
            # Request-hash context must remain stable across preview and commit.
            if dict(expected_ctx) != dict(auth_ctx):
                return {
                    "status": "DENY",
                    "summary": "tx_id bound to a different auth context.",
                    "data": {"tx_id": rec.tx_id, "expected_auth_context": expected_ctx},
                    "artifacts": [],
                    "reason_code": "TX_AUTH_CONTEXT_MISMATCH",
                }
        allow_pre = bool(pv.get("allow_pre", False))
        need_confirm = bool(pv.get("need_confirm", False))
        patch_dict = pv.get("patch") or {}
        patch_id = int(patch_dict.get("patch_id", PATCH_NOOP))
        patch_params = patch_dict.get("params") if isinstance(patch_dict.get("params"), dict) else {}
        patch = SanitizePatch(patch_id, dict(patch_params))

        user_confirm = bool((constraints or {}).get("user_confirm", False))
        if not allow_pre:
            return {"status": "DENY", "summary": "Policy denied by preview.", "data": {"tx_id": rec.tx_id}, "artifacts": [], "reason_code": "POLICY_DENY"}
        if need_confirm and not user_confirm:
            # Return the sanitized preview so the caller can display it before confirm.
            return {
                "status": "DENY",
                "summary": "Commit requires explicit user confirmation.",
                "data": {"tx_id": rec.tx_id, "patch": patch.to_dict()},
                "artifacts": [],
                "reason_code": "REQUIRE_CONFIRM",
            }

        # Return the tx payload needed by executor. The executor will re-verify dual commit proofs and enforce sanitize.
        return {
            "status": "OK",
            "summary": "Commit authorized by preview tokens.",
            "data": {
                "tx_id": rec.tx_id,
                "action_id": rec.action_id,
                "request_sha256": rec.request_sha256,
                "patch": patch.to_dict(),
                "auth_context": dict(expected_ctx or auth_ctx),
                "commit_evidence": pv.get("commit_evidence") or {},
            },
            "artifacts": [],
            "reason_code": "ALLOW",
        }
