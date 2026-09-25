from __future__ import annotations

import ast
import hashlib
import hmac as _hmac_mod
import os
import secrets
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

import requests
import yaml

from common.canonical import request_sha256_v1
from common.sanitize import PATCH_CLAMP_LEN, PATCH_NOOP, PATCH_REDACT, SanitizePatch

from .capabilities import get_effective_capabilities
from .fss_pir import PirClient
from .guardrails import stable_idx
from .skill_ingress import extract_install_tokens
from .tx_store import TxStore
from .policy_unified import UnifiedPolicyEngine
from .http_session import session_for


_HTTP_POOL = ThreadPoolExecutor(max_workers=8)


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


def build_skill_ingress_v1_circuit_from_policy(cfg: dict[str, Any]) -> Circuit | None:
    programs = cfg.get("policy_programs") if isinstance(cfg, dict) else None
    if not isinstance(programs, dict):
        return None
    prog = programs.get("skill_ingress_v1")
    if not isinstance(prog, dict):
        return None
    outs_cfg = prog.get("outputs")
    if not isinstance(outs_cfg, dict):
        return None

    b = _CircuitBuilder()
    # Inputs are fixed to keep the MPC program constant-shape.
    for nm in ["cap_skill_install", "ioc_hit", "install_hit", "base64_obf"]:
        b.input(nm)

    def compile_expr(expr: str) -> int:
        s = str(expr or "").strip() or "0"
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

    allow_pre = compile_expr(str(outs_cfg.get("allow_pre") or "0"))
    need_confirm = compile_expr(str(outs_cfg.get("need_confirm") or "0"))
    patch0 = compile_expr(str(outs_cfg.get("patch0") or "0"))
    patch1 = compile_expr(str(outs_cfg.get("patch1") or "0"))

    outputs = {"allow_pre": allow_pre, "need_confirm": need_confirm, "patch0": patch0, "patch1": patch1}
    return Circuit(n_wires=b._w, gates=b.gates, inputs=b.inputs, outputs=outputs, and_gate_indices=b.and_gate_indices)


def build_skill_ingress_v1_circuit_default() -> Circuit:
    b = _CircuitBuilder()
    cap = b.input("cap_skill_install")
    ioc = b.input("ioc_hit")
    inst = b.input("install_hit")
    b64 = b.input("base64_obf")

    allow_pre = b.and_(cap, b.not_(ioc))
    need_confirm = b.xor(inst, b64)  # OR via XOR+AND
    need_confirm = b.xor(need_confirm, b.and_(inst, b64))
    patch0 = need_confirm
    patch1 = b.const(0)
    outputs = {"allow_pre": allow_pre, "need_confirm": need_confirm, "patch0": patch0, "patch1": patch1}
    return Circuit(n_wires=b._w, gates=b.gates, inputs=b.inputs, outputs=outputs, and_gate_indices=b.and_gate_indices)


def _share_bit(x: int) -> Tuple[int, int]:
    r = secrets.randbits(1) & 1
    return r, (r ^ (int(x) & 1)) & 1


class SkillIngressPolicyEngine:
    def __init__(self, *, pir: PirClient, tx_store: TxStore, domain_size: int, max_tokens: int):
        self.pir = pir
        self.tx = tx_store
        self.domain_size = int(domain_size)
        self.max_tokens = int(max_tokens)

        self.unified_policy = bool(int(os.getenv("UNIFIED_POLICY", "1")))

        self.signed_pir = True  # skill ingress always uses signed PIR in this demo.
        self.use_bundle = bool(int(os.getenv("USE_POLICY_BUNDLE", "1")))
        self.policy_bypass = bool(int(os.getenv("MIRAGE_POLICY_BYPASS", "0")))
        self.single_server_cleartext = bool(int(os.getenv("SINGLE_SERVER_POLICY", "0")))
        self.single_server_id = int(os.getenv("SINGLE_SERVER_ID", "0") or "0")
        self._bundle_cache: dict[str, Any] | None = None

        cfg = _load_policy_config()
        self._circuit = build_skill_ingress_v1_circuit_from_policy(cfg) or build_skill_ingress_v1_circuit_default()
        self._unified: UnifiedPolicyEngine | None = None
        if self.unified_policy:
            # Unified program hides skill-ingress vs egress category at the policy server.
            # Note: handles store is not needed for skill-only flows.
            self._unified = UnifiedPolicyEngine(pir=pir, handles=None, tx_store=tx_store, domain_size=domain_size, max_tokens=max_tokens)

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

    def _bundle_shift(self, *, logical: str, raw_idx: int, bundle_env: str) -> tuple[str, int, int | None]:
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

    def _mpc_init(self, *, action_id: str, program_id: str, request_sha256: str, input0: dict[int, int], input1: dict[int, int]) -> None:
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

    def _mpc_eval_and(self, *, action_id: str) -> None:
        u0 = str(self.pir.policy0_url).rstrip("/")
        u1 = str(self.pir.policy1_url).rstrip("/")
        for gi in self._circuit.and_gate_indices:
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
        skill_id: str,
        skill_digest: str,
        skill_md: str,
        domains: list[str],
        base64_obf: bool,
        session: str,
        caller: str,
        auth_context: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        if self._unified is not None:
            return self._unified.preview_skill_install(
                skill_id=skill_id,
                skill_digest=skill_digest,
                skill_md=skill_md,
                domains=domains,
                base64_obf=base64_obf,
                session=session,
                caller=caller,
                auth_context=auth_context,
            )
        auth_ctx = dict(auth_context or {})
        external_principal = str(auth_ctx.get("external_principal") or "")
        delegation_jti = str(auth_ctx.get("delegation_jti") or "")
        hash_ctx: dict[str, Any] = {}
        if external_principal:
            hash_ctx["external_principal"] = external_principal
        if delegation_jti:
            hash_ctx["delegation_jti"] = delegation_jti

        caps = get_effective_capabilities(caller, external_principal=(external_principal or None))
        cap_install = 1 if caps.egress_ok(kind="skill_install") else 0

        # Fixed-shape PIR surface.
        action_id = f"a_{secrets.token_urlsafe(12)}"
        request_sha = request_sha256_v1(
            intent_id="CommitSkillInstall",
            caller=str(caller),
            session=str(session),
            inputs={"skill_id": str(skill_id), "skill_digest": str(skill_digest)},
            context=hash_ctx,
        )

        if self.policy_bypass:
            patch = SanitizePatch(PATCH_NOOP, {})
            preview = {
                "program_id": "skill_ingress_v1",
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
                intent_id="CommitSkillInstall",
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
                "risk_categories": [],
                "risk_explanation": "Policy bypass mode enabled.",
            }

        max_domains = int(os.getenv("MAX_SKILL_DOMAINS", "8"))
        if max_domains < 1:
            max_domains = 1
        if max_domains > 64:
            max_domains = 64
        doms = [str(d).strip().lower() for d in (domains or []) if str(d).strip()]
        doms = doms[:max_domains]
        while len(doms) < max_domains:
            doms.append(os.getenv("DUMMY_SKILL_DOMAIN", "example.com"))

        # IOC membership queries (oblivious).
        raw = [stable_idx(d, self.domain_size) for d in doms]
        db_ioc, _idx0, dom_override = self._bundle_shift(logical="ioc_domains", raw_idx=0, bundle_env="POLICY_BUNDLE_SKILL")
        idxs: list[int] = []
        if db_ioc == "ioc_domains":
            idxs = raw
        else:
            # bundle-shift each index
            b = self._load_bundle() or {}
            base_ds = int(b.get("base_domain_size") or self.domain_size)
            bundles = b.get("bundles") or {"default": 0}
            if not isinstance(bundles, dict):
                bundles = {"default": 0}
            bundle_name = (os.getenv("POLICY_BUNDLE_SKILL", "default") or "default").strip()
            bid = int(bundles.get(bundle_name, 0))
            stride = int(b.get("bundle_stride") or 0)
            offs = b.get("logical_offsets") or {}
            loff = int((offs or {}).get("ioc_domains", 0))
            idxs = [(bid * stride) + loff + (int(x) % base_ds) for x in raw]

        bits_ioc, ev_ioc = self._query_bits_signed_or_single_server(
            db_name=db_ioc,
            idxs=idxs,
            action_id=action_id,
            domain_size=dom_override,
        )
        ioc_hit = 1 if any(int(x) == 1 for x in bits_ioc) else 0

        # Install semantics token DB (oblivious).
        #
        # IMPORTANT: do *not* query all 4-grams of SKILL.md here. That approach has very high false-positive
        # rates at small domain sizes (collisions), which makes benign skills spuriously require confirmation.
        # Instead, we extract a small set of canonical install-semantic tokens (curl|bash, base64 -d, etc.)
        # and query those (padded to fixed shape).
        toks = extract_install_tokens(text=skill_md or "", max_tokens=self.max_tokens)
        while len(toks) < self.max_tokens:
            toks.append(f"__pad_install_token_{len(toks)}__")
        tok_raw = [stable_idx(t, self.domain_size) for t in toks[: self.max_tokens]]
        db_tok, _idx1, dom_override2 = self._bundle_shift(logical="banned_install_tokens", raw_idx=0, bundle_env="POLICY_BUNDLE_SKILL")
        idxs2: list[int] = []
        if db_tok == "banned_install_tokens":
            idxs2 = tok_raw
        else:
            b = self._load_bundle() or {}
            base_ds = int(b.get("base_domain_size") or self.domain_size)
            bundles = b.get("bundles") or {"default": 0}
            if not isinstance(bundles, dict):
                bundles = {"default": 0}
            bundle_name = (os.getenv("POLICY_BUNDLE_SKILL", "default") or "default").strip()
            bid = int(bundles.get(bundle_name, 0))
            stride = int(b.get("bundle_stride") or 0)
            offs = b.get("logical_offsets") or {}
            loff = int((offs or {}).get("banned_install_tokens", 0))
            idxs2 = [(bid * stride) + loff + (int(x) % base_ds) for x in tok_raw]

        hits, ev_tok = self._query_bits_signed_or_single_server(
            db_name=db_tok,
            idxs=idxs2,
            action_id=action_id,
            domain_size=dom_override2,
        )
        install_hit = 1 if any(int(x) == 1 for x in hits) else 0

        # Secret-share MPC inputs.
        in0: dict[int, int] = {}
        in1: dict[int, int] = {}

        def set_in(name: str, share0: int, share1: int) -> None:
            wi = int(self._circuit.inputs[name])
            in0[wi] = int(share0) & 1
            in1[wi] = int(share1) & 1

        for nm, bit in [
            ("cap_skill_install", cap_install),
            ("ioc_hit", ioc_hit),
            ("install_hit", install_hit),
            ("base64_obf", 1 if base64_obf else 0),
        ]:
            s0, s1 = _share_bit(int(bit) & 1)
            set_in(nm, s0, s1)

        program_id = "skill_ingress_v1"
        self._mpc_init(action_id=action_id, program_id=program_id, request_sha256=request_sha, input0=in0, input1=in1)
        self._mpc_eval_and(action_id=action_id)
        commit_ev = self._mpc_finalize(action_id=action_id)

        # Reconstruct outputs at gateway (trusted).
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
            patch_params["max_chars"] = int(os.getenv("SKILL_MD_MAX_CHARS", "2000"))
        patch = SanitizePatch(int(patch_id), patch_params)

        reason = "ALLOW"
        if allow_pre != 1:
            reason = "IOC_BLOCKED" if ioc_hit == 1 else "POLICY_DENY"
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
            "skill_id": str(skill_id),
            "skill_digest": str(skill_digest),
            "pir_evidence": {"ioc_domains": ev_ioc, "banned_install_tokens": ev_tok},
            "commit_evidence": commit_ev,
        }

        tx_rec = self.tx.mint(
            intent_id="CommitSkillInstall",
            action_id=action_id,
            request_sha256=request_sha,
            caller=caller,
            session=session,
            preview=preview,
            ttl_seconds=int(os.getenv("TX_TTL_S", "120")),
        )

        result: dict[str, Any] = {
            "allow_pre": bool(allow_pre == 1),
            "need_confirm": bool(need_confirm == 1),
            "patch": patch.to_dict(),
            "reason_code": reason,
            "evidence": {"commit": commit_ev, "pir": {"ioc_domains": ev_ioc, "banned_install_tokens": ev_tok}},
            "tx_id": tx_rec.tx_id,
            "action_id": action_id,
            "request_sha256": request_sha,
        }
        if need_confirm == 1:
            raw = (os.getenv("SECURECLAW_CONFIRM_TOKEN_KEY_HEX", "").strip()
                   or os.getenv("CONFIRM_TOKEN_KEY_HEX", "").strip())
            if raw:
                key = bytes.fromhex(raw)
                ct = _hmac_mod.new(key, f"{action_id}|{request_sha}".encode(), hashlib.sha256).hexdigest()
                result["confirm_token"] = ct
        return result

    def commit_from_tx(self, *, tx_id: str, constraints: Dict[str, Any], session: str, caller: str) -> Dict[str, Any]:
        rec = self.tx.get(str(tx_id))
        if not rec:
            return {"status": "DENY", "summary": "Invalid or expired tx_id.", "data": {}, "artifacts": [], "reason_code": "TX_INVALID"}
        if rec.session != session:
            return {"status": "DENY", "summary": "tx_id bound to a different session.", "data": {}, "artifacts": [], "reason_code": "TX_SESSION_MISMATCH"}
        if rec.caller != caller:
            return {"status": "DENY", "summary": "tx_id bound to a different caller.", "data": {}, "artifacts": [], "reason_code": "TX_CALLER_MISMATCH"}

        pv = rec.preview or {}
        auth_ctx = (constraints or {}).get("_auth_ctx") if isinstance((constraints or {}).get("_auth_ctx"), dict) else {}
        expected_ctx = pv.get("auth_context") if isinstance(pv.get("auth_context"), dict) else {}
        if expected_ctx:
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
            return {"status": "DENY", "summary": "Commit requires explicit user confirmation.", "data": {"tx_id": rec.tx_id, "patch": patch.to_dict()}, "artifacts": [], "reason_code": "REQUIRE_CONFIRM"}

        return {
            "status": "OK",
            "summary": "Commit authorized by preview tokens.",
            "data": {
                "tx_id": rec.tx_id,
                "action_id": rec.action_id,
                "request_sha256": rec.request_sha256,
                "patch": patch.to_dict(),
                "commit_evidence": pv.get("commit_evidence") or {},
                "skill_id": str(pv.get("skill_id") or ""),
                "skill_digest": str(pv.get("skill_digest") or ""),
            },
            "artifacts": [],
            "reason_code": "ALLOW",
        }
