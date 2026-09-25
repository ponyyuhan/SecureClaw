from __future__ import annotations

import ast
import os
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import Future
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

import requests
import yaml

from common.install_tokens import normalize_install_token
from common.canonical import sha256_hex
from common.canonical import request_sha256_v1

import hashlib
import hmac as _hmac_mod
from common.uds_http import uds_http_request, uds_post_json
from common.sanitize import (
    PATCH_CLAMP_LEN,
    PATCH_NOOP,
    PATCH_REDACT,
    PATCH_REWRITE_DOMAIN_TO_PROXY,
    SanitizePatch,
)

from .capabilities import get_effective_capabilities
from .fss_pir import MixedPirClient, PirClient
from .guardrails import fourgram_indices, stable_idx
from .handles import HandleStore
from .skill_ingress import extract_install_tokens
from .tx_store import TxStore
from .http_session import session_for

_HTTP_POOL = ThreadPoolExecutor(max_workers=8)
_TRACE_LOCK = threading.Lock()


def _mint_confirm_token(action_id: str, request_sha: str) -> str:
    """Mint a confirm token bound to (action_id, request_sha).

    If SECURECLAW_CONFIRM_TOKEN_KEY_HEX is set, returns HMAC.
    Otherwise returns empty string (legacy bare-boolean mode).
    """
    raw = (os.getenv("SECURECLAW_CONFIRM_TOKEN_KEY_HEX", "").strip()
           or os.getenv("CONFIRM_TOKEN_KEY_HEX", "").strip())
    if not raw:
        return ""
    key = bytes.fromhex(raw)
    return _hmac_mod.new(key, f"{action_id}|{request_sha}".encode(), hashlib.sha256).hexdigest()


def _normalize_ctx_target(raw: Any) -> str:
    s = str(raw or "").strip().lower()
    return s


def _ctx_target_match(targets: set[str], *, recipient: str, domain: str) -> tuple[bool, bool]:
    rec = _normalize_ctx_target(recipient)
    dom = _normalize_ctx_target(domain)
    rec_ok = bool(rec and rec in targets)
    dom_ok = bool(dom and dom in targets)
    if not dom_ok and rec and "@" in rec:
        dom_ok = rec.rsplit("@", 1)[1] in targets
    return rec_ok, dom_ok


def _uds_or_http_post_json(
    *,
    uds_path: str | None,
    base_url: str,
    path: str,
    obj: dict[str, Any],
    timeout_s: int,
) -> dict[str, Any]:
    if uds_path:
        st, _hdrs, resp = uds_post_json(
            uds_path=str(uds_path),
            path=str(path),
            obj={str(k): v for k, v in (obj or {}).items()},
            timeout_s=float(timeout_s),
        )
        if int(st) != 200:
            raise RuntimeError(f"uds_http_status_{st}")
        return resp if isinstance(resp, dict) else {"_resp": resp}
    u = str(base_url).rstrip("/")
    r = session_for(u).post(f"{u}{path}", json=obj, timeout=int(timeout_s))
    r.raise_for_status()
    j = r.json()
    return j if isinstance(j, dict) else {"_resp": j}


def _trace_mpc(
    *,
    server_id: int,
    endpoint: str,
    action_id: str | None,
    program_id: str,
    request_sha256: str | None = None,
    n_wires: int | None = None,
    n_gates: int | None = None,
    and_round: int | None = None,
    n_items: int | None = None,
    multi: bool = False,
) -> None:
    """
    Optional "single policy server transcript" logging for leakage evaluation.

    This logs only metadata that a single policy server learns at the MPC API layer
    (endpoint name, action_id, program_id, request_sha256 hash, circuit size, batch sizes).
    """
    path = (os.getenv("MIRAGE_TRANSCRIPT_PATH") or os.getenv("MPC_TRANSCRIPT_PATH") or "").strip()
    if not path:
        return
    ev: dict[str, Any] = {
        "ts": int(time.time() * 1000),
        "server_id": int(server_id),
        "endpoint": str(endpoint),
        "program_id": str(program_id),
        "multi": bool(multi),
    }
    if action_id:
        ev["action_id"] = str(action_id)
    if request_sha256:
        ev["request_sha256"] = str(request_sha256)
    if n_wires is not None:
        ev["n_wires"] = int(n_wires)
    if n_gates is not None:
        ev["n_gates"] = int(n_gates)
    if and_round is not None:
        ev["and_round"] = int(and_round)
    if n_items is not None:
        ev["n_items"] = int(n_items)
    import json

    line = json.dumps(ev, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    with _TRACE_LOCK:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


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
    and_rounds: List[List[int]]


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


def _share_bit(x: int) -> Tuple[int, int]:
    r = secrets.randbits(1) & 1
    return r, (r ^ (int(x) & 1)) & 1


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


def _compile_expr(b: _CircuitBuilder, expr: str) -> int:
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


def _xor_reduce(b: _CircuitBuilder, ws: list[int]) -> int:
    if not ws:
        return b.const(0)
    acc = int(ws[0])
    for w in ws[1:]:
        acc = b.xor(acc, int(w))
    return acc


def _compute_and_rounds(c: Circuit) -> list[list[int]]:
    # AND-depth for each wire. XOR/NOT/CONST keep depth; AND increases by 1.
    wdepth: list[int] = [0 for _ in range(int(c.n_wires))]
    gate_and_depth: dict[int, int] = {}
    for gi, g in enumerate(c.gates):
        op = str(g.op).upper()
        if op == "CONST":
            wdepth[int(g.out)] = 0
            continue
        if op == "NOT":
            if g.a is None:
                raise ValueError("bad NOT gate")
            wdepth[int(g.out)] = int(wdepth[int(g.a)])
            continue
        if op == "XOR":
            if g.a is None or g.b is None:
                raise ValueError("bad XOR gate")
            wdepth[int(g.out)] = max(int(wdepth[int(g.a)]), int(wdepth[int(g.b)]))
            continue
        if op == "AND":
            if g.a is None or g.b is None:
                raise ValueError("bad AND gate")
            d = max(int(wdepth[int(g.a)]), int(wdepth[int(g.b)])) + 1
            wdepth[int(g.out)] = int(d)
            gate_and_depth[int(gi)] = int(d)
            continue
        raise ValueError(f"unknown gate op: {g.op}")

    if not gate_and_depth:
        return []
    maxd = max(int(x) for x in gate_and_depth.values())
    rounds: list[list[int]] = [[] for _ in range(maxd + 1)]
    for gi, d in gate_and_depth.items():
        rounds[int(d)].append(int(gi))
    out: list[list[int]] = []
    for d in range(1, maxd + 1):
        if rounds[d]:
            out.append(sorted(rounds[d]))
    return out


def _pick_safe_pad_strings(*, prefix: str, n: int, domain_size: int, forbidden: set[int]) -> list[str]:
    """
    Deterministically pick padding strings whose stable indices are not set bits in the target DB.

    This reduces false positives caused by padding-item hash collisions at small domain sizes.
    """
    out: list[str] = []
    seen: set[int] = set()
    j = 0
    # Hard bound to avoid any risk of non-termination.
    while len(out) < int(n) and j < 200000:
        cand = f"{prefix}{j}"
        idx = int(stable_idx(cand, int(domain_size)))
        if idx not in forbidden and idx not in seen:
            out.append(cand)
            seen.add(idx)
        j += 1
    if len(out) < int(n):
        raise RuntimeError("failed_to_pick_safe_padding")
    return out


def build_policy_unified_v1_circuit_from_policy(cfg: dict[str, Any]) -> Circuit | None:
    programs = cfg.get("policy_programs") if isinstance(cfg, dict) else None
    if not isinstance(programs, dict):
        return None
    egress = programs.get("egress_v1")
    ingress = programs.get("skill_ingress_v1")
    if not isinstance(egress, dict) or not isinstance(ingress, dict):
        return None
    intents = egress.get("intents")
    if not isinstance(intents, dict):
        return None
    ingress_outs = ingress.get("outputs")
    if not isinstance(ingress_outs, dict):
        return None

    b = _CircuitBuilder()

    # Fixed inputs for constant-shape program.
    for nm in [
        "intent_send",
        "intent_fetch",
        "intent_webhook",
        "intent_skill_install",
        "cap_send",
        "cap_fetch",
        "cap_webhook",
        "cap_skill_install",
        "recipient_ok",
        "domain_ok",
        "dlp_hit",
        "high_handle_present",
        "ioc_hit",
        "install_hit",
        "base64_obf",
    ]:
        b.input(nm)

    def intent_bit_for(name: str) -> str:
        if name == "SendMessage":
            return "intent_send"
        if name == "FetchResource":
            return "intent_fetch"
        if name == "PostWebhook":
            return "intent_webhook"
        raise ValueError(f"unsupported egress intent in policy_programs.egress_v1: {name}")

    # Compile egress per-intent outputs from DSL.
    allow_terms: list[int] = []
    conf_terms: list[int] = []
    patch0_terms: list[int] = []
    patch1_terms: list[int] = []
    for intent_name, icfg in intents.items():
        if not isinstance(icfg, dict):
            continue
        intent_name = str(intent_name)
        ib = int(b.inputs[intent_bit_for(intent_name)])
        allow_i = _compile_expr(b, str(icfg.get("allow_pre") or "0"))
        conf_i = _compile_expr(b, str(icfg.get("need_confirm") or "0"))
        patch0_i = _compile_expr(b, str(icfg.get("patch0") or "0"))
        patch1_i = _compile_expr(b, str(icfg.get("patch1") or "0"))
        allow_terms.append(b.and_(ib, allow_i))
        conf_terms.append(b.and_(ib, conf_i))
        patch0_terms.append(b.and_(ib, patch0_i))
        patch1_terms.append(b.and_(ib, patch1_i))

    # Skill ingress is treated as a fourth intent.
    ib_skill = int(b.inputs["intent_skill_install"])
    allow_skill = _compile_expr(b, str(ingress_outs.get("allow_pre") or "0"))
    conf_skill = _compile_expr(b, str(ingress_outs.get("need_confirm") or "0"))
    patch0_skill = _compile_expr(b, str(ingress_outs.get("patch0") or "0"))
    patch1_skill = _compile_expr(b, str(ingress_outs.get("patch1") or "0"))
    allow_terms.append(b.and_(ib_skill, allow_skill))
    conf_terms.append(b.and_(ib_skill, conf_skill))
    patch0_terms.append(b.and_(ib_skill, patch0_skill))
    patch1_terms.append(b.and_(ib_skill, patch1_skill))

    allow_pre = _xor_reduce(b, allow_terms)
    need_confirm = _xor_reduce(b, conf_terms)
    patch0 = _xor_reduce(b, patch0_terms)
    patch1 = _xor_reduce(b, patch1_terms)

    outputs = {"allow_pre": allow_pre, "need_confirm": need_confirm, "patch0": patch0, "patch1": patch1}
    tmp = Circuit(
        n_wires=b._w,
        gates=b.gates,
        inputs=b.inputs,
        outputs=outputs,
        and_gate_indices=b.and_gate_indices,
        and_rounds=[],
    )
    rounds = _compute_and_rounds(tmp)
    return Circuit(
        n_wires=tmp.n_wires,
        gates=tmp.gates,
        inputs=tmp.inputs,
        outputs=tmp.outputs,
        and_gate_indices=tmp.and_gate_indices,
        and_rounds=rounds,
    )


def build_policy_unified_v1_circuit_default() -> Circuit:
    b = _CircuitBuilder()
    intent_send = b.input("intent_send")
    intent_fetch = b.input("intent_fetch")
    intent_webhook = b.input("intent_webhook")
    intent_skill = b.input("intent_skill_install")

    cap_send = b.input("cap_send")
    cap_fetch = b.input("cap_fetch")
    cap_webhook = b.input("cap_webhook")
    cap_skill = b.input("cap_skill_install")

    recipient_ok = b.input("recipient_ok")
    domain_ok = b.input("domain_ok")
    dlp_hit = b.input("dlp_hit")
    high_handle = b.input("high_handle_present")
    ioc_hit = b.input("ioc_hit")
    install_hit = b.input("install_hit")
    base64_obf = b.input("base64_obf")

    not_high = b.not_(high_handle)
    allow_send = b.and_(cap_send, recipient_ok)
    allow_send = b.and_(allow_send, not_high)
    allow_fetch = b.and_(cap_fetch, domain_ok)
    allow_webhook = b.and_(cap_webhook, domain_ok)
    allow_webhook = b.and_(allow_webhook, not_high)

    allow_skill = b.and_(cap_skill, b.not_(ioc_hit))

    term_send = b.and_(intent_send, allow_send)
    term_fetch = b.and_(intent_fetch, allow_fetch)
    term_webhook = b.and_(intent_webhook, allow_webhook)
    term_skill = b.and_(intent_skill, allow_skill)
    allow_pre = _xor_reduce(b, [term_send, term_fetch, term_webhook, term_skill])

    conf_send = b.and_(intent_send, dlp_hit)
    conf_webhook = b.and_(intent_webhook, dlp_hit)
    # skill_confirm = intent_skill & (install_hit | base64_obf)
    skill_or = b.xor(install_hit, base64_obf)
    skill_or = b.xor(skill_or, b.and_(install_hit, base64_obf))
    conf_skill = b.and_(intent_skill, skill_or)
    need_confirm = _xor_reduce(b, [conf_send, conf_webhook, conf_skill])

    patch0 = need_confirm
    patch1 = b.const(0)

    outputs = {"allow_pre": allow_pre, "need_confirm": need_confirm, "patch0": patch0, "patch1": patch1}
    tmp = Circuit(
        n_wires=b._w,
        gates=b.gates,
        inputs=b.inputs,
        outputs=outputs,
        and_gate_indices=b.and_gate_indices,
        and_rounds=[],
    )
    rounds = _compute_and_rounds(tmp)
    return Circuit(
        n_wires=tmp.n_wires,
        gates=tmp.gates,
        inputs=tmp.inputs,
        outputs=tmp.outputs,
        and_gate_indices=tmp.and_gate_indices,
        and_rounds=rounds,
    )


@dataclass(frozen=True, slots=True)
class BundleConfig:
    enabled: bool
    db: str
    base_domain_size: int
    bundle_domain_size: int
    bundle_stride: int
    bundle_id: int
    logical_offsets: dict[str, int]


def _load_bundle_cfg(pir: PirClient, *, domain_size: int) -> BundleConfig | None:
    if not bool(int(os.getenv("USE_POLICY_BUNDLE", "1"))):
        return None
    try:
        uds0 = (str(getattr(pir, "policy0_uds_path", "") or "").strip() or None)
        if uds0:
            st, _hdrs, body = uds_http_request(uds_path=uds0, method="GET", path="/meta", timeout_s=2.0)
            if int(st) != 200:
                return None
            import json
            meta = json.loads(body.decode("utf-8", errors="replace") or "{}")
        else:
            u0 = str(pir.policy0_url).rstrip("/")
            meta = session_for(u0).get(f"{u0}/meta", timeout=2.0).json()
    except Exception:
        return None
    b = (meta.get("bundle") or {}) if isinstance(meta, dict) else {}
    if not isinstance(b, dict) or not b.get("enabled"):
        return None
    base_ds = int(b.get("base_domain_size") or domain_size)
    bundle_ds = int(b.get("bundle_domain_size") or 0)
    stride = int(b.get("bundle_stride") or 0)
    bundles = b.get("bundles") or {"default": 0}
    if not isinstance(bundles, dict):
        bundles = {"default": 0}
    bundle_name = (os.getenv("POLICY_BUNDLE_NAME", "default") or "default").strip()
    bid = int(bundles.get(bundle_name, 0))
    offs = b.get("logical_offsets") or {}
    if not isinstance(offs, dict):
        offs = {}
    logical_offsets = {str(k): int(v) for k, v in offs.items()}
    return BundleConfig(
        enabled=True,
        db=str(b.get("db") or "policy_bundle"),
        base_domain_size=base_ds,
        bundle_domain_size=bundle_ds,
        bundle_stride=stride,
        bundle_id=bid,
        logical_offsets=logical_offsets,
    )


def _bundle_shift(b: BundleConfig, *, logical: str, raw_idx: int) -> int:
    loff = int(b.logical_offsets.get(str(logical), 0))
    base = int(b.bundle_id) * int(b.bundle_stride)
    return int(base + loff + (int(raw_idx) % int(b.base_domain_size)))


def _bool_or(xs: list[int]) -> int:
    return 1 if any(int(x) & 1 for x in (xs or [])) else 0


@dataclass(frozen=True, slots=True)
class MpcMixConfig:
    """
    Gateway-side MPC cover traffic / microbatching configuration.

    This mixer is specialized for the unified constant-shape policy program:
    it evaluates a fixed circuit for a fixed number of sessions per tick, padding
    with dummy sessions when needed.
    """

    enabled: bool
    interval_ms: int
    pad_to: int
    cover_traffic: bool = False
    timeout_s: int = 15
    use_multi_endpoints: bool = True
    lanes: int = 1
    max_inflight: int = 1
    schedule_mode: str = "fixed"  # fixed | eager


class _MpcReq:
    __slots__ = ("action_id", "request_sha256", "input0", "input1", "future", "is_dummy")

    def __init__(self, *, action_id: str, request_sha256: str, input0: dict[int, int], input1: dict[int, int], future: Future, is_dummy: bool) -> None:
        self.action_id = str(action_id)
        self.request_sha256 = str(request_sha256)
        self.input0 = dict(input0 or {})
        self.input1 = dict(input1 or {})
        self.future = future
        self.is_dummy = bool(is_dummy)


class _MpcBatchMixer:
    def __init__(
        self,
        *,
        policy0_url: str,
        policy1_url: str,
        cfg: MpcMixConfig,
        circuit: Circuit,
        program_id: str,
        policy0_uds_path: str | None = None,
        policy1_uds_path: str | None = None,
    ) -> None:
        self.policy0_url = str(policy0_url)
        self.policy1_url = str(policy1_url)
        self.policy0_uds_path = (str(policy0_uds_path).strip() if policy0_uds_path else "") or None
        self.policy1_uds_path = (str(policy1_uds_path).strip() if policy1_uds_path else "") or None
        self.cfg = cfg
        self.circuit = circuit
        self.program_id = str(program_id)

        self._lock = threading.Lock()
        self._pending: list[_MpcReq] = []
        self._inflight = 0
        self._stop = threading.Event()
        self._wakeup = threading.Event()
        lanes = int(getattr(cfg, "lanes", 1) or 1)
        if lanes < 1:
            lanes = 1
        if lanes > 16:
            lanes = 16
        self._lanes = lanes
        # Run MPC batches in a separate pool so the scheduler threads never block
        # and we avoid deadlocking on the shared HTTP pool.
        self._work_pool = ThreadPoolExecutor(max_workers=max(1, min(8, lanes * 2)))
        self._threads: list[threading.Thread] = []
        for i in range(lanes):
            t = threading.Thread(target=self._run_lane, args=(i,), name=f"mpc-mixer-{i}", daemon=True)
            t.start()
            self._threads.append(t)

    def close(self) -> None:
        self._stop.set()
        self._wakeup.set()
        for t in list(self._threads):
            try:
                t.join(timeout=1.0)
            except Exception:
                pass
        try:
            self._work_pool.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

    def submit(self, *, action_id: str, request_sha256: str, input0: dict[int, int], input1: dict[int, int]) -> Future:
        fut: Future = Future()
        with self._lock:
            self._pending.append(_MpcReq(action_id=action_id, request_sha256=request_sha256, input0=input0, input1=input1, future=fut, is_dummy=False))
        # Wake lanes and, in eager-ish modes, try dispatch immediately to avoid
        # adding the full tick interval of queueing latency under low load.
        self._wakeup.set()
        mode = str(getattr(self.cfg, "schedule_mode", "fixed") or "fixed").strip().lower()
        if mode in ("eager", "on_demand", "ondemand"):
            try:
                self._dispatch_tick()
            except Exception:
                pass
        return fut

    def _mk_dummy_req(self) -> _MpcReq:
        # Keep the same action_id *shape* as real requests (e.g., "a_<urlsafe>") so
        # the policy servers cannot trivially distinguish cover vs real by prefix.
        aid = f"a_{secrets.token_urlsafe(12)}"
        # request_sha256 is the request-binding digest field in protocol v1.
        # For cover traffic, any random-looking digest-shaped value is fine.
        req_sha = os.urandom(32).hex()

        # Provide shares for all fixed input wires to keep sessions evaluatable.
        in0: dict[int, int] = {}
        in1: dict[int, int] = {}
        for _nm, wi in (self.circuit.inputs or {}).items():
            x0 = secrets.randbits(1) & 1
            x1 = secrets.randbits(1) & 1
            in0[int(wi)] = int(x0) & 1
            in1[int(wi)] = int(x1) & 1
        fut: Future = Future()
        fut.set_result(None)
        return _MpcReq(action_id=aid, request_sha256=req_sha, input0=in0, input1=in1, future=fut, is_dummy=True)

    def _mpc_init_many(self, batch: list[_MpcReq]) -> None:
        gates = [{"op": g.op, "out": int(g.out), "a": g.a, "b": g.b, "value": g.value} for g in self.circuit.gates]
        ttl = int(os.getenv("MPC_SESSION_TTL_S", "30"))
        if ttl < 5:
            ttl = 5
        if ttl > 300:
            ttl = 300

        def one(url: str, req: _MpcReq, shares: dict[int, int]) -> dict[str, Any]:
            payload = {
                "action_id": req.action_id,
                "program_id": str(self.program_id),
                "request_sha256": str(req.request_sha256),
                "n_wires": int(self.circuit.n_wires),
                "gates": gates,
                "input_shares": {str(k): int(v) & 1 for k, v in (shares or {}).items()},
                "outputs": {k: int(v) for k, v in self.circuit.outputs.items()},
                "ttl_seconds": ttl,
            }
            _trace_mpc(server_id=(0 if url == self.policy0_url else 1), endpoint="/mpc/init", action_id=req.action_id, program_id=str(self.program_id), request_sha256=req.request_sha256, n_wires=int(self.circuit.n_wires), n_gates=len(gates), multi=False)
            uds = self.policy0_uds_path if url == self.policy0_url else self.policy1_uds_path
            u = str(url).rstrip("/")
            j = _uds_or_http_post_json(uds_path=uds, base_url=u, path="/mpc/init", obj=payload, timeout_s=int(self.cfg.timeout_s))
            if not j.get("ok"):
                raise RuntimeError("mpc_init_failed")
            return j

        fs: list[Future] = []
        for req in batch:
            fs.append(_HTTP_POOL.submit(one, self.policy0_url, req, req.input0))
            fs.append(_HTTP_POOL.submit(one, self.policy1_url, req, req.input1))
        # raise on any failure
        for f in fs:
            _ = f.result()

    def _mpc_and_round_multi(self, batch: list[_MpcReq], *, round_index: int, gate_indices: list[int]) -> None:
        # Prepare triple shares for each session.
        reqs0: list[dict[str, Any]] = []
        reqs1: list[dict[str, Any]] = []
        for req in batch:
            triples0: list[dict[str, Any]] = []
            triples1: list[dict[str, Any]] = []
            for gi in gate_indices:
                a = secrets.randbits(1) & 1
                b = secrets.randbits(1) & 1
                c = (a & b) & 1
                a0, a1 = _share_bit(a)
                b0, b1 = _share_bit(b)
                c0, c1 = _share_bit(c)
                triples0.append({"gate_index": int(gi), "a_share": int(a0), "b_share": int(b0), "c_share": int(c0)})
                triples1.append({"gate_index": int(gi), "a_share": int(a1), "b_share": int(b1), "c_share": int(c1)})
            reqs0.append({"action_id": str(req.action_id), "triples": triples0})
            reqs1.append({"action_id": str(req.action_id), "triples": triples1})

        _trace_mpc(server_id=0, endpoint="/mpc/and_mask_multi", action_id=None, program_id=str(self.program_id), and_round=int(round_index), n_items=len(batch) * len(gate_indices), multi=True)
        _trace_mpc(server_id=1, endpoint="/mpc/and_mask_multi", action_id=None, program_id=str(self.program_id), and_round=int(round_index), n_items=len(batch) * len(gate_indices), multi=True)
        u0 = str(self.policy0_url).rstrip("/")
        u1 = str(self.policy1_url).rstrip("/")
        f0 = _HTTP_POOL.submit(
            _uds_or_http_post_json,
            uds_path=self.policy0_uds_path,
            base_url=u0,
            path="/mpc/and_mask_multi",
            obj={"requests": reqs0},
            timeout_s=int(self.cfg.timeout_s),
        )
        f1 = _HTTP_POOL.submit(
            _uds_or_http_post_json,
            uds_path=self.policy1_uds_path,
            base_url=u1,
            path="/mpc/and_mask_multi",
            obj={"requests": reqs1},
            timeout_s=int(self.cfg.timeout_s),
        )
        j0 = f0.result()
        j1 = f1.result()

        # action_id -> shares
        m0: dict[str, tuple[list[int], list[int]]] = {}
        m1: dict[str, tuple[list[int], list[int]]] = {}
        for it in (j0.get("responses") or []):
            if not isinstance(it, dict):
                continue
            if not it.get("ok"):
                continue
            aid = str(it.get("action_id") or "")
            d = [int(x) & 1 for x in (it.get("d_shares") or [])]
            e = [int(x) & 1 for x in (it.get("e_shares") or [])]
            m0[aid] = (d, e)
        for it in (j1.get("responses") or []):
            if not isinstance(it, dict):
                continue
            if not it.get("ok"):
                continue
            aid = str(it.get("action_id") or "")
            d = [int(x) & 1 for x in (it.get("d_shares") or [])]
            e = [int(x) & 1 for x in (it.get("e_shares") or [])]
            m1[aid] = (d, e)

        # Build finish opens per session.
        fin_reqs: list[dict[str, Any]] = []
        for req in batch:
            a0 = m0.get(str(req.action_id))
            a1 = m1.get(str(req.action_id))
            if not a0 or not a1:
                raise RuntimeError("mpc_multi_missing_reply")
            d0s, e0s = a0
            d1s, e1s = a1
            if not (len(d0s) == len(e0s) == len(d1s) == len(e1s) == len(gate_indices)):
                raise RuntimeError("mpc_multi_bad_batch_size")
            opens: list[dict[str, Any]] = []
            for k, gi in enumerate(gate_indices):
                d = (int(d0s[k]) ^ int(d1s[k])) & 1
                e = (int(e0s[k]) ^ int(e1s[k])) & 1
                opens.append({"gate_index": int(gi), "d": int(d), "e": int(e)})
            fin_reqs.append({"action_id": str(req.action_id), "opens": opens})

        _trace_mpc(server_id=0, endpoint="/mpc/and_finish_multi", action_id=None, program_id=str(self.program_id), and_round=int(round_index), n_items=len(batch) * len(gate_indices), multi=True)
        _trace_mpc(server_id=1, endpoint="/mpc/and_finish_multi", action_id=None, program_id=str(self.program_id), and_round=int(round_index), n_items=len(batch) * len(gate_indices), multi=True)
        f0 = _HTTP_POOL.submit(
            _uds_or_http_post_json,
            uds_path=self.policy0_uds_path,
            base_url=u0,
            path="/mpc/and_finish_multi",
            obj={"requests": fin_reqs},
            timeout_s=int(self.cfg.timeout_s),
        )
        f1 = _HTTP_POOL.submit(
            _uds_or_http_post_json,
            uds_path=self.policy1_uds_path,
            base_url=u1,
            path="/mpc/and_finish_multi",
            obj={"requests": fin_reqs},
            timeout_s=int(self.cfg.timeout_s),
        )
        _ = f0.result()
        _ = f1.result()
        # We don't need z_shares for correctness at gateway (servers update wires internally).

    def _mpc_and_round_single(self, batch: list[_MpcReq], *, round_index: int, gate_indices: list[int]) -> None:
        # Fallback: per-session batch endpoints.
        for req in batch:
            triples0: list[dict[str, Any]] = []
            triples1: list[dict[str, Any]] = []
            for gi in gate_indices:
                a = secrets.randbits(1) & 1
                b = secrets.randbits(1) & 1
                c = (a & b) & 1
                a0, a1 = _share_bit(a)
                b0, b1 = _share_bit(b)
                c0, c1 = _share_bit(c)
                triples0.append({"gate_index": int(gi), "a_share": int(a0), "b_share": int(b0), "c_share": int(c0)})
                triples1.append({"gate_index": int(gi), "a_share": int(a1), "b_share": int(b1), "c_share": int(c1)})

            _trace_mpc(server_id=0, endpoint="/mpc/and_mask_batch", action_id=req.action_id, program_id=str(self.program_id), and_round=int(round_index), n_items=len(gate_indices), multi=False)
            _trace_mpc(server_id=1, endpoint="/mpc/and_mask_batch", action_id=req.action_id, program_id=str(self.program_id), and_round=int(round_index), n_items=len(gate_indices), multi=False)
            u0 = str(self.policy0_url).rstrip("/")
            u1 = str(self.policy1_url).rstrip("/")
            f0 = _HTTP_POOL.submit(
                _uds_or_http_post_json,
                uds_path=self.policy0_uds_path,
                base_url=u0,
                path="/mpc/and_mask_batch",
                obj={"action_id": req.action_id, "triples": triples0},
                timeout_s=int(self.cfg.timeout_s),
            )
            f1 = _HTTP_POOL.submit(
                _uds_or_http_post_json,
                uds_path=self.policy1_uds_path,
                base_url=u1,
                path="/mpc/and_mask_batch",
                obj={"action_id": req.action_id, "triples": triples1},
                timeout_s=int(self.cfg.timeout_s),
            )
            j0 = f0.result()
            j1 = f1.result()
            d0s = j0.get("d_shares") or []
            e0s = j0.get("e_shares") or []
            d1s = j1.get("d_shares") or []
            e1s = j1.get("e_shares") or []
            if not (len(d0s) == len(e0s) == len(d1s) == len(e1s) == len(gate_indices)):
                raise RuntimeError("mpc_bad_batch_size")
            opens: list[dict[str, Any]] = []
            for k, gi in enumerate(gate_indices):
                d = (int(d0s[k]) ^ int(d1s[k])) & 1
                e = (int(e0s[k]) ^ int(e1s[k])) & 1
                opens.append({"gate_index": int(gi), "d": int(d), "e": int(e)})

            _trace_mpc(server_id=0, endpoint="/mpc/and_finish_batch", action_id=req.action_id, program_id=str(self.program_id), and_round=int(round_index), n_items=len(gate_indices), multi=False)
            _trace_mpc(server_id=1, endpoint="/mpc/and_finish_batch", action_id=req.action_id, program_id=str(self.program_id), and_round=int(round_index), n_items=len(gate_indices), multi=False)
            f0 = _HTTP_POOL.submit(
                _uds_or_http_post_json,
                uds_path=self.policy0_uds_path,
                base_url=u0,
                path="/mpc/and_finish_batch",
                obj={"action_id": req.action_id, "opens": opens},
                timeout_s=int(self.cfg.timeout_s),
            )
            f1 = _HTTP_POOL.submit(
                _uds_or_http_post_json,
                uds_path=self.policy1_uds_path,
                base_url=u1,
                path="/mpc/and_finish_batch",
                obj={"action_id": req.action_id, "opens": opens},
                timeout_s=int(self.cfg.timeout_s),
            )
            _ = f0.result()
            _ = f1.result()

    def _mpc_finalize_many(self, batch: list[_MpcReq]) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}

        def one(url: str, req: _MpcReq) -> dict[str, Any]:
            _trace_mpc(server_id=(0 if url == self.policy0_url else 1), endpoint="/mpc/finalize", action_id=req.action_id, program_id=str(self.program_id), request_sha256=req.request_sha256, multi=False)
            uds = self.policy0_uds_path if url == self.policy0_url else self.policy1_uds_path
            u = str(url).rstrip("/")
            j = _uds_or_http_post_json(uds_path=uds, base_url=u, path="/mpc/finalize", obj={"action_id": req.action_id}, timeout_s=int(self.cfg.timeout_s))
            if not j.get("ok"):
                raise RuntimeError("mpc_finalize_failed")
            return j

        fs: dict[tuple[str, int], Future] = {}
        for req in batch:
            fs[(req.action_id, 0)] = _HTTP_POOL.submit(one, self.policy0_url, req)
            fs[(req.action_id, 1)] = _HTTP_POOL.submit(one, self.policy1_url, req)
        # collect
        for (aid, sid), f in fs.items():
            j = f.result()
            out.setdefault(aid, {})
            out[aid][f"policy{sid}"] = j.get("proof")
        return out

    def _dispatch_tick(self) -> None:
        cfg = self.cfg
        batch: list[_MpcReq] = []
        with self._lock:
            if self._inflight >= int(getattr(cfg, "max_inflight", 1) or 1):
                return
            if self._pending:
                take = min(int(cfg.pad_to), len(self._pending))
                batch = self._pending[:take]
                self._pending = self._pending[take:]

        # If there are no real sessions, still emit cover traffic if enabled.
        if not batch and not bool(cfg.cover_traffic):
            return

        # Pad with dummy sessions up to pad_to.
        pad_to = int(cfg.pad_to)
        while len(batch) < pad_to:
            batch.append(self._mk_dummy_req())

        with self._lock:
            self._inflight += 1
        self._work_pool.submit(self._do_batch, batch)

    def _do_batch(self, batch: list[_MpcReq]) -> None:
        cfg = self.cfg
        try:
            # Execute full MPC pipeline for this constant-shape batch.
            self._mpc_init_many(batch)
            for ridx, gates in enumerate(self.circuit.and_rounds):
                if not gates:
                    continue
                if bool(cfg.use_multi_endpoints):
                    self._mpc_and_round_multi(batch, round_index=ridx, gate_indices=gates)
                else:
                    self._mpc_and_round_single(batch, round_index=ridx, gate_indices=gates)
            proofs_by_action = self._mpc_finalize_many(batch)
        except Exception as e:
            for req in batch:
                if req.is_dummy:
                    continue
                try:
                    req.future.set_exception(e)
                except Exception:
                    pass
            return
        finally:
            with self._lock:
                self._inflight = max(0, int(self._inflight) - 1)

        for req in batch:
            if req.is_dummy:
                continue
            try:
                ce = proofs_by_action.get(req.action_id) or {}
                if not ce.get("policy0") or not ce.get("policy1"):
                    raise RuntimeError("mpc_missing_commit_proofs")
                req.future.set_result({"policy0": ce.get("policy0"), "policy1": ce.get("policy1")})
            except Exception as e:
                try:
                    req.future.set_exception(e)
                except Exception:
                    pass

    def _run_lane(self, lane: int) -> None:
        interval_s = max(0.001, float(self.cfg.interval_ms) / 1000.0)
        if self._lanes > 1:
            self._stop.wait(timeout=(interval_s * float(int(lane) % int(self._lanes)) / float(self._lanes)))
        while not self._stop.is_set():
            t0 = time.perf_counter()
            self._dispatch_tick()
            dt = time.perf_counter() - t0
            mode = str(getattr(self.cfg, "schedule_mode", "fixed") or "fixed").strip().lower()
            if mode == "eager":
                with self._lock:
                    pending = len(self._pending)
                    inflight = int(self._inflight)
                if pending >= int(self.cfg.pad_to) and inflight < int(getattr(self.cfg, "max_inflight", 1) or 1):
                    sleep_s = 0.0
                else:
                    sleep_s = interval_s - dt
            else:
                sleep_s = interval_s - dt
            if sleep_s > 0:
                self._wakeup.wait(timeout=sleep_s)
                self._wakeup.clear()


class MixedMpcClient:
    """
    Minimal wrapper that exposes a `run_commit` API for the unified policy engine.

    When enabled, MPC sessions are executed in constant-shape ticks.
    """

    def __init__(
        self,
        *,
        policy0_url: str,
        policy1_url: str,
        cfg: MpcMixConfig,
        circuit: Circuit,
        program_id: str,
        policy0_uds_path: str | None = None,
        policy1_uds_path: str | None = None,
    ) -> None:
        self._cfg = cfg
        self._mixer: _MpcBatchMixer | None = None
        if cfg.enabled:
            self._mixer = _MpcBatchMixer(
                policy0_url=policy0_url,
                policy1_url=policy1_url,
                cfg=cfg,
                circuit=circuit,
                program_id=program_id,
                policy0_uds_path=policy0_uds_path,
                policy1_uds_path=policy1_uds_path,
            )

    def close(self) -> None:
        if self._mixer:
            self._mixer.close()

    def run_commit(self, *, action_id: str, request_sha256: str, input0: dict[int, int], input1: dict[int, int], timeout_s: int) -> dict[str, Any]:
        if not self._mixer:
            raise RuntimeError("mpc_mixer_disabled")
        fut = self._mixer.submit(action_id=action_id, request_sha256=request_sha256, input0=input0, input1=input1)
        out = fut.result(timeout=max(1.0, float(timeout_s)))
        if not isinstance(out, dict):
            raise RuntimeError("mpc_mixer_bad_result")
        return dict(out)


class UnifiedPolicyEngine:
    """
    Unified policy program with constant-shape PIR surface and constant program_id.

    This provides intent shadowing across:
    - SendMessage / FetchResource / PostWebhook
    - CommitSkillInstall
    """

    def __init__(self, *, pir: PirClient | MixedPirClient, handles: HandleStore | None, tx_store: TxStore, domain_size: int, max_tokens: int):
        self.pir = pir
        self.handles = handles
        self.tx = tx_store
        self.domain_size = int(domain_size)
        self.max_tokens = int(max_tokens)
        self.max_skill_domains = int(os.getenv("MAX_SKILL_DOMAINS", "8"))
        if self.max_skill_domains < 1:
            self.max_skill_domains = 1
        if self.max_skill_domains > 64:
            self.max_skill_domains = 64

        # Knobs
        self.signed_pir = bool(int(os.getenv("SIGNED_PIR", "1")))
        self.policy_bypass = bool(int(os.getenv("MIRAGE_POLICY_BYPASS", "0")))
        self.single_server_cleartext = bool(int(os.getenv("SINGLE_SERVER_POLICY", "0")))
        self.single_server_id = int(os.getenv("SINGLE_SERVER_ID", "0") or "0")

        self.program_id = (os.getenv("MIRAGE_POLICY_PROGRAM_ID", "policy_unified_v1") or "policy_unified_v1").strip()

        cfg = _load_policy_config()
        self._circuit = build_policy_unified_v1_circuit_from_policy(cfg) or build_policy_unified_v1_circuit_default()
        # Padding safety configuration (to reduce false positives from padding hash collisions).
        self._cfg_ioc_domains = [str(d).strip().lower() for d in (cfg.get("ioc_domains") or []) if str(d).strip()]
        raw_inst = list(cfg.get("install_patterns") or cfg.get("ingress_install_patterns") or [])
        inst_norm: list[str] = []
        for x in raw_inst:
            t = normalize_install_token(str(x))
            if t:
                inst_norm.append(t)
        self._cfg_install_tokens = sorted(set(inst_norm))
        self._pad_base_domain_size: int | None = None
        self._pad_skill_domains: list[str] | None = None
        self._pad_install_tokens: list[str] | None = None
        self._bundle: BundleConfig | None = None
        self._mpc_mixed: MixedMpcClient | None = None

        # Optional MPC cover traffic + microbatching (to reduce action-count/timing leakage at MPC layer).
        if bool(int(os.getenv("MPC_MIX_ENABLED", "0"))):
            pad_to = int(os.getenv("MPC_MIX_PAD_TO", "1"))
            if pad_to < 1:
                pad_to = 1
            if pad_to > 64:
                pad_to = 64
            mcfg = MpcMixConfig(
                enabled=True,
                interval_ms=int(os.getenv("MPC_MIX_INTERVAL_MS", "50")),
                # Default to no padding for paper pipeline; raise for production hiding.
                pad_to=int(pad_to),
                cover_traffic=bool(int(os.getenv("MPC_COVER_TRAFFIC", "0"))),
                timeout_s=int(os.getenv("MPC_MIX_TIMEOUT_S", "15")),
                use_multi_endpoints=bool(int(os.getenv("MPC_MIX_MULTI_ENDPOINTS", "1"))),
                lanes=int(os.getenv("MPC_MIX_LANES", "1")),
                max_inflight=int(os.getenv("MPC_MIX_MAX_INFLIGHT", "1")),
                schedule_mode=str(os.getenv("MPC_MIX_SCHEDULE", "fixed")),
            )
            self._mpc_mixed = MixedMpcClient(
                policy0_url=str(getattr(self.pir, "policy0_url")),
                policy1_url=str(getattr(self.pir, "policy1_url")),
                cfg=mcfg,
                circuit=self._circuit,
                program_id=str(self.program_id),
                policy0_uds_path=(os.getenv("POLICY0_UDS_PATH") or "").strip() or None,
                policy1_uds_path=(os.getenv("POLICY1_UDS_PATH") or "").strip() or None,
            )

    def _query_bits_signed_or_single_server(
        self,
        *,
        db_name: str,
        idxs: list[int],
        action_id: str,
        domain_size: int | None = None,
    ) -> tuple[list[int], dict[str, Any]]:
        if self.single_server_cleartext and isinstance(self.pir, PirClient):
            # If the gateway wrapped the client with mixing, it may not expose the baseline API.
            # In that case, baselines are disabled (paper eval uses separate configs).
            return self.pir.query_bits_single_server_cleartext_signed(
                db_name,
                idxs,
                action_id=action_id,
                server_id=self.single_server_id,
                domain_size=domain_size,
            )
        if self.single_server_cleartext and hasattr(self.pir, "query_bits_single_server_cleartext_signed"):
            return getattr(self.pir, "query_bits_single_server_cleartext_signed")(
                db_name,
                idxs,
                action_id=action_id,
                server_id=self.single_server_id,
                domain_size=domain_size,
            )
        return getattr(self.pir, "query_bits_signed")(db_name, idxs, action_id=action_id, domain_size=domain_size)

    def _load_bundle(self) -> BundleConfig:
        if self._bundle is not None:
            return self._bundle
        b = _load_bundle_cfg(self.pir if isinstance(self.pir, PirClient) else self.pir._base, domain_size=self.domain_size)  # type: ignore[attr-defined]
        if not b:
            raise RuntimeError("policy_bundle_required_for_unified_mode")
        self._bundle = b
        return b

    def _pir_unified_plan(
        self,
        *,
        recipient: str,
        domain: str,
        text: str,
        skill_domains: list[str],
        skill_md: str,
        action_id: str,
    ) -> tuple[dict[str, int], dict[str, Any]]:
        """
        Fixed-shape PIR plan (single bundled DB, constant key count).

        Returns:
        - features (clear bits): recipient_ok, domain_ok, dlp_hit, ioc_hit, install_hit
        - evidence (per-action signed PIR transcript)
        """
        if not self.signed_pir:
            raise RuntimeError("FULL policy engine requires SIGNED_PIR=1")
        b = self._load_bundle()

        # Precompute safe padding strings under the bundle base domain.
        base_ds = int(b.base_domain_size)
        if self._pad_base_domain_size != base_ds or self._pad_skill_domains is None or self._pad_install_tokens is None:
            forbidden_ioc = {int(stable_idx(str(d), base_ds)) for d in (self._cfg_ioc_domains or [])}
            forbidden_inst = {int(stable_idx(str(t), base_ds)) for t in (self._cfg_install_tokens or [])}
            self._pad_skill_domains = _pick_safe_pad_strings(
                prefix="__pad_skill_domain__",
                n=int(self.max_skill_domains),
                domain_size=base_ds,
                forbidden=forbidden_ioc,
            )
            self._pad_install_tokens = _pick_safe_pad_strings(
                prefix="__pad_install_token__",
                n=int(self.max_tokens),
                domain_size=base_ds,
                forbidden=forbidden_inst,
            )
            self._pad_base_domain_size = base_ds

        # Fixed-shape padding.
        doms = [str(d).strip().lower() for d in (skill_domains or []) if str(d).strip()]
        doms = doms[: self.max_skill_domains]
        while len(doms) < self.max_skill_domains:
            pad = (self._pad_skill_domains or ["example.com"])[len(doms) % max(1, int(self.max_skill_domains))]
            doms.append(str(pad))

        toks = extract_install_tokens(text=skill_md or "", max_tokens=self.max_tokens)
        while len(toks) < self.max_tokens:
            pad2 = (self._pad_install_tokens or [f"__pad_install_token_{len(toks)}__"])[len(toks) % max(1, int(self.max_tokens))]
            toks.append(str(pad2))

        # Stable raw indices under the *base* domain.
        rec_raw = stable_idx(str(recipient or ""), base_ds)
        dom_raw = stable_idx(str(domain or ""), base_ds)
        tok_raw = fourgram_indices(str(text or ""), base_ds, int(self.max_tokens))
        ioc_raw = [stable_idx(d, base_ds) for d in doms]
        inst_raw = [stable_idx(t, base_ds) for t in toks[: self.max_tokens]]

        idxs: list[int] = []
        idxs.append(_bundle_shift(b, logical="allow_recipients", raw_idx=rec_raw))
        idxs.append(_bundle_shift(b, logical="allow_domains", raw_idx=dom_raw))
        idxs.extend([_bundle_shift(b, logical="banned_tokens", raw_idx=int(x)) for x in tok_raw])
        idxs.extend([_bundle_shift(b, logical="ioc_domains", raw_idx=int(x)) for x in ioc_raw])
        idxs.extend([_bundle_shift(b, logical="banned_install_tokens", raw_idx=int(x)) for x in inst_raw])

        # One constant-shape signed PIR call.
        bits, ev = self._query_bits_signed_or_single_server(
            db_name=str(b.db),
            idxs=idxs,
            action_id=action_id,
            domain_size=int(b.bundle_domain_size),
        )
        if len(bits) != len(idxs):
            raise RuntimeError("policy_server_wrong_batch_size")

        n_tok = int(self.max_tokens)
        n_dom = int(self.max_skill_domains)
        rec_ok = int(bits[0]) & 1
        dom_ok = int(bits[1]) & 1
        dlp_hit = _bool_or([int(x) & 1 for x in bits[2 : 2 + n_tok]])
        ioc_hit = _bool_or([int(x) & 1 for x in bits[2 + n_tok : 2 + n_tok + n_dom]])
        install_hit = _bool_or([int(x) & 1 for x in bits[2 + n_tok + n_dom : 2 + n_tok + n_dom + n_tok]])
        feats = {
            "recipient_ok": int(rec_ok),
            "domain_ok": int(dom_ok),
            "dlp_hit": int(dlp_hit),
            "ioc_hit": int(ioc_hit),
            "install_hit": int(install_hit),
        }
        return feats, {"unified_bits": ev}

    def _mpc_init(self, *, action_id: str, request_sha256: str, input0: dict[int, int], input1: dict[int, int]) -> None:
        gates = [{"op": g.op, "out": int(g.out), "a": g.a, "b": g.b, "value": g.value} for g in self._circuit.gates]
        payload0 = {
            "action_id": action_id,
            "program_id": str(self.program_id),
            "request_sha256": str(request_sha256),
            "n_wires": int(self._circuit.n_wires),
            "gates": gates,
            "input_shares": {str(k): int(v) & 1 for k, v in (input0 or {}).items()},
            "outputs": {k: int(v) for k, v in self._circuit.outputs.items()},
            "ttl_seconds": int(os.getenv("MPC_SESSION_TTL_S", "30")),
        }
        payload1 = dict(payload0)
        payload1["input_shares"] = {str(k): int(v) & 1 for k, v in (input1 or {}).items()}

        _trace_mpc(server_id=0, endpoint="/mpc/init", action_id=str(action_id), program_id=str(self.program_id), request_sha256=str(request_sha256), n_wires=int(self._circuit.n_wires), n_gates=len(gates), multi=False)
        _trace_mpc(server_id=1, endpoint="/mpc/init", action_id=str(action_id), program_id=str(self.program_id), request_sha256=str(request_sha256), n_wires=int(self._circuit.n_wires), n_gates=len(gates), multi=False)
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

    def _mpc_eval_and_rounds(self, *, action_id: str) -> None:
        u0 = str(self.pir.policy0_url).rstrip("/")
        u1 = str(self.pir.policy1_url).rstrip("/")
        for ridx, round_gates in enumerate(self._circuit.and_rounds):
            triples0: list[dict[str, Any]] = []
            triples1: list[dict[str, Any]] = []
            for gi in round_gates:
                a = secrets.randbits(1) & 1
                b = secrets.randbits(1) & 1
                c = (a & b) & 1
                a0, a1 = _share_bit(a)
                b0, b1 = _share_bit(b)
                c0, c1 = _share_bit(c)
                triples0.append({"gate_index": int(gi), "a_share": int(a0), "b_share": int(b0), "c_share": int(c0)})
                triples1.append({"gate_index": int(gi), "a_share": int(a1), "b_share": int(b1), "c_share": int(c1)})

            m0 = {"action_id": action_id, "triples": triples0}
            m1 = {"action_id": action_id, "triples": triples1}
            _trace_mpc(server_id=0, endpoint="/mpc/and_mask_batch", action_id=str(action_id), program_id=str(self.program_id), and_round=int(ridx), n_items=len(round_gates), multi=False)
            _trace_mpc(server_id=1, endpoint="/mpc/and_mask_batch", action_id=str(action_id), program_id=str(self.program_id), and_round=int(ridx), n_items=len(round_gates), multi=False)
            f0 = _HTTP_POOL.submit(session_for(u0).post, f"{u0}/mpc/and_mask_batch", json=m0, timeout=10)
            f1 = _HTTP_POOL.submit(session_for(u1).post, f"{u1}/mpc/and_mask_batch", json=m1, timeout=10)
            r0 = f0.result()
            r1 = f1.result()
            r0.raise_for_status()
            r1.raise_for_status()
            j0 = r0.json()
            j1 = r1.json()
            d0s = j0.get("d_shares") or []
            e0s = j0.get("e_shares") or []
            d1s = j1.get("d_shares") or []
            e1s = j1.get("e_shares") or []
            if not (isinstance(d0s, list) and isinstance(e0s, list) and isinstance(d1s, list) and isinstance(e1s, list)):
                raise RuntimeError("mpc_bad_batch_reply")
            if not (len(d0s) == len(e0s) == len(d1s) == len(e1s) == len(round_gates)):
                raise RuntimeError("mpc_bad_batch_size")

            opens: list[dict[str, Any]] = []
            for k, gi in enumerate(round_gates):
                d = (int(d0s[k]) ^ int(d1s[k])) & 1
                e = (int(e0s[k]) ^ int(e1s[k])) & 1
                opens.append({"gate_index": int(gi), "d": int(d), "e": int(e)})
            fin = {"action_id": action_id, "opens": opens}
            _trace_mpc(server_id=0, endpoint="/mpc/and_finish_batch", action_id=str(action_id), program_id=str(self.program_id), and_round=int(ridx), n_items=len(round_gates), multi=False)
            _trace_mpc(server_id=1, endpoint="/mpc/and_finish_batch", action_id=str(action_id), program_id=str(self.program_id), and_round=int(ridx), n_items=len(round_gates), multi=False)
            f0 = _HTTP_POOL.submit(session_for(u0).post, f"{u0}/mpc/and_finish_batch", json=fin, timeout=10)
            f1 = _HTTP_POOL.submit(session_for(u1).post, f"{u1}/mpc/and_finish_batch", json=fin, timeout=10)
            r0 = f0.result()
            r1 = f1.result()
            r0.raise_for_status()
            r1.raise_for_status()

    def _mpc_finalize(self, *, action_id: str) -> dict[str, Any]:
        payload = {"action_id": action_id}
        _trace_mpc(server_id=0, endpoint="/mpc/finalize", action_id=str(action_id), program_id=str(self.program_id), multi=False)
        _trace_mpc(server_id=1, endpoint="/mpc/finalize", action_id=str(action_id), program_id=str(self.program_id), multi=False)
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

    def preview_egress(
        self,
        *,
        intent_id: str,
        inputs: Dict[str, Any],
        constraints: Dict[str, Any],
        session: str,
        caller: str,
    ) -> Dict[str, Any]:
        auth_ctx = (constraints or {}).get("_auth_ctx") if isinstance((constraints or {}).get("_auth_ctx"), dict) else {}
        external_principal = str((auth_ctx or {}).get("external_principal") or "")
        delegation_jti = str((auth_ctx or {}).get("delegation_jti") or "")
        hash_ctx: dict[str, Any] = {}
        if external_principal:
            hash_ctx["external_principal"] = external_principal
        if delegation_jti:
            hash_ctx["delegation_jti"] = delegation_jti
        contextual_targets_raw = (constraints or {}).get("contextual_targets") if isinstance((constraints or {}).get("contextual_targets"), list) else []
        contextual_targets = {_normalize_ctx_target(x) for x in contextual_targets_raw if str(x or "").strip()}
        if contextual_targets:
            digest = sha256_hex("|".join(sorted(contextual_targets)).encode("utf-8"))
            hash_ctx["contextual_targets_sha256"] = digest
        # query_anchored_targets: derived solely from user request text, safe for auth override.
        # Full contextual_targets (which includes tool-output-derived targets) are used for
        # hash binding only — NOT for recipient_ok/domain_ok authorization.
        qa_targets_raw = (constraints or {}).get("query_anchored_targets") if isinstance((constraints or {}).get("query_anchored_targets"), list) else []
        query_anchored_targets = {_normalize_ctx_target(x) for x in qa_targets_raw if str(x or "").strip()}
        # Task capsule: bind user-mentioned principal set hash (Proposition 6).
        capsule_hash = str((constraints or {}).get("capsule_hash") or "").strip()
        if capsule_hash:
            hash_ctx["capsule_hash"] = capsule_hash
        if self.handles is None:
            raise RuntimeError("unified_egress_requires_handle_store")
        intent = str(intent_id)
        if intent not in ("SendMessage", "FetchResource", "PostWebhook", "CheckMessagePolicy", "CheckWebhookPolicy", "CheckFetchPolicy"):
            raise ValueError("unsupported intent for unified egress preview")

        is_send = 1 if intent in ("SendMessage", "CheckMessagePolicy") else 0
        is_fetch = 1 if intent in ("FetchResource", "CheckFetchPolicy") else 0
        is_webhook = 1 if intent in ("PostWebhook", "CheckWebhookPolicy") else 0
        is_skill = 0

        recipient_real = str(inputs.get("recipient", ""))
        text_real = str(inputs.get("text", ""))
        domain_real = str(inputs.get("domain", "example.com"))
        channel_real = str(inputs.get("channel", "email"))
        resource_id_real = str(inputs.get("resource_id", "example"))
        path_real = str(inputs.get("path", "/"))

        dummy_recipient = os.getenv("DUMMY_RECIPIENT", "alice@example.com")
        dummy_domain = os.getenv("DUMMY_DOMAIN", "example.com")
        dummy_text = os.getenv("DUMMY_TEXT", "hello world")

        recipient = recipient_real if is_send else str(dummy_recipient)
        text = text_real if (is_send or is_webhook) else str(dummy_text)
        domain = domain_real if (is_fetch or is_webhook) else str(dummy_domain)

        artifacts = inputs.get("artifacts", []) or []
        # Hard-stop: sensitive handles are a gateway-TCB property.
        for a in artifacts or []:
            hid = a.get("handle") if isinstance(a, dict) else None
            if not hid:
                continue
            rec = self.handles.get(str(hid))
            if not rec:
                continue
            if rec.session != session or rec.caller != caller or rec.sensitivity.upper() == "HIGH":
                return {
                    "allow_pre": False,
                    "need_confirm": False,
                    "patch": SanitizePatch(PATCH_NOOP, {}).to_dict(),
                    "reason_code": "HIGH_HANDLE_BLOCKED",
                    "details": "Sensitive handle cannot be externalized.",
                    "evidence": {},
                    "tx_id": None,
                }

        action_id = f"a_{secrets.token_urlsafe(12)}"

        canonical_intent = ("SendMessage" if is_send else ("FetchResource" if is_fetch else "PostWebhook"))
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

        if self.policy_bypass:
            patch = SanitizePatch(PATCH_NOOP, {})
            preview = {
                "program_id": self.program_id,
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

        caps = get_effective_capabilities(caller, external_principal=(external_principal or None))
        cap_send = 1 if caps.egress_ok(kind="send_message") else 0
        cap_fetch = 1 if caps.egress_ok(kind="fetch_resource") else 0
        cap_webhook = 1 if caps.egress_ok(kind="post_webhook") else 0
        cap_skill = 0

        feats, pir_ev = self._pir_unified_plan(
            recipient=recipient,
            domain=domain,
            text=text,
            skill_domains=[],
            skill_md=os.getenv("DUMMY_SKILL_MD", ""),
            action_id=action_id,
        )
        # Authorization target source: which target set may flip recipient_ok / domain_ok.
        #   "query_only"  (default, secure) — only user-query-derived targets.
        #   "contextual"  — both query + tool-output targets (pre-hardening legacy).
        # Tool-output-derived targets are always bound in the hash regardless.
        auth_target_mode = (os.getenv("SECURECLAW_AUTH_TARGET_SOURCE", "query_only") or "query_only").strip().lower()
        if auth_target_mode == "contextual":
            auth_targets = query_anchored_targets | contextual_targets
        else:
            auth_targets = query_anchored_targets
        if auth_targets:
            ctx_rec_ok, ctx_dom_ok = _ctx_target_match(auth_targets, recipient=recipient, domain=domain)
            feats = dict(feats)
            if ctx_rec_ok:
                feats["recipient_ok"] = 1
            if ctx_dom_ok:
                feats["domain_ok"] = 1

        # Optional DFA confirm stage (keeps legacy demo semantics).
        dlp_mode = (os.getenv("DLP_MODE", "fourgram") or "fourgram").strip().lower()
        dfa_ev = None
        if int(feats.get("dlp_hit", 0)) == 1 and dlp_mode == "dfa" and (is_send or is_webhook):
            from .guardrails import ObliviousGuardrails  # local import to avoid cycles

            tmp = ObliviousGuardrails(
                pir=self.pir,
                handles=self.handles,
                domain_size=self.domain_size,
                max_tokens=self.max_tokens,
                dlp_mode="dfa",
                signed_pir=True,
            )
            matched, dfa_ev = tmp._dfa_match(text, action_id=action_id)
            feats = dict(feats)
            feats["dlp_hit"] = 1 if matched else 0
            if dfa_ev is not None:
                pir_ev = dict(pir_ev)
                pir_ev["dfa"] = dfa_ev

        # Secret-share MPC inputs.
        in0: dict[int, int] = {}
        in1: dict[int, int] = {}

        def set_in(name: str, bit: int) -> None:
            wi = int(self._circuit.inputs[name])
            s0, s1 = _share_bit(int(bit) & 1)
            in0[wi] = int(s0) & 1
            in1[wi] = int(s1) & 1

        for nm, bit in [
            ("intent_send", is_send),
            ("intent_fetch", is_fetch),
            ("intent_webhook", is_webhook),
            ("intent_skill_install", is_skill),
            ("cap_send", cap_send),
            ("cap_fetch", cap_fetch),
            ("cap_webhook", cap_webhook),
            ("cap_skill_install", cap_skill),
            ("recipient_ok", int(feats["recipient_ok"])),
            ("domain_ok", int(feats["domain_ok"])),
            ("dlp_hit", int(feats["dlp_hit"])),
            ("high_handle_present", 0),
            ("ioc_hit", int(feats["ioc_hit"])),
            ("install_hit", int(feats["install_hit"])),
            ("base64_obf", 0),
        ]:
            set_in(nm, int(bit) & 1)

        if self._mpc_mixed is not None:
            commit_ev = self._mpc_mixed.run_commit(
                action_id=action_id,
                request_sha256=request_sha,
                input0=in0,
                input1=in1,
                timeout_s=int(os.getenv("MPC_COMMIT_TIMEOUT_S", "30")),
            )
        else:
            self._mpc_init(action_id=action_id, request_sha256=request_sha, input0=in0, input1=in1)
            self._mpc_eval_and_rounds(action_id=action_id)
            commit_ev = self._mpc_finalize(action_id=action_id)

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

        reason = "ALLOW"
        if allow_pre != 1:
            if int(feats["recipient_ok"]) != 1 and is_send:
                reason = "RECIPIENT_NOT_ALLOWED"
            elif int(feats["domain_ok"]) != 1 and (is_fetch or is_webhook):
                reason = "DOMAIN_NOT_ALLOWED"
            else:
                reason = "POLICY_DENY"
        elif need_confirm == 1:
            reason = "REQUIRE_CONFIRM"

        preview = {
            "program_id": str(self.program_id),
            "action_id": action_id,
            "request_sha256": request_sha,
            "auth_context": hash_ctx,
            "allow_pre": bool(allow_pre == 1),
            "need_confirm": bool(need_confirm == 1),
            "patch": patch.to_dict(),
            "pir_evidence": pir_ev,
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

        result: dict[str, Any] = {
            "allow_pre": bool(allow_pre == 1),
            "need_confirm": bool(need_confirm == 1),
            "patch": patch.to_dict(),
            "reason_code": reason,
            "details": "",
            "evidence": {"commit": commit_ev, "pir": pir_ev},
            "tx_id": tx_rec.tx_id,
            "action_id": action_id,
            "request_sha256": request_sha,
        }
        # Mint a bound confirm token for actions requiring confirmation.
        if need_confirm == 1:
            ct = _mint_confirm_token(action_id, request_sha)
            if ct:
                result["confirm_token"] = ct
        return result

    def preview_skill_install(
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
                "program_id": str(self.program_id),
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

        # Intent bits
        is_send, is_fetch, is_webhook, is_skill = 0, 0, 0, 1

        feats, pir_ev = self._pir_unified_plan(
            recipient=os.getenv("DUMMY_RECIPIENT", "alice@example.com"),
            domain=os.getenv("DUMMY_DOMAIN", "example.com"),
            text=os.getenv("DUMMY_TEXT", "hello world"),
            skill_domains=list(domains or []),
            skill_md=str(skill_md or ""),
            action_id=action_id,
        )

        in0: dict[int, int] = {}
        in1: dict[int, int] = {}

        def set_in(name: str, bit: int) -> None:
            wi = int(self._circuit.inputs[name])
            s0, s1 = _share_bit(int(bit) & 1)
            in0[wi] = int(s0) & 1
            in1[wi] = int(s1) & 1

        for nm, bit in [
            ("intent_send", is_send),
            ("intent_fetch", is_fetch),
            ("intent_webhook", is_webhook),
            ("intent_skill_install", is_skill),
            ("cap_send", 0),
            ("cap_fetch", 0),
            ("cap_webhook", 0),
            ("cap_skill_install", cap_install),
            ("recipient_ok", int(feats["recipient_ok"])),
            ("domain_ok", int(feats["domain_ok"])),
            ("dlp_hit", int(feats["dlp_hit"])),
            ("high_handle_present", 0),
            ("ioc_hit", int(feats["ioc_hit"])),
            ("install_hit", int(feats["install_hit"])),
            ("base64_obf", 1 if base64_obf else 0),
        ]:
            set_in(nm, int(bit) & 1)

        if self._mpc_mixed is not None:
            commit_ev = self._mpc_mixed.run_commit(
                action_id=action_id,
                request_sha256=request_sha,
                input0=in0,
                input1=in1,
                timeout_s=int(os.getenv("MPC_COMMIT_TIMEOUT_S", "30")),
            )
        else:
            self._mpc_init(action_id=action_id, request_sha256=request_sha, input0=in0, input1=in1)
            self._mpc_eval_and_rounds(action_id=action_id)
            commit_ev = self._mpc_finalize(action_id=action_id)

        p0 = (commit_ev.get("policy0") or {}) if isinstance(commit_ev, dict) else {}
        p1 = (commit_ev.get("policy1") or {}) if isinstance(commit_ev, dict) else {}
        o0 = p0.get("outputs") or {}
        o1 = p1.get("outputs") or {}
        allow_pre = (int(o0.get("allow_pre", 0)) ^ int(o1.get("allow_pre", 0))) & 1
        need_confirm = (int(o0.get("need_confirm", 0)) ^ int(o1.get("need_confirm", 0))) & 1
        patch0 = (int(o0.get("patch0", 0)) ^ int(o1.get("patch0", 0))) & 1
        patch1 = (int(o0.get("patch1", 0)) ^ int(o1.get("patch1", 0))) & 1
        patch_id = (patch0 | (patch1 << 1)) & 3

        # Keep a single patch space across intents. For skills, patch is advisory.
        patch_params: dict[str, Any] = {}
        if patch_id == PATCH_CLAMP_LEN:
            patch_params["max_chars"] = int(os.getenv("SKILL_MD_MAX_CHARS", "2000"))
        patch = SanitizePatch(int(patch_id), patch_params)

        reason = "ALLOW"
        if allow_pre != 1:
            reason = "IOC_BLOCKED" if int(feats["ioc_hit"]) == 1 else "POLICY_DENY"
        elif need_confirm == 1:
            reason = "REQUIRE_CONFIRM"

        preview = {
            "program_id": str(self.program_id),
            "action_id": action_id,
            "request_sha256": request_sha,
            "auth_context": hash_ctx,
            "allow_pre": bool(allow_pre == 1),
            "need_confirm": bool(need_confirm == 1),
            "patch": patch.to_dict(),
            "skill_id": str(skill_id),
            "skill_digest": str(skill_digest),
            "pir_evidence": pir_ev,
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

        return {
            "allow_pre": bool(allow_pre == 1),
            "need_confirm": bool(need_confirm == 1),
            "patch": patch.to_dict(),
            "reason_code": reason,
            "evidence": {"commit": commit_ev, "pir": pir_ev},
            "tx_id": tx_rec.tx_id,
            "action_id": action_id,
            "request_sha256": request_sha,
        }
