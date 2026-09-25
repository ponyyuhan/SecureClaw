import os
import hashlib
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple

import requests

from .fss_pir import PirClient
from .handles import HandleStore
from .http_session import session_for

def stable_idx(s: str, domain_size: int) -> int:
    d = hashlib.sha256(s.encode("utf-8")).digest()
    x = int.from_bytes(d[:4], "little")
    return x % domain_size

def fourgram_indices(text: str, domain_size: int, max_tokens: int) -> List[int]:
    """Tokenize text into character 4-grams and hash each to an index in [0, domain_size).

    This is a demo-friendly surrogate for regex / multi-pattern matching.
    """
    s = text or ""
    s = s.replace("\n", " ")
    grams = []
    for i in range(0, max(0, len(s) - 3)):
        g = s[i:i+4]
        grams.append(g)
        if len(grams) >= max_tokens:
            break
    idxs = [stable_idx(g, domain_size) for g in grams]

    # Traffic shaping: pad to a fixed batch size so the policy servers do not learn
    # message length (within the max_tokens cap) from request size.
    if bool(int(os.getenv("PAD_TOKEN_BATCH", "1"))):
        while len(idxs) < max_tokens:
            idxs.append(stable_idx(f"__pad_token_{len(idxs)}__", domain_size))
        idxs = idxs[:max_tokens]
    return idxs

@dataclass
class GuardrailDecision:
    allow: bool
    reason_code: str
    details: str = ""
    evidence: dict[str, Any] | None = None

class ObliviousGuardrails:
    """Oblivious guardrails via 2-server FSS-PIR queries."""

    def __init__(
        self,
        pir: PirClient,
        handles: HandleStore,
        domain_size: int,
        max_tokens: int,
        *,
        dlp_mode: str | None = None,
        signed_pir: bool | None = None,
    ):
        self.pir = pir
        self.handles = handles
        self.domain_size = domain_size
        self.max_tokens = max_tokens
        self.dlp_mode = (dlp_mode or os.getenv("DLP_MODE", "fourgram")).strip().lower()
        self.signed_pir = bool(int(os.getenv("SIGNED_PIR", "0"))) if signed_pir is None else bool(signed_pir)
        self.shape_all_intents = bool(int(os.getenv("SHAPE_ALL_INTENTS", "0")))
        self.use_bundle = bool(int(os.getenv("USE_POLICY_BUNDLE", "0")))

        # DFA config (loaded lazily / best-effort).
        self._dfa: dict[str, Any] | None = None
        self._dfa_cache: dict[tuple[int, int], bytes] = {}
        self._bundle: dict[str, Any] | None = None

    def _load_dfa(self) -> dict[str, Any] | None:
        if self._dfa is not None:
            return self._dfa
        try:
            r = session_for(self.pir.policy0_url).get(f"{self.pir.policy0_url}/meta", timeout=2.0)
            r.raise_for_status()
            meta = r.json()
            dfa = (meta.get("dfa") or {}) if isinstance(meta, dict) else {}
            if not dfa or not dfa.get("enabled"):
                self._dfa = None
                return None
            alpha = int(dfa.get("alpha"))
            block_size = int(dfa.get("block_size"))
            db_name = str(dfa.get("db") or "dfa_transitions")
            dfa_domain_size = int(dfa.get("domain_size") or meta.get("domain_size") or self.domain_size)
            alphabet = meta.get("dfa_alphabet") or {}
            if not isinstance(alphabet, dict):
                raise ValueError("bad dfa_alphabet")
            char_to_sym = alphabet.get("char_to_sym") or {}
            if not isinstance(char_to_sym, dict):
                raise ValueError("bad char_to_sym")
            # json loads keys as str and values as numbers already.
            char_to_sym2 = {str(k): int(v) for k, v in char_to_sym.items()}
            self._dfa = {
                "alpha": alpha,
                "block_size": block_size,
                "db": db_name,
                "domain_size": dfa_domain_size,
                "char_to_sym": char_to_sym2,
            }
            return self._dfa
        except Exception:
            self._dfa = None
            return None

    def _load_bundle(self) -> dict[str, Any] | None:
        if self._bundle is not None:
            return self._bundle
        if not self.use_bundle:
            self._bundle = None
            return None
        try:
            r = session_for(self.pir.policy0_url).get(f"{self.pir.policy0_url}/meta", timeout=2.0)
            r.raise_for_status()
            meta = r.json()
            b = (meta.get("bundle") or {}) if isinstance(meta, dict) else {}
            if not b or not b.get("enabled"):
                self._bundle = None
                return None
            db = str(b.get("db") or "policy_bundle")
            base_domain_size = int(b.get("base_domain_size"))
            bundle_domain_size = int(b.get("bundle_domain_size"))
            # New schema: bundles + (bundle_stride, logical_offsets)
            bundles = b.get("bundles") or {"default": 0}
            if not isinstance(bundles, dict):
                raise ValueError("bad bundle bundles")
            bundles2 = {str(k): int(v) for k, v in bundles.items()}

            bundle_stride = int(b.get("bundle_stride") or 0)
            logical_offsets = b.get("logical_offsets") or b.get("offsets") or {}
            if not isinstance(logical_offsets, dict):
                raise ValueError("bad bundle offsets")
            logical_offsets2 = {str(k): int(v) for k, v in logical_offsets.items()}
            self._bundle = {
                "db": db,
                "base_domain_size": base_domain_size,
                "bundle_domain_size": bundle_domain_size,
                "bundles": bundles2,
                "bundle_stride": bundle_stride,
                "logical_offsets": logical_offsets2,
            }
            return self._bundle
        except Exception:
            self._bundle = None
            return None

    def _dfa_match(self, text: str, *, action_id: str | None = None) -> tuple[bool, dict[str, Any] | None]:
        cfg = self._load_dfa()
        if not cfg:
            # Fail closed: if configured to use DFA but cannot load it, block.
            return True, None

        alpha = int(cfg["alpha"])
        block_size = int(cfg["block_size"])
        db_name = str(cfg["db"])
        dfa_domain_size = int(cfg.get("domain_size") or self.domain_size)
        char_to_sym: dict[str, int] = cfg["char_to_sym"]

        s = (text or "").upper().replace("\n", " ")
        # Limit scan length (demo / DoS bound).
        max_chars = int(os.getenv("MAX_DFA_SCAN_CHARS", "256"))
        if max_chars < 16:
            max_chars = 16
        if max_chars > 4096:
            max_chars = 4096
        if len(s) > max_chars:
            s = s[:max_chars]
        if bool(int(os.getenv("PAD_DFA_STEPS", "0"))):
            if len(s) < max_chars:
                s = s + ("~" * (max_chars - len(s)))

        state = 0
        steps: list[dict[str, Any]] = []
        matched = False
        for ch in s:
            sym = int(char_to_sym.get(ch, 0))
            blk = None
            proof = None
            if self.signed_pir:
                if not action_id:
                    raise ValueError("action_id required for signed DFA scan")
                idx = (state * alpha) + sym
                blks, pr = self.pir.query_blocks_signed(db_name, [idx], block_size=block_size, action_id=action_id, domain_size=dfa_domain_size)
                blk = blks[0]
                proof = pr
            else:
                ck = (state, sym)
                blk = self._dfa_cache.get(ck)
                if blk is None:
                    idx = (state * alpha) + sym
                    blk = self.pir.query_block(db_name, idx, block_size=block_size, domain_size=dfa_domain_size)
                    self._dfa_cache[ck] = blk

            if self.signed_pir:
                if proof is not None:
                    steps.append({"state": state, "sym": sym, "idx": (state * alpha) + sym, "proof": proof})
            # next_state u16 LE + match flag byte
            state = int.from_bytes(blk[0:2], "little", signed=False)
            if (blk[2] & 1) == 1:
                matched = True
                if not bool(int(os.getenv("PAD_DFA_STEPS", "0"))):
                    return True, {"db": db_name, "alpha": alpha, "block_size": block_size, "char_to_sym": char_to_sym, "steps": steps}
        if self.signed_pir:
            return matched, {"db": db_name, "alpha": alpha, "block_size": block_size, "char_to_sym": char_to_sym, "steps": steps}
        return False, None

    def _contains_high_handle(self, artifacts: List[Dict[str, Any]], session: str, caller: str) -> Tuple[bool, str]:
        for a in artifacts or []:
            hid = a.get("handle")
            if not hid:
                continue
            rec = self.handles.get(hid)
            if not rec:
                continue
            if rec.session != session:
                return True, "HANDLE_SESSION_MISMATCH"
            if rec.caller != caller:
                return True, "HANDLE_CALLER_MISMATCH"
            if rec.sensitivity.upper() == "HIGH":
                return True, "HIGH_HANDLE_BLOCKED"
            # Even non-HIGH handles should not automatically be allowed to flow to arbitrary sinks.
            if "SendMessage" not in (rec.allowed_sinks or []):
                return True, "HANDLE_SINK_BLOCKED"
        return False, ""

    def check_egress_message(
        self,
        *,
        recipient: str,
        text: str,
        artifacts: List[Dict[str, Any]],
        session: str,
        caller: str,
        action_id: str | None = None,
    ) -> GuardrailDecision:
        evidence: dict[str, Any] = {}
        if action_id:
            evidence["action_id"] = action_id
        # 1) hard IFC rule: HIGH handles cannot flow to egress
        bad, code = self._contains_high_handle(artifacts, session=session, caller=caller)
        if bad:
            return GuardrailDecision(False, code, "Sensitive handle cannot be externalized.", evidence=None)

        bcfg = self._load_bundle()

        # 2) recipient allowlist (oblivious)
        if bcfg:
            base_ds = int(bcfg["base_domain_size"])
            bundles: dict[str, int] = bcfg.get("bundles") or {"default": 0}
            bundle_name = (os.getenv("POLICY_BUNDLE_EGRESS", "default") or "default").strip()
            bid = int(bundles.get(bundle_name, 0))
            stride = int(bcfg.get("bundle_stride") or 0)
            loff = int((bcfg.get("logical_offsets") or {}).get("allow_recipients", 0))
            ridx = (bid * stride) + loff + stable_idx(recipient, base_ds)
            db_name = str(bcfg["db"])
            dom = int(bcfg["bundle_domain_size"])
        else:
            ridx = stable_idx(recipient, self.domain_size)
            db_name = "allow_recipients"
            dom = None
        if self.signed_pir:
            if not action_id:
                raise ValueError("action_id required for signed_pir")
            allowed_bits, pr = self.pir.query_bits_signed(db_name, [ridx], action_id=action_id, domain_size=dom)
            allowed = int(allowed_bits[0]) if allowed_bits else 0
            evidence["allow_recipients"] = pr
        else:
            if dom is None:
                allowed = self.pir.query_bit(db_name, ridx)
            else:
                allowed = self.pir.query_bit(db_name, ridx, domain_size=dom)
        if allowed != 1:
            return GuardrailDecision(False, "RECIPIENT_NOT_ALLOWED", "Recipient blocked by allowlist.", evidence=(evidence if evidence else None))

        # 3) content DLP (oblivious)
        # First-stage coarse filter: 4-gram bitset (cheap, but may have collisions).
        if bcfg:
            base_ds = int(bcfg["base_domain_size"])
            bundles: dict[str, int] = bcfg.get("bundles") or {"default": 0}
            bundle_name = (os.getenv("POLICY_BUNDLE_EGRESS", "default") or "default").strip()
            bid = int(bundles.get(bundle_name, 0))
            stride = int(bcfg.get("bundle_stride") or 0)
            loff = int((bcfg.get("logical_offsets") or {}).get("banned_tokens", 0))
            idxs0 = fourgram_indices(text, base_ds, self.max_tokens)
            idxs = [(bid * stride) + loff + x for x in idxs0]
            db_name2 = str(bcfg["db"])
            dom2 = int(bcfg["bundle_domain_size"])
        else:
            idxs = fourgram_indices(text, self.domain_size, self.max_tokens)
            db_name2 = "banned_tokens"
            dom2 = None
        if self.signed_pir:
            if not action_id:
                raise ValueError("action_id required for signed_pir")
            hits, pr = self.pir.query_bits_signed(db_name2, idxs, action_id=action_id, domain_size=dom2)
            evidence["banned_tokens"] = pr
        else:
            if dom2 is None:
                hits = self.pir.query_bits(db_name2, idxs)
            else:
                hits = self.pir.query_bits(db_name2, idxs, domain_size=dom2)

        if any(int(h) == 1 for h in hits):
            if self.dlp_mode == "dfa":
                # Second-stage exact confirmation via oblivious DFA scan (Aho-Corasick).
                matched, dfa_ev = self._dfa_match(text, action_id=action_id)
                if dfa_ev is not None:
                    evidence["dfa"] = dfa_ev
                if matched:
                    return GuardrailDecision(False, "DLP_BLOCKED", "Outbound content matched a banned pattern (oblivious DFA confirm).", evidence=(evidence if evidence else None))
            else:
                return GuardrailDecision(False, "DLP_BLOCKED", "Outbound content matched a banned token (oblivious check).", evidence=(evidence if evidence else None))

        # Optional traffic shaping: also query domain allowlist with a fixed dummy value,
        # so that a single policy server cannot infer "intent class" from which DBs are queried.
        if self.shape_all_intents:
            if bcfg:
                base_ds = int(bcfg["base_domain_size"])
                bundles: dict[str, int] = bcfg.get("bundles") or {"default": 0}
                bundle_name = (os.getenv("POLICY_BUNDLE_EGRESS", "default") or "default").strip()
                bid = int(bundles.get(bundle_name, 0))
                stride = int(bcfg.get("bundle_stride") or 0)
                loff = int((bcfg.get("logical_offsets") or {}).get("allow_domains", 0))
                didx = (bid * stride) + loff + stable_idx("example.com", base_ds)
                db_name3 = str(bcfg["db"])
                dom3 = int(bcfg["bundle_domain_size"])
            else:
                didx = stable_idx("example.com", self.domain_size)
                db_name3 = "allow_domains"
                dom3 = None
            if self.signed_pir:
                if not action_id:
                    raise ValueError("action_id required for signed_pir")
                _bits, pr = self.pir.query_bits_signed(db_name3, [didx], action_id=action_id, domain_size=dom3)
                evidence["allow_domains"] = pr
            else:
                if dom3 is None:
                    _ = self.pir.query_bit(db_name3, didx)
                else:
                    _ = self.pir.query_bit(db_name3, didx, domain_size=dom3)

        return GuardrailDecision(True, "ALLOW", "OK", evidence=(evidence if evidence else None))

    def check_network_domain(self, *, domain: str, action_id: str | None = None, session: str = "demo-session", caller: str = "unknown") -> GuardrailDecision:
        bcfg = self._load_bundle()
        if bcfg:
            base_ds = int(bcfg["base_domain_size"])
            bundles: dict[str, int] = bcfg.get("bundles") or {"default": 0}
            bundle_name = (os.getenv("POLICY_BUNDLE_NET", "default") or "default").strip()
            bid = int(bundles.get(bundle_name, 0))
            stride = int(bcfg.get("bundle_stride") or 0)
            loff = int((bcfg.get("logical_offsets") or {}).get("allow_domains", 0))
            didx = (bid * stride) + loff + stable_idx(domain, base_ds)
            db_name = str(bcfg["db"])
            dom = int(bcfg["bundle_domain_size"])
        else:
            didx = stable_idx(domain, self.domain_size)
            db_name = "allow_domains"
            dom = None
        evidence: dict[str, Any] = {}
        if action_id:
            evidence["action_id"] = action_id
        if self.signed_pir:
            if not action_id:
                raise ValueError("action_id required for signed_pir")
            allowed_bits, pr = self.pir.query_bits_signed(db_name, [didx], action_id=action_id, domain_size=dom)
            allowed = int(allowed_bits[0]) if allowed_bits else 0
            evidence["allow_domains"] = pr
        else:
            if dom is None:
                allowed = self.pir.query_bit(db_name, didx)
            else:
                allowed = self.pir.query_bit(db_name, didx, domain_size=dom)
        if allowed != 1:
            return GuardrailDecision(False, "DOMAIN_NOT_ALLOWED", "Domain blocked by allowlist.", evidence=(evidence if evidence else None))

        # Optional traffic shaping: always issue recipient + token checks too (dummy)
        # so policy servers observe a constant query pattern across intents.
        if self.shape_all_intents:
            # Dummy allow recipient (must still be proven in executor for SendMessage).
            if bcfg:
                base_ds = int(bcfg["base_domain_size"])
                bundles: dict[str, int] = bcfg.get("bundles") or {"default": 0}
                bundle_name = (os.getenv("POLICY_BUNDLE_NET", "default") or "default").strip()
                bid = int(bundles.get(bundle_name, 0))
                stride = int(bcfg.get("bundle_stride") or 0)
                loff = int((bcfg.get("logical_offsets") or {}).get("allow_recipients", 0))
                ridx = (bid * stride) + loff + stable_idx("alice@example.com", base_ds)
                db_name_r = str(bcfg["db"])
                dom_r = int(bcfg["bundle_domain_size"])
            else:
                ridx = stable_idx("alice@example.com", self.domain_size)
                db_name_r = "allow_recipients"
                dom_r = None
            if self.signed_pir:
                if not action_id:
                    raise ValueError("action_id required for signed_pir")
                _bits, pr = self.pir.query_bits_signed(db_name_r, [ridx], action_id=action_id, domain_size=dom_r)
                evidence["allow_recipients"] = pr
            else:
                if dom_r is None:
                    _ = self.pir.query_bit(db_name_r, ridx)
                else:
                    _ = self.pir.query_bit(db_name_r, ridx, domain_size=dom_r)

            if bcfg:
                base_ds = int(bcfg["base_domain_size"])
                bundles: dict[str, int] = bcfg.get("bundles") or {"default": 0}
                bundle_name = (os.getenv("POLICY_BUNDLE_NET", "default") or "default").strip()
                bid = int(bundles.get(bundle_name, 0))
                stride = int(bcfg.get("bundle_stride") or 0)
                loff = int((bcfg.get("logical_offsets") or {}).get("banned_tokens", 0))
                idxs0 = fourgram_indices("hello world", base_ds, self.max_tokens)
                idxs = [(bid * stride) + loff + x for x in idxs0]
                db_name_b = str(bcfg["db"])
                dom_b = int(bcfg["bundle_domain_size"])
            else:
                idxs = fourgram_indices("hello world", self.domain_size, self.max_tokens)
                db_name_b = "banned_tokens"
                dom_b = None
            if self.signed_pir:
                if not action_id:
                    raise ValueError("action_id required for signed_pir")
                _hits, pr = self.pir.query_bits_signed(db_name_b, idxs, action_id=action_id, domain_size=dom_b)
                evidence["banned_tokens"] = pr
            else:
                if dom_b is None:
                    _ = self.pir.query_bits(db_name_b, idxs)
                else:
                    _ = self.pir.query_bits(db_name_b, idxs, domain_size=dom_b)

        return GuardrailDecision(True, "ALLOW", "OK", evidence=(evidence if evidence else None))
