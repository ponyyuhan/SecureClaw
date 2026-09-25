"""Build policy DB bitsets for the 2-server FSS-PIR guardrails demo.

We store bitset databases (same on both servers):
- banned_tokens: hashed 4-gram tokens representing DLP patterns
- allow_recipients: hashed recipient identifiers allowed for egress
- allow_domains: hashed domain identifiers allowed for network access
- ioc_domains: hashed domains/IPs for known-bad skill ingress infrastructure (supply-chain IOCs)
- banned_install_tokens: hashed 4-gram tokens for suspicious install semantics (curl|bash, base64 decode, etc)

The gateway queries these bitsets via FSS-PIR so that each policy server learns nothing about
the specific token/domain/recipient being checked.

NOTE: We use a *stable* SHA256-based hash -> index mapping (do NOT use Python's built-in hash()).
"""

import os
import hashlib
import re
from pathlib import Path
import json

from .dfa import build_char_mapping, build_aho_corasick_dfa
import yaml

from common.install_tokens import normalize_install_token

DATA_DIR = Path(__file__).resolve().parent / "data"
DATA_DIR.mkdir(exist_ok=True)

def set_bit(buf: bytearray, idx: int) -> None:
    byte_i = idx // 8
    bit_i = idx % 8
    buf[byte_i] |= (1 << bit_i)

def stable_idx(s: str, domain_size: int) -> int:
    d = hashlib.sha256(s.encode("utf-8")).digest()
    x = int.from_bytes(d[:4], "little")
    return x % domain_size

def add_fourgrams(buf: bytearray, pattern: str, domain_size: int):
    p = pattern.replace("\n", " ")
    for i in range(0, max(0, len(p) - 3)):
        g = p[i:i+4]
        set_bit(buf, stable_idx(g, domain_size))

def _write_dfa_transitions(*, patterns: list[str], out_dir: Path, domain_size: int) -> dict:
    # Normalize patterns to reduce alphabet and improve match rate.
    pats = [p.upper().replace("\n", " ") for p in patterns if p]
    char_to_sym = build_char_mapping(pats)
    trans, out = build_aho_corasick_dfa(pats, char_to_sym=char_to_sym)

    alpha = 1 + len(char_to_sym)
    nstates = len(trans)
    needed = nstates * alpha
    if needed > domain_size:
        raise SystemExit(
            f"DFA transition table too large for FSS_DOMAIN_SIZE={domain_size}: "
            f"need {needed} entries (states={nstates}, alpha={alpha}). Increase FSS_DOMAIN_SIZE."
        )

    # Fixed block: next_state (u16 LE) + is_match_next (u8) + reserved (u8)
    block_size = 4
    db = bytearray(b"\x00" * (domain_size * block_size))
    for st in range(nstates):
        for sym in range(alpha):
            idx = st * alpha + sym
            ns = int(trans[st][sym])
            is_match = 1 if out[ns] else 0
            off = idx * block_size
            db[off : off + 2] = int(ns).to_bytes(2, "little", signed=False)
            db[off + 2] = is_match & 0xFF
            db[off + 3] = 0

    (out_dir / "dfa_transitions.blk").write_bytes(bytes(db))
    (out_dir / "dfa_alphabet.json").write_text(
        json.dumps(
            {
                "char_to_sym": char_to_sym,
                "alpha": alpha,
                "reserved_other": 0,
                "normalization": "upper + \\n->space",
            },
            indent=2,
        )
    )
    return {
        "dfa": {
            "enabled": True,
            "db": "dfa_transitions",
            "domain_size": domain_size,
            "block_size": block_size,
            "alpha": alpha,
            "states": nstates,
        }
    }

def _load_policy_config() -> dict:
    cfg_path = os.getenv("POLICY_CONFIG_PATH", "").strip()
    if not cfg_path:
        p = Path(__file__).resolve().parent / "policy.yaml"
        if p.exists():
            cfg_path = str(p)
    if not cfg_path:
        return {}
    try:
        return yaml.safe_load(Path(cfg_path).read_text()) or {}
    except Exception as e:
        raise SystemExit(f"failed_to_load_policy_config: {e}")

def main():
    cfg = _load_policy_config()
    domain_size = int(cfg.get("domain_size") or os.getenv("FSS_DOMAIN_SIZE", "4096"))
    if domain_size <= 0 or (domain_size & (domain_size - 1)) != 0:
        raise SystemExit("FSS_DOMAIN_SIZE (or policy.yaml:domain_size) must be a power of two (e.g. 4096, 65536).")
    nbytes = (domain_size + 7) // 8

    # --- DLP patterns (demo) ---
    patterns = list(cfg.get("dlp_patterns") or [
        "AKIA",                        # AWS access key prefix
        "xoxb-",                       # Slack bot token prefix
        "OPENSSH PRIVATE KEY",         # private key marker
        "BEGIN PRIVATE KEY",           # generic key marker
    ])

    banned = bytearray(b"\x00" * nbytes)
    for pat in patterns:
        add_fourgrams(banned, pat, domain_size)

    # --- Skill ingress IOCs / install semantics (demo) ---
    # These are used by the Skill Ingress PREVIEW->COMMIT flow to block or require confirmation
    # when importing/enabling untrusted skills.
    ioc_domains = list(cfg.get("ioc_domains") or [
        # Example IOCs from public reports of malicious agent skill supply-chain attacks.
        "socifiapp.com",
        "rentry.co",
        "install.app-distribution.net",
        "91.92.242.30",
    ])
    install_patterns = list(cfg.get("install_patterns") or cfg.get("ingress_install_patterns") or [
        "curl | bash",
        "curl|bash",
        "wget | sh",
        "base64 -d",
        "| sh",
        "| bash",
        "chmod +x",
        "powershell",
        "Invoke-Expression",
    ])

    ioc = bytearray(b"\x00" * nbytes)
    for d in ioc_domains:
        set_bit(ioc, stable_idx(str(d), domain_size))

    banned_install = bytearray(b"\x00" * nbytes)
    for pat in install_patterns:
        tok = normalize_install_token(pat)
        if not tok:
            continue
        set_bit(banned_install, stable_idx(tok, domain_size))

    bundle_meta = {}
    bundles_cfg = cfg.get("bundles")
    if isinstance(bundles_cfg, dict) and bundles_cfg:
        bundles = [(str(name), dict(bcfg or {})) for name, bcfg in bundles_cfg.items()]
    else:
        bundles = [("default", cfg)]

    # Always write legacy per-db bitsets for the first bundle (for debugging and backward compatibility).
    first_name, first_cfg = bundles[0]
    allow_recipients0 = bytearray(b"\x00" * nbytes)
    allow_domains0 = bytearray(b"\x00" * nbytes)

    recipients0 = list(first_cfg.get("allow_recipients") or cfg.get("allow_recipients") or [
        "alice@example.com",
        "bob@example.com",
    ])
    for r in recipients0:
        set_bit(allow_recipients0, stable_idx(r, domain_size))

    domains0 = list(first_cfg.get("allow_domains") or cfg.get("allow_domains") or [
        "example.com",
        "api.github.com",
    ])
    for d in domains0:
        set_bit(allow_domains0, stable_idx(d, domain_size))

    (DATA_DIR / "banned_tokens.bitset").write_bytes(bytes(banned))
    (DATA_DIR / "allow_recipients.bitset").write_bytes(bytes(allow_recipients0))
    (DATA_DIR / "allow_domains.bitset").write_bytes(bytes(allow_domains0))
    (DATA_DIR / "ioc_domains.bitset").write_bytes(bytes(ioc))
    (DATA_DIR / "banned_install_tokens.bitset").write_bytes(bytes(banned_install))

    if bool(cfg.get("bundle_enabled", False)) or bool(int(os.getenv("POLICY_BUNDLE_ENABLE", "0"))):
        logical = ["banned_tokens", "allow_recipients", "allow_domains", "ioc_domains", "banned_install_tokens"]
        nbundles = len(bundles)
        needed = domain_size * len(logical) * nbundles
        bundle_domain_size = 1
        while bundle_domain_size < needed:
            bundle_domain_size <<= 1
        bundle_bytes = (bundle_domain_size + 7) // 8
        bundle = bytearray(b"\x00" * bundle_bytes)
        base_stride_bytes = nbytes
        bundle_stride_bits = domain_size * len(logical)
        bundle_stride_bytes = base_stride_bytes * len(logical)

        for bid, (bname, bcfg) in enumerate(bundles):
            allow_recipients_b = bytearray(b"\x00" * nbytes)
            allow_domains_b = bytearray(b"\x00" * nbytes)
            recs = list(bcfg.get("allow_recipients") or cfg.get("allow_recipients") or recipients0)
            doms = list(bcfg.get("allow_domains") or cfg.get("allow_domains") or domains0)
            for r in recs:
                set_bit(allow_recipients_b, stable_idx(r, domain_size))
            for d in doms:
                set_bit(allow_domains_b, stable_idx(d, domain_size))

            base_off = bid * bundle_stride_bytes
            bundle[base_off : base_off + base_stride_bytes] = bytes(banned)
            bundle[base_off + base_stride_bytes : base_off + 2 * base_stride_bytes] = bytes(allow_recipients_b)
            bundle[base_off + 2 * base_stride_bytes : base_off + 3 * base_stride_bytes] = bytes(allow_domains_b)
            bundle[base_off + 3 * base_stride_bytes : base_off + 4 * base_stride_bytes] = bytes(ioc)
            bundle[base_off + 4 * base_stride_bytes : base_off + 5 * base_stride_bytes] = bytes(banned_install)

        (DATA_DIR / "policy_bundle.bitset").write_bytes(bytes(bundle))
        bundle_meta = {
            "bundle": {
                "enabled": True,
                "db": "policy_bundle",
                "base_domain_size": domain_size,
                "bundle_domain_size": bundle_domain_size,
                "logical_dbs": logical,
                "bundles": {name: i for i, (name, _bcfg) in enumerate(bundles)},
                "bundle_stride": bundle_stride_bits,
                "logical_offsets": {
                    "banned_tokens": 0,
                    "allow_recipients": domain_size * 1,
                    "allow_domains": domain_size * 2,
                    "ioc_domains": domain_size * 3,
                    "banned_install_tokens": domain_size * 4,
                },
            }
        }

    dfa_meta = {}
    if bool(cfg.get("dfa_enabled", True)):
        dfa_meta = _write_dfa_transitions(patterns=patterns, out_dir=DATA_DIR, domain_size=domain_size)

    meta = {
        "domain_size": domain_size,
        "patterns": patterns,
        "allow_recipients": recipients0,
        "allow_domains": domains0,
        "ioc_domains": ioc_domains,
        "install_patterns": [normalize_install_token(p) for p in install_patterns if normalize_install_token(p)],
        "hash": "sha256[:4] % domain_size",
        "tokenization": "char-4gram",
        "install_tokenization": "normalized-exact-token",
    }
    meta.update(bundle_meta)
    meta.update(dfa_meta)
    (DATA_DIR / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"[build_dbs] wrote bitsets to: {DATA_DIR}")
    print(json.dumps(meta, indent=2))

if __name__ == "__main__":
    main()
