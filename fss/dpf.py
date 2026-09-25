from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Iterable, List, Tuple


SEED_BYTES = 16  # 128-bit security parameter (lambda)


class DpfError(Exception):
    pass


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])


def _prg(seed: bytes) -> Tuple[bytes, int, bytes, int]:
    """
    PRG G: {0,1}^lambda -> {0,1}^{2(lambda+1)}

    Expand a seed into two child seeds (lambda bits each) and two control bits tL/tR.
    """
    # NOTE: key versioning is handled at the DpfKey level. This function is used
    # by the v2+ construction only.
    if len(seed) != SEED_BYTES:
        raise DpfError("bad seed length")
    # Single SHA-512 expansion (faster than 2x SHA-256) to derive both children.
    d = hashlib.sha512(seed + b"prg").digest()
    sL = d[0:SEED_BYTES]
    tL = d[SEED_BYTES] & 1
    sR = d[SEED_BYTES + 1 : SEED_BYTES + 1 + SEED_BYTES]
    tR = d[2 * SEED_BYTES + 1] & 1
    return sL, tL, sR, tR


def _convert_to_bit(seed: bytes) -> int:
    # v2+: output bit is derived directly from the seed (no extra hash).
    # The seed is pseudorandom under the PRG security, so this is fine.
    return seed[0] & 1


def _int_to_bits(x: int, nbits: int) -> List[int]:
    # MSB-first bit list.
    return [((x >> (nbits - 1 - i)) & 1) for i in range(nbits)]


@dataclass(frozen=True, slots=True)
class CorrectionWord:
    s_cw: bytes  # lambda-bit seed correction
    t_l: int     # 1-bit
    t_r: int     # 1-bit


@dataclass(frozen=True, slots=True)
class DpfKey:
    """
    2-party Distributed Point Function key for a point function f_{alpha,beta} over domain {0,1}^n -> {0,1}.

    This is a Python implementation of the standard 2-party DPF construction (FSS) specialized to range bit.

    The key format is self-contained and versioned for transport over HTTP.
    """

    version: int
    domain_bits: int
    seed0: bytes
    cws: Tuple[CorrectionWord, ...]
    cw_last: int  # 1-bit

    def encode(self) -> bytes:
        if self.version not in (1, 2):
            raise DpfError("unsupported key version")
        if len(self.seed0) != SEED_BYTES:
            raise DpfError("bad seed length")
        if len(self.cws) != self.domain_bits:
            raise DpfError("bad cw length")
        if self.domain_bits <= 0 or self.domain_bits > 30:
            raise DpfError("domain_bits out of supported range")
        if self.cw_last not in (0, 1):
            raise DpfError("bad cw_last")

        out = bytearray()
        out.append(self.version & 0xFF)
        out.append(self.domain_bits & 0xFF)
        out.extend(self.seed0)
        out.append(self.cw_last & 0xFF)
        for cw in self.cws:
            if len(cw.s_cw) != SEED_BYTES:
                raise DpfError("bad cw seed length")
            out.extend(cw.s_cw)
            out.append(cw.t_l & 0xFF)
            out.append(cw.t_r & 0xFF)
        return bytes(out)

    @staticmethod
    def decode(data: bytes) -> "DpfKey":
        if len(data) < 1 + 1 + SEED_BYTES + 1:
            raise DpfError("truncated key")
        version = data[0]
        if version not in (1, 2):
            raise DpfError("unsupported key version")
        domain_bits = data[1]
        seed0 = data[2 : 2 + SEED_BYTES]
        cw_last = data[2 + SEED_BYTES] & 1
        rest = data[2 + SEED_BYTES + 1 :]
        expected = domain_bits * (SEED_BYTES + 2)
        if len(rest) != expected:
            raise DpfError("bad key length")
        cws: list[CorrectionWord] = []
        off = 0
        for _ in range(domain_bits):
            s_cw = rest[off : off + SEED_BYTES]
            t_l = rest[off + SEED_BYTES] & 1
            t_r = rest[off + SEED_BYTES + 1] & 1
            cws.append(CorrectionWord(s_cw=s_cw, t_l=t_l, t_r=t_r))
            off += SEED_BYTES + 2
        return DpfKey(version=version, domain_bits=domain_bits, seed0=seed0, cws=tuple(cws), cw_last=cw_last)


def gen_dpf_keys(*, alpha: int, beta: int, domain_bits: int) -> Tuple[bytes, bytes]:
    """
    Generate DPF keys (k0, k1) such that:
      eval(k0, x, party=0) XOR eval(k1, x, party=1) == beta if x==alpha else 0.

    beta must be 0/1.
    """
    if beta not in (0, 1):
        raise DpfError("beta must be 0/1")
    if domain_bits <= 0 or domain_bits > 30:
        raise DpfError("domain_bits out of supported range")
    domain_size = 1 << domain_bits
    if alpha < 0 or alpha >= domain_size:
        raise DpfError("alpha out of range")

    alpha_bits = _int_to_bits(alpha, domain_bits)

    # v2 keys (faster PRG / conversion); we keep v1 decoding for compatibility.
    version = 2

    root0 = secrets.token_bytes(SEED_BYTES)
    root1 = secrets.token_bytes(SEED_BYTES)
    s0 = root0
    s1 = root1
    t0 = 0
    t1 = 1

    cws: list[CorrectionWord] = []

    for bit in alpha_bits:
        s0L, t0L, s0R, t0R = _prg(s0)
        s1L, t1L, s1R, t1R = _prg(s1)

        if bit == 0:
            keep0_s, keep0_t = s0L, t0L
            lose0_s = s0R
            keep1_s, keep1_t = s1L, t1L
            lose1_s = s1R
            t_keep_cw_name = "L"
        else:
            keep0_s, keep0_t = s0R, t0R
            lose0_s = s0L
            keep1_s, keep1_t = s1R, t1R
            lose1_s = s1L
            t_keep_cw_name = "R"

        s_cw = _xor_bytes(lose0_s, lose1_s)
        # Correction bits as in the standard 2-party DPF construction.
        t_l_cw = (t0L ^ t1L ^ bit ^ 1) & 1
        t_r_cw = (t0R ^ t1R ^ bit) & 1
        cws.append(CorrectionWord(s_cw=s_cw, t_l=t_l_cw, t_r=t_r_cw))

        # Next state update uses t^{i-1} to conditionally apply correction word.
        if t0 == 1:
            s0 = _xor_bytes(keep0_s, s_cw)
            if t_keep_cw_name == "L":
                t0 = (keep0_t ^ t_l_cw) & 1
            else:
                t0 = (keep0_t ^ t_r_cw) & 1
        else:
            s0 = keep0_s
            t0 = keep0_t & 1

        if t1 == 1:
            s1 = _xor_bytes(keep1_s, s_cw)
            if t_keep_cw_name == "L":
                t1 = (keep1_t ^ t_l_cw) & 1
            else:
                t1 = (keep1_t ^ t_r_cw) & 1
        else:
            s1 = keep1_s
            t1 = keep1_t & 1

    # Final correction word CW(n+1) for range bit.
    conv0 = _convert_to_bit(s0)
    conv1 = _convert_to_bit(s1)
    cw_last = (beta ^ conv0 ^ conv1) & 1

    # Keys differ only in initial seed; CWs and cw_last are shared.
    key0 = DpfKey(version=version, domain_bits=domain_bits, seed0=root0, cws=tuple(cws), cw_last=cw_last).encode()
    key1 = DpfKey(version=version, domain_bits=domain_bits, seed0=root1, cws=tuple(cws), cw_last=cw_last).encode()
    return key0, key1


def eval_dpf_point(*, key_bytes: bytes, x: int, party: int) -> int:
    key = DpfKey.decode(key_bytes)
    return _eval_dpf_point_decoded(key=key, x=x, party=party)


def _eval_dpf_point_decoded(*, key: DpfKey, x: int, party: int) -> int:
    if party not in (0, 1):
        raise DpfError("party must be 0/1")
    if x < 0 or x >= (1 << key.domain_bits):
        raise DpfError("x out of range")

    s = key.seed0
    t = party & 1
    for level in range(int(key.domain_bits)):
        cw = key.cws[level]
        if key.version == 1:
            # Legacy v1 PRG: 2x SHA-256 with domain separation.
            h0 = hashlib.sha256(s + b"\x00").digest()
            h1 = hashlib.sha256(s + b"\x01").digest()
            sL, tL = h0[:SEED_BYTES], (h0[-1] & 1)
            sR, tR = h1[:SEED_BYTES], (h1[-1] & 1)
        else:
            sL, tL, sR, tR = _prg(s)
        if t == 1:
            sL = _xor_bytes(sL, cw.s_cw)
            tL ^= cw.t_l
            sR = _xor_bytes(sR, cw.s_cw)
            tR ^= cw.t_r

        xb = (int(x) >> (int(key.domain_bits) - 1 - level)) & 1
        if xb == 0:
            s, t = sL, (tL & 1)
        else:
            s, t = sR, (tR & 1)

    if key.version == 1:
        out = hashlib.sha256(s + b"convert").digest()[0] & 1
    else:
        out = _convert_to_bit(s)
    return (int(out) ^ (int(t) & int(key.cw_last))) & 1


def eval_dpf_pir_parity_share_sparse(*, key_bytes: bytes, ones: Iterable[int], party: int) -> int:
    """
    Sparse PIR evaluation for a bitset DB with few 1-bits.

    If DB[i]=1 only for i in S, then:
        ans_share = XOR_i (DB[i] & f_party(i)) = XOR_{i in S} f_party(i).

    This reduces server work from O(N) to O(|S| log N) when the DB is sparse.
    """
    key = DpfKey.decode(key_bytes)
    if party not in (0, 1):
        raise DpfError("party must be 0/1")
    domain_size = 1 << int(key.domain_bits)
    ans = 0
    for idx in ones:
        i = int(idx)
        if i < 0 or i >= domain_size:
            continue
        ans ^= _eval_dpf_point_decoded(key=key, x=i, party=party) & 1
    return int(ans) & 1


def eval_dpf_pir_parity_share(*, key_bytes: bytes, db_bitset: bytes, party: int) -> int:
    """
    Evaluate the PIR answer share for a bitset DB.

    Returns: ans_share = XOR_i (db[i] & f_party(i)).
    """
    key = DpfKey.decode(key_bytes)
    domain_size = 1 << key.domain_bits
    nbytes = (domain_size + 7) // 8
    if len(db_bitset) != nbytes:
        raise DpfError("db length mismatch (domain_size mismatch)")
    if party not in (0, 1):
        raise DpfError("party must be 0/1")

    ans = 0

    # Stack-based DFS to avoid recursion overhead.
    # Each stack item: (level, seed, t, node_index)
    # node_index is the index in [0, 2^level) for this node; used to derive leaf indices.
    stack: list[tuple[int, bytes, int, int]] = [(0, key.seed0, party, 0)]
    while stack:
        level, s, t, node_idx = stack.pop()
        if level == key.domain_bits:
            if key.version == 1:
                out = hashlib.sha256(s + b"convert").digest()[0] & 1
            else:
                out = _convert_to_bit(s)
            out_bit = (out ^ (t & key.cw_last)) & 1
            if out_bit:
                leaf = node_idx
                b = (db_bitset[leaf // 8] >> (leaf % 8)) & 1
                ans ^= b
            continue

        cw = key.cws[level]
        if key.version == 1:
            h0 = hashlib.sha256(s + b"\x00").digest()
            h1 = hashlib.sha256(s + b"\x01").digest()
            sL, tL = h0[:SEED_BYTES], (h0[-1] & 1)
            sR, tR = h1[:SEED_BYTES], (h1[-1] & 1)
        else:
            sL, tL, sR, tR = _prg(s)
        if t == 1:
            sL = _xor_bytes(sL, cw.s_cw)
            tL ^= cw.t_l
            sR = _xor_bytes(sR, cw.s_cw)
            tR ^= cw.t_r

        # DFS order doesn't matter for parity, but keep deterministic (right then left due to stack pop).
        stack.append((level + 1, sR, tR & 1, (node_idx << 1) | 1))
        stack.append((level + 1, sL, tL & 1, (node_idx << 1) | 0))

    return ans & 1


def eval_dpf_pir_block_share(*, key_bytes: bytes, db_blocks: bytes, block_size: int, party: int) -> bytes:
    """
    Evaluate a *block* PIR answer share.

    DB layout: concatenation of fixed-size blocks:
      DB = DB[0] || DB[1] || ... || DB[N-1], each block_size bytes.

    Returns: ans_share_block = XOR_i ( DB[i] if f_party(i)==1 else 0 ).
    """
    if block_size <= 0 or block_size > 4096:
        raise DpfError("block_size out of supported range")
    key = DpfKey.decode(key_bytes)
    domain_size = 1 << key.domain_bits
    expected = domain_size * block_size
    if len(db_blocks) != expected:
        raise DpfError("db length mismatch (domain_size/block_size mismatch)")
    if party not in (0, 1):
        raise DpfError("party must be 0/1")

    acc = bytearray(b"\x00" * block_size)

    stack: list[tuple[int, bytes, int, int]] = [(0, key.seed0, party, 0)]
    while stack:
        level, s, t, node_idx = stack.pop()
        if level == key.domain_bits:
            if key.version == 1:
                out = hashlib.sha256(s + b"convert").digest()[0] & 1
            else:
                out = _convert_to_bit(s)
            out_bit = (out ^ (t & key.cw_last)) & 1
            if out_bit:
                leaf = node_idx
                off = leaf * block_size
                blk = db_blocks[off : off + block_size]
                for i in range(block_size):
                    acc[i] ^= blk[i]
            continue

        cw = key.cws[level]
        if key.version == 1:
            h0 = hashlib.sha256(s + b"\x00").digest()
            h1 = hashlib.sha256(s + b"\x01").digest()
            sL, tL = h0[:SEED_BYTES], (h0[-1] & 1)
            sR, tR = h1[:SEED_BYTES], (h1[-1] & 1)
        else:
            sL, tL, sR, tR = _prg(s)
        if t == 1:
            sL = _xor_bytes(sL, cw.s_cw)
            tL ^= cw.t_l
            sR = _xor_bytes(sR, cw.s_cw)
            tR ^= cw.t_r

        stack.append((level + 1, sR, tR & 1, (node_idx << 1) | 1))
        stack.append((level + 1, sL, tL & 1, (node_idx << 1) | 0))

    return bytes(acc)
