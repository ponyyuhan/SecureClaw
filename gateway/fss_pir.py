from __future__ import annotations

import base64
import json
import math
import os
import secrets
import threading
import time
import random
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import Future

import requests

from fss.dpf import gen_dpf_keys
from common.uds_http import uds_http_request, uds_post_json
from .http_session import session_for


def _domain_bits(domain_size: int) -> int:
    if domain_size <= 0 or (domain_size & (domain_size - 1)) != 0:
        raise ValueError("domain_size must be a power of two")
    return int(math.log2(domain_size))

_HTTP_POOL = ThreadPoolExecutor(max_workers=8)
_TRACE_LOCK = threading.Lock()

_BIN_MAGIC = b"MPIR"
_BIN_VER = 1
_BIN_MSG_PIR_BATCH = 1
_BIN_MSG_PIR_BATCH_SIGNED = 2
_BIN_MSG_PIR_MULTI_SIGNED = 3


def _pir_bin_enabled() -> bool:
    # Default to binary transport when available; falls back to JSON automatically on error.
    return bool(int(os.getenv("PIR_BINARY_TRANSPORT", "1")))


def _u16(x: int) -> bytes:
    return int(x).to_bytes(2, "little", signed=False)


def _u32(x: int) -> bytes:
    return int(x).to_bytes(4, "little", signed=False)


def _pack_str(buf: bytearray, s: str) -> None:
    b = str(s).encode("utf-8")
    buf.extend(_u32(len(b)))
    buf.extend(b)


def _pack_pir_batch_req(*, msg_type: int, db_name: str, keys: list[bytes], action_id: str | None = None) -> bytes:
    if not keys:
        raise ValueError("empty_keys")
    key_len = len(keys[0])
    if key_len <= 0:
        raise ValueError("bad_key_len")
    for k in keys:
        if len(k) != key_len:
            raise ValueError("nonuniform_key_len")

    buf = bytearray()
    buf.extend(_BIN_MAGIC)
    buf.append(_BIN_VER)
    buf.append(int(msg_type) & 0xFF)
    buf.extend(_u16(0))  # flags
    _pack_str(buf, db_name)
    if action_id is not None:
        _pack_str(buf, action_id)
    buf.extend(_u32(len(keys)))
    buf.extend(_u16(key_len))
    for k in keys:
        buf.extend(k)
    return bytes(buf)


def _pack_pir_multi_signed_req(*, db_name: str, reqs: list[tuple[str, list[bytes]]]) -> bytes:
    if not reqs:
        raise ValueError("empty_subrequests")
    keys_per = len(reqs[0][1] or [])
    if keys_per <= 0:
        raise ValueError("empty_subrequest_keys")
    key_len = len((reqs[0][1] or [b""])[0])
    if key_len <= 0:
        raise ValueError("bad_key_len")
    for _aid, keys in reqs:
        if len(keys) != keys_per:
            raise ValueError("nonuniform_keys_per_subrequest")
        for k in keys:
            if len(k) != key_len:
                raise ValueError("nonuniform_key_len")

    buf = bytearray()
    buf.extend(_BIN_MAGIC)
    buf.append(_BIN_VER)
    buf.append(_BIN_MSG_PIR_MULTI_SIGNED)
    buf.extend(_u16(0))  # flags
    _pack_str(buf, db_name)
    buf.extend(_u32(len(reqs)))
    buf.extend(_u32(keys_per))
    buf.extend(_u16(key_len))
    for aid, keys in reqs:
        _pack_str(buf, aid)
        for k in keys:
            buf.extend(k)
    return bytes(buf)


def _expect_u8(buf: bytes, off: int) -> tuple[int, int]:
    if off + 1 > len(buf):
        raise ValueError("bin_truncated")
    return int(buf[off]), off + 1


def _expect_u16(buf: bytes, off: int) -> tuple[int, int]:
    if off + 2 > len(buf):
        raise ValueError("bin_truncated")
    return int.from_bytes(buf[off : off + 2], "little", signed=False), off + 2


def _expect_u32(buf: bytes, off: int) -> tuple[int, int]:
    if off + 4 > len(buf):
        raise ValueError("bin_truncated")
    return int.from_bytes(buf[off : off + 4], "little", signed=False), off + 4


def _expect_bytes(buf: bytes, off: int, n: int) -> tuple[bytes, int]:
    n = int(n)
    if n < 0 or off + n > len(buf):
        raise ValueError("bin_truncated")
    return bytes(buf[off : off + n]), off + n


def _expect_str(buf: bytes, off: int) -> tuple[str, int]:
    n, off = _expect_u32(buf, off)
    b, off = _expect_bytes(buf, off, n)
    return b.decode("utf-8"), off


def _parse_batch_resp(buf: bytes, *, expect_msg: int) -> list[int]:
    off = 0
    magic, off = _expect_bytes(buf, off, 4)
    if magic != _BIN_MAGIC:
        raise ValueError("bin_bad_magic")
    ver, off = _expect_u8(buf, off)
    if ver != _BIN_VER:
        raise ValueError("bin_bad_version")
    msg, off = _expect_u8(buf, off)
    if int(msg) != int(expect_msg):
        raise ValueError("bin_bad_msg")
    _flags, off = _expect_u16(buf, off)
    n, off = _expect_u32(buf, off)
    ans, off = _expect_bytes(buf, off, n)
    if off != len(buf):
        raise ValueError("bin_extra_bytes")
    return [int(x) & 1 for x in ans]


def _parse_batch_signed_resp(buf: bytes) -> tuple[list[int], dict[str, Any]]:
    off = 0
    magic, off = _expect_bytes(buf, off, 4)
    if magic != _BIN_MAGIC:
        raise ValueError("bin_bad_magic")
    ver, off = _expect_u8(buf, off)
    if ver != _BIN_VER:
        raise ValueError("bin_bad_version")
    msg, off = _expect_u8(buf, off)
    if int(msg) != int(_BIN_MSG_PIR_BATCH_SIGNED):
        raise ValueError("bin_bad_msg")
    _flags, off = _expect_u16(buf, off)
    n, off = _expect_u32(buf, off)
    ans, off = _expect_bytes(buf, off, n)
    proof_n, off = _expect_u32(buf, off)
    proof_b, off = _expect_bytes(buf, off, proof_n)
    if off != len(buf):
        raise ValueError("bin_extra_bytes")
    proof = json.loads(proof_b.decode("utf-8"))
    if not isinstance(proof, dict):
        raise ValueError("bin_bad_proof")
    return [int(x) & 1 for x in ans], dict(proof)


def _parse_multi_signed_resp(buf: bytes) -> dict[str, tuple[list[int], dict[str, Any]]]:
    off = 0
    magic, off = _expect_bytes(buf, off, 4)
    if magic != _BIN_MAGIC:
        raise ValueError("bin_bad_magic")
    ver, off = _expect_u8(buf, off)
    if ver != _BIN_VER:
        raise ValueError("bin_bad_version")
    msg, off = _expect_u8(buf, off)
    if int(msg) != int(_BIN_MSG_PIR_MULTI_SIGNED):
        raise ValueError("bin_bad_msg")
    _flags, off = _expect_u16(buf, off)
    n_sub, off = _expect_u32(buf, off)
    out: dict[str, tuple[list[int], dict[str, Any]]] = {}
    for _ in range(int(n_sub)):
        aid, off = _expect_str(buf, off)
        ans_n, off = _expect_u32(buf, off)
        ans_b, off = _expect_bytes(buf, off, ans_n)
        proof_n, off = _expect_u32(buf, off)
        proof_b, off = _expect_bytes(buf, off, proof_n)
        proof = json.loads(proof_b.decode("utf-8"))
        if not isinstance(proof, dict):
            raise ValueError("bin_bad_proof")
        out[str(aid)] = ([int(x) & 1 for x in ans_b], dict(proof))
    if off != len(buf):
        raise ValueError("bin_extra_bytes")
    return out


def _trace_pir(
    *,
    server_id: int,
    endpoint: str,
    db: str,
    n_keys: int,
    domain_size: int,
    action_id: str | None,
    block_size: int | None = None,
    signed: bool = False,
    n_subreq: int | None = None,
    keys_per_subreq: int | None = None,
) -> None:
    """
    Optional "single policy server transcript" logging for leakage evaluation.

    This logs only metadata visible to the policy server (endpoint, db, batch size),
    not the PIR index itself.
    """
    path = (os.getenv("MIRAGE_TRANSCRIPT_PATH") or os.getenv("PIR_TRANSCRIPT_PATH") or "").strip()
    if not path:
        return
    ev = {
        "ts": int(time.time() * 1000),
        "server_id": int(server_id),
        "endpoint": str(endpoint),
        "db": str(db),
        "n_keys": int(n_keys),
        "domain_size": int(domain_size),
        "signed": bool(signed),
    }
    if n_subreq is not None:
        ev["n_subreq"] = int(n_subreq)
    if keys_per_subreq is not None:
        ev["keys_per_subreq"] = int(keys_per_subreq)
    if action_id:
        ev["action_id"] = str(action_id)
    if block_size is not None:
        ev["block_size"] = int(block_size)
    line = json.dumps(ev, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    with _TRACE_LOCK:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def _uds_or_http_post_octet(
    *,
    uds_path: str | None,
    base_url: str,
    path: str,
    body: bytes,
    timeout_s: int,
    headers: dict[str, str] | None = None,
) -> bytes:
    if uds_path:
        st, _hdrs, resp = uds_http_request(
            uds_path=str(uds_path),
            method="POST",
            path=str(path),
            headers=headers or {},
            body=body,
            timeout_s=float(timeout_s),
        )
        if int(st) != 200:
            raise RuntimeError(f"uds_http_status_{st}")
        return resp
    u = str(base_url).rstrip("/")
    r = session_for(u).post(f"{u}{path}", data=body, headers=headers, timeout=timeout_s)
    r.raise_for_status()
    return bytes(r.content)


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
    r = session_for(u).post(f"{u}{path}", json=obj, timeout=timeout_s)
    r.raise_for_status()
    j = r.json()
    return j if isinstance(j, dict) else {"_resp": j}


@dataclass(frozen=True, slots=True)
class PirClient:
    """
    2-server PIR client using efficient FSS (DPF).

    Communication:
    - client -> each server: O(log N) bytes per query key (DPF key)
    - server -> client: 1 bit share
    """

    policy0_url: str
    policy1_url: str
    domain_size: int
    # Optional UDS (Unix domain socket) transport for same-host deployments.
    # When set, PIR requests are sent over HTTP/1.1 via UDS rather than TCP loopback.
    policy0_uds_path: str | None = None
    policy1_uds_path: str | None = None

    def query_bit(self, db_name: str, idx: int, timeout_s: int = 10, *, domain_size: int | None = None) -> int:
        return self.query_bits(db_name, [idx], timeout_s=timeout_s, domain_size=domain_size)[0]

    def query_bits(self, db_name: str, idxs: Iterable[int], timeout_s: int = 10, *, domain_size: int | None = None) -> List[int]:
        idx_list = list(idxs)
        if not idx_list:
            return []

        ds = int(domain_size or self.domain_size)
        nbits = _domain_bits(ds)
        keys0: list[str] = []
        keys1: list[str] = []
        keys0_raw: list[bytes] = []
        keys1_raw: list[bytes] = []
        for idx in idx_list:
            if idx < 0 or idx >= ds:
                raise ValueError("idx out of range")
            k0, k1 = gen_dpf_keys(alpha=idx, beta=1, domain_bits=nbits)
            keys0_raw.append(k0)
            keys1_raw.append(k1)
            keys0.append(base64.b64encode(k0).decode("ascii"))
            keys1.append(base64.b64encode(k1).decode("ascii"))

        payload0 = {"db": db_name, "dpf_keys_b64": keys0}
        payload1 = {"db": db_name, "dpf_keys_b64": keys1}

        _trace_pir(server_id=0, endpoint="/pir/query_batch", db=db_name, n_keys=len(keys0), domain_size=ds, action_id=None, signed=False)
        _trace_pir(server_id=1, endpoint="/pir/query_batch", db=db_name, n_keys=len(keys1), domain_size=ds, action_id=None, signed=False)

        u0 = str(self.policy0_url).rstrip("/")
        u1 = str(self.policy1_url).rstrip("/")
        a0: list[int] | None = None
        a1: list[int] | None = None
        if _pir_bin_enabled():
            try:
                b0 = _pack_pir_batch_req(msg_type=_BIN_MSG_PIR_BATCH, db_name=db_name, keys=keys0_raw)
                b1 = _pack_pir_batch_req(msg_type=_BIN_MSG_PIR_BATCH, db_name=db_name, keys=keys1_raw)
                h = {"content-type": "application/octet-stream"}
                f0 = _HTTP_POOL.submit(
                    _uds_or_http_post_octet,
                    uds_path=self.policy0_uds_path,
                    base_url=u0,
                    path="/pir/query_batch_bin",
                    body=b0,
                    timeout_s=timeout_s,
                    headers=h,
                )
                f1 = _HTTP_POOL.submit(
                    _uds_or_http_post_octet,
                    uds_path=self.policy1_uds_path,
                    base_url=u1,
                    path="/pir/query_batch_bin",
                    body=b1,
                    timeout_s=timeout_s,
                    headers=h,
                )
                a0 = _parse_batch_resp(f0.result(), expect_msg=_BIN_MSG_PIR_BATCH)
                a1 = _parse_batch_resp(f1.result(), expect_msg=_BIN_MSG_PIR_BATCH)
            except Exception:
                a0 = None
                a1 = None
        if a0 is None or a1 is None:
            f0 = _HTTP_POOL.submit(
                _uds_or_http_post_json,
                uds_path=self.policy0_uds_path,
                base_url=u0,
                path="/pir/query_batch",
                obj=payload0,
                timeout_s=timeout_s,
            )
            f1 = _HTTP_POOL.submit(
                _uds_or_http_post_json,
                uds_path=self.policy1_uds_path,
                base_url=u1,
                path="/pir/query_batch",
                obj=payload1,
                timeout_s=timeout_s,
            )
            j0 = f0.result()
            j1 = f1.result()
            a0 = [int(x) & 1 for x in (j0.get("ans_shares") or [])]
            a1 = [int(x) & 1 for x in (j1.get("ans_shares") or [])]
        if len(a0) != len(idx_list) or len(a1) != len(idx_list):
            raise ValueError("policy server returned wrong batch size")
        return [(x ^ y) & 1 for x, y in zip(a0, a1)]

    def query_block(self, db_name: str, idx: int, *, block_size: int, timeout_s: int = 10, domain_size: int | None = None) -> bytes:
        return self.query_blocks(db_name, [idx], block_size=block_size, timeout_s=timeout_s, domain_size=domain_size)[0]

    def query_blocks(self, db_name: str, idxs: Iterable[int], *, block_size: int, timeout_s: int = 10, domain_size: int | None = None) -> List[bytes]:
        idx_list = list(idxs)
        if not idx_list:
            return []
        if block_size <= 0 or block_size > 4096:
            raise ValueError("bad block_size")

        ds = int(domain_size or self.domain_size)
        nbits = _domain_bits(ds)
        keys0: list[str] = []
        keys1: list[str] = []
        for idx in idx_list:
            if idx < 0 or idx >= ds:
                raise ValueError("idx out of range")
            k0, k1 = gen_dpf_keys(alpha=idx, beta=1, domain_bits=nbits)
            keys0.append(base64.b64encode(k0).decode("ascii"))
            keys1.append(base64.b64encode(k1).decode("ascii"))

        payload0 = {"db": db_name, "dpf_keys_b64": keys0}
        payload1 = {"db": db_name, "dpf_keys_b64": keys1}

        _trace_pir(server_id=0, endpoint="/pir/query_block_batch", db=db_name, n_keys=len(keys0), domain_size=ds, action_id=None, block_size=block_size, signed=False)
        _trace_pir(server_id=1, endpoint="/pir/query_block_batch", db=db_name, n_keys=len(keys1), domain_size=ds, action_id=None, block_size=block_size, signed=False)

        u0 = str(self.policy0_url).rstrip("/")
        u1 = str(self.policy1_url).rstrip("/")
        f0 = _HTTP_POOL.submit(
            _uds_or_http_post_json,
            uds_path=self.policy0_uds_path,
            base_url=u0,
            path="/pir/query_block_batch",
            obj=payload0,
            timeout_s=timeout_s,
        )
        f1 = _HTTP_POOL.submit(
            _uds_or_http_post_json,
            uds_path=self.policy1_uds_path,
            base_url=u1,
            path="/pir/query_block_batch",
            obj=payload1,
            timeout_s=timeout_s,
        )
        j0 = f0.result()
        j1 = f1.result()

        s0 = [base64.b64decode(x) for x in (j0.get("block_shares_b64") or [])]
        s1 = [base64.b64decode(x) for x in (j1.get("block_shares_b64") or [])]
        if len(s0) != len(idx_list) or len(s1) != len(idx_list):
            raise ValueError("policy server returned wrong batch size")
        out: list[bytes] = []
        for b0, b1 in zip(s0, s1):
            if len(b0) != block_size or len(b1) != block_size:
                raise ValueError("policy server returned wrong block size")
            out.append(bytes([x ^ y for x, y in zip(b0, b1)]))
        return out

    def query_bits_signed(self, db_name: str, idxs: Iterable[int], *, action_id: str, timeout_s: int = 10, domain_size: int | None = None) -> Tuple[List[int], Dict[str, Any]]:
        """
        Like query_bits, but also returns per-server MAC proofs so an executor can verify
        that both policy servers participated.
        """
        idx_list = list(idxs)
        if not idx_list:
            return [], {"policy0": None, "policy1": None}

        ds = int(domain_size or self.domain_size)
        nbits = _domain_bits(ds)
        keys0: list[str] = []
        keys1: list[str] = []
        keys0_raw: list[bytes] = []
        keys1_raw: list[bytes] = []
        for idx in idx_list:
            if idx < 0 or idx >= ds:
                raise ValueError("idx out of range")
            k0, k1 = gen_dpf_keys(alpha=idx, beta=1, domain_bits=nbits)
            keys0_raw.append(k0)
            keys1_raw.append(k1)
            keys0.append(base64.b64encode(k0).decode("ascii"))
            keys1.append(base64.b64encode(k1).decode("ascii"))

        payload0 = {"db": db_name, "dpf_keys_b64": keys0, "action_id": action_id}
        payload1 = {"db": db_name, "dpf_keys_b64": keys1, "action_id": action_id}

        _trace_pir(server_id=0, endpoint="/pir/query_batch_signed", db=db_name, n_keys=len(keys0), domain_size=ds, action_id=action_id, signed=True)
        _trace_pir(server_id=1, endpoint="/pir/query_batch_signed", db=db_name, n_keys=len(keys1), domain_size=ds, action_id=action_id, signed=True)

        u0 = str(self.policy0_url).rstrip("/")
        u1 = str(self.policy1_url).rstrip("/")
        j0: dict[str, Any] | None = None
        j1: dict[str, Any] | None = None
        if _pir_bin_enabled():
            try:
                b0 = _pack_pir_batch_req(msg_type=_BIN_MSG_PIR_BATCH_SIGNED, db_name=db_name, keys=keys0_raw, action_id=action_id)
                b1 = _pack_pir_batch_req(msg_type=_BIN_MSG_PIR_BATCH_SIGNED, db_name=db_name, keys=keys1_raw, action_id=action_id)
                h = {"content-type": "application/octet-stream"}
                f0 = _HTTP_POOL.submit(
                    _uds_or_http_post_octet,
                    uds_path=self.policy0_uds_path,
                    base_url=u0,
                    path="/pir/query_batch_signed_bin",
                    body=b0,
                    timeout_s=timeout_s,
                    headers=h,
                )
                f1 = _HTTP_POOL.submit(
                    _uds_or_http_post_octet,
                    uds_path=self.policy1_uds_path,
                    base_url=u1,
                    path="/pir/query_batch_signed_bin",
                    body=b1,
                    timeout_s=timeout_s,
                    headers=h,
                )
                a0_bin, p0_bin = _parse_batch_signed_resp(f0.result())
                a1_bin, p1_bin = _parse_batch_signed_resp(f1.result())
                j0 = {"ans_shares": a0_bin, "proof": p0_bin}
                j1 = {"ans_shares": a1_bin, "proof": p1_bin}
            except Exception:
                j0 = None
                j1 = None
        if j0 is None or j1 is None:
            f0 = _HTTP_POOL.submit(
                _uds_or_http_post_json,
                uds_path=self.policy0_uds_path,
                base_url=u0,
                path="/pir/query_batch_signed",
                obj=payload0,
                timeout_s=timeout_s,
            )
            f1 = _HTTP_POOL.submit(
                _uds_or_http_post_json,
                uds_path=self.policy1_uds_path,
                base_url=u1,
                path="/pir/query_batch_signed",
                obj=payload1,
                timeout_s=timeout_s,
            )
            j0 = f0.result()
            j1 = f1.result()

        a0 = [int(x) & 1 for x in j0.get("ans_shares", [])]
        a1 = [int(x) & 1 for x in j1.get("ans_shares", [])]
        if len(a0) != len(idx_list) or len(a1) != len(idx_list):
            raise ValueError("policy server returned wrong batch size")
        recon = [(x ^ y) & 1 for x, y in zip(a0, a1)]
        proof = {"policy0": j0.get("proof"), "policy1": j1.get("proof"), "a0": a0, "a1": a1, "db": db_name, "action_id": action_id}
        return recon, proof

    def query_blocks_signed(self, db_name: str, idxs: Iterable[int], *, block_size: int, action_id: str, timeout_s: int = 10, domain_size: int | None = None) -> Tuple[List[bytes], Dict[str, Any]]:
        idx_list = list(idxs)
        if not idx_list:
            return [], {"policy0": None, "policy1": None}
        if block_size <= 0 or block_size > 4096:
            raise ValueError("bad block_size")

        ds = int(domain_size or self.domain_size)
        nbits = _domain_bits(ds)
        keys0: list[str] = []
        keys1: list[str] = []
        for idx in idx_list:
            if idx < 0 or idx >= ds:
                raise ValueError("idx out of range")
            k0, k1 = gen_dpf_keys(alpha=idx, beta=1, domain_bits=nbits)
            keys0.append(base64.b64encode(k0).decode("ascii"))
            keys1.append(base64.b64encode(k1).decode("ascii"))

        payload0 = {"db": db_name, "dpf_keys_b64": keys0, "action_id": action_id}
        payload1 = {"db": db_name, "dpf_keys_b64": keys1, "action_id": action_id}

        _trace_pir(server_id=0, endpoint="/pir/query_block_batch_signed", db=db_name, n_keys=len(keys0), domain_size=ds, action_id=action_id, block_size=block_size, signed=True)
        _trace_pir(server_id=1, endpoint="/pir/query_block_batch_signed", db=db_name, n_keys=len(keys1), domain_size=ds, action_id=action_id, block_size=block_size, signed=True)

        u0 = str(self.policy0_url).rstrip("/")
        u1 = str(self.policy1_url).rstrip("/")
        f0 = _HTTP_POOL.submit(
            _uds_or_http_post_json,
            uds_path=self.policy0_uds_path,
            base_url=u0,
            path="/pir/query_block_batch_signed",
            obj=payload0,
            timeout_s=timeout_s,
        )
        f1 = _HTTP_POOL.submit(
            _uds_or_http_post_json,
            uds_path=self.policy1_uds_path,
            base_url=u1,
            path="/pir/query_block_batch_signed",
            obj=payload1,
            timeout_s=timeout_s,
        )
        j0 = f0.result()
        j1 = f1.result()
        s0 = [base64.b64decode(x) for x in (j0.get("block_shares_b64") or [])]
        s1 = [base64.b64decode(x) for x in (j1.get("block_shares_b64") or [])]
        if len(s0) != len(idx_list) or len(s1) != len(idx_list):
            raise ValueError("policy server returned wrong batch size")
        out: list[bytes] = []
        for b0, b1 in zip(s0, s1):
            if len(b0) != block_size or len(b1) != block_size:
                raise ValueError("policy server returned wrong block size")
            out.append(bytes([x ^ y for x, y in zip(b0, b1)]))
        proof = {"policy0": j0.get("proof"), "policy1": j1.get("proof"), "s0_b64": j0.get("block_shares_b64"), "s1_b64": j1.get("block_shares_b64"), "db": db_name, "action_id": action_id, "block_size": block_size}
        return out, proof

    def query_bits_single_server_cleartext(
        self,
        db_name: str,
        idxs: Iterable[int],
        *,
        server_id: int = 0,
        timeout_s: int = 10,
        domain_size: int | None = None,
    ) -> list[int]:
        """
        Baseline-only single-server cleartext query.

        WARNING: this leaks plaintext indices to one policy server and should never
        be used in the full MIRAGE mode.
        """
        idx_list = [int(x) for x in idxs]
        if not idx_list:
            return []
        ds = int(domain_size or self.domain_size)
        for idx in idx_list:
            if idx < 0 or idx >= ds:
                raise ValueError("idx out of range")
        url = self.policy0_url if int(server_id) == 0 else self.policy1_url
        _trace_pir(
            server_id=int(server_id),
            endpoint="/pir/query_idx_batch",
            db=db_name,
            n_keys=len(idx_list),
            domain_size=ds,
            action_id=None,
            signed=False,
        )
        uds = self.policy0_uds_path if int(server_id) == 0 else self.policy1_uds_path
        u = str(url).rstrip("/")
        j = _uds_or_http_post_json(
            uds_path=uds,
            base_url=u,
            path="/pir/query_idx_batch",
            obj={"db": db_name, "idxs": idx_list},
            timeout_s=timeout_s,
        )
        bits = [int(x) & 1 for x in (j.get("ans_bits") or [])]
        if len(bits) != len(idx_list):
            raise ValueError("policy server returned wrong batch size")
        return bits

    def query_bits_single_server_cleartext_signed(
        self,
        db_name: str,
        idxs: Iterable[int],
        *,
        action_id: str,
        server_id: int = 0,
        timeout_s: int = 10,
        domain_size: int | None = None,
    ) -> tuple[list[int], dict[str, Any]]:
        """
        Signed variant of the single-server cleartext baseline query.
        """
        idx_list = [int(x) for x in idxs]
        if not idx_list:
            return [], {"policy0": None, "policy1": None}
        ds = int(domain_size or self.domain_size)
        for idx in idx_list:
            if idx < 0 or idx >= ds:
                raise ValueError("idx out of range")
        url = self.policy0_url if int(server_id) == 0 else self.policy1_url
        sid = int(server_id)
        _trace_pir(
            server_id=sid,
            endpoint="/pir/query_idx_batch_signed",
            db=db_name,
            n_keys=len(idx_list),
            domain_size=ds,
            action_id=action_id,
            signed=True,
        )
        u = str(url).rstrip("/")
        uds = self.policy0_uds_path if sid == 0 else self.policy1_uds_path
        j = _uds_or_http_post_json(
            uds_path=uds,
            base_url=u,
            path="/pir/query_idx_batch_signed",
            obj={"db": db_name, "idxs": idx_list, "action_id": str(action_id)},
            timeout_s=timeout_s,
        )
        bits = [int(x) & 1 for x in (j.get("ans_bits") or [])]
        if len(bits) != len(idx_list):
            raise ValueError("policy server returned wrong batch size")
        zeros = [0 for _ in bits]
        if sid == 0:
            proof = {
                "policy0": j.get("proof"),
                "policy1": None,
                "a0": bits,
                "a1": zeros,
                "db": db_name,
                "action_id": action_id,
                "baseline_mode": "single_server_cleartext",
            }
        else:
            proof = {
                "policy0": None,
                "policy1": j.get("proof"),
                "a0": zeros,
                "a1": bits,
                "db": db_name,
                "action_id": action_id,
                "baseline_mode": "single_server_cleartext",
            }
        return bits, proof


@dataclass(frozen=True, slots=True)
class PirMixConfig:
    """
    Gateway-side PIR microbatching / cover-traffic configuration.

    The mixer is intentionally narrow: it batches *signed bitset* PIR queries
    (`/pir/query_batch_multi_signed`) for a single `db_name` with a fixed
    number of keys per subrequest (constant-shape).
    """

    enabled: bool
    interval_ms: int
    pad_to: int
    fixed_n_keys: int
    db_name: str
    domain_size: int
    timeout_s: int = 10
    cover_traffic: bool = True
    lanes: int = 1
    max_inflight: int = 1
    schedule_mode: str = "fixed"  # fixed | eager


class _SignedBitBatchMixer:
    def __init__(
        self,
        *,
        policy0_url: str,
        policy1_url: str,
        cfg: PirMixConfig,
        policy0_uds_path: str | None = None,
        policy1_uds_path: str | None = None,
    ) -> None:
        self.policy0_url = str(policy0_url)
        self.policy1_url = str(policy1_url)
        self.policy0_uds_path = (str(policy0_uds_path).strip() if policy0_uds_path else "") or None
        self.policy1_uds_path = (str(policy1_uds_path).strip() if policy1_uds_path else "") or None
        self.cfg = cfg
        self._lock = threading.Lock()
        self._pending: list[tuple[str, list[str], list[str], Future]] = []
        self._inflight = 0
        self._stop = threading.Event()
        self._wakeup = threading.Event()
        lanes = int(getattr(cfg, "lanes", 1) or 1)
        if lanes < 1:
            lanes = 1
        if lanes > 32:
            lanes = 32
        self._lanes = lanes
        self._threads: list[threading.Thread] = []
        for i in range(lanes):
            t = threading.Thread(target=self._run_lane, args=(i,), name=f"pir-mixer-{i}", daemon=True)
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

    def submit(self, *, action_id: str, keys0_b64: list[str], keys1_b64: list[str]) -> Future:
        fut: Future = Future()
        if len(keys0_b64) != len(keys1_b64):
            fut.set_exception(ValueError("bad_key_share_lengths"))
            return fut
        if int(len(keys0_b64)) != int(self.cfg.fixed_n_keys):
            fut.set_exception(ValueError("bad_fixed_shape_n_keys"))
            return fut
        with self._lock:
            self._pending.append((str(action_id), list(keys0_b64), list(keys1_b64), fut))
        # Wake scheduler lanes and, in eager-ish modes, dispatch immediately to avoid
        # adding the full tick interval of queuing latency under low load.
        self._wakeup.set()
        mode = str(getattr(self.cfg, "schedule_mode", "fixed") or "fixed").strip().lower()
        if mode in ("eager", "on_demand", "ondemand"):
            try:
                self._dispatch_tick()
            except Exception:
                pass
        return fut

    def _mk_dummy_req(self) -> tuple[str, list[str], list[str]]:
        # Dummy subrequest: random action_id + random index keys. Indistinguishable
        # from real subrequests under DPF security (keys hide indices).
        # Keep the same action_id *shape* as real requests (e.g., "a_<urlsafe>") so
        # the policy servers cannot trivially distinguish cover vs real by prefix.
        action_id = f"a_{secrets.token_urlsafe(12)}"
        ds = int(self.cfg.domain_size)
        nbits = _domain_bits(ds)
        keys0: list[str] = []
        keys1: list[str] = []
        for _ in range(int(self.cfg.fixed_n_keys)):
            idx = int.from_bytes(os.urandom(4), "little") % ds
            k0, k1 = gen_dpf_keys(alpha=idx, beta=1, domain_bits=nbits)
            keys0.append(base64.b64encode(k0).decode("ascii"))
            keys1.append(base64.b64encode(k1).decode("ascii"))
        return action_id, keys0, keys1

    def _dispatch_tick(self) -> None:
        cfg = self.cfg
        batch: list[tuple[str, list[str], list[str], Future]] = []
        with self._lock:
            if int(getattr(self, "_inflight", 0)) >= int(getattr(cfg, "max_inflight", 1) or 1):
                return
            if self._pending:
                take = min(int(cfg.pad_to), len(self._pending))
                batch = self._pending[:take]
                self._pending = self._pending[take:]

        # If there are no real subrequests, still emit cover traffic if enabled.
        if not batch and not bool(cfg.cover_traffic):
            return

        # Pad with dummy subrequests up to pad_to.
        pad_to = int(cfg.pad_to)
        req0: list[dict[str, Any]] = []
        req1: list[dict[str, Any]] = []

        for action_id, k0s, k1s, _f in batch:
            req0.append({"action_id": str(action_id), "dpf_keys_b64": list(k0s)})
            req1.append({"action_id": str(action_id), "dpf_keys_b64": list(k1s)})
        while len(req0) < pad_to:
            aid, k0s, k1s = self._mk_dummy_req()
            req0.append({"action_id": aid, "dpf_keys_b64": k0s})
            req1.append({"action_id": aid, "dpf_keys_b64": k1s})

        # Shuffle subrequests so "real-first" ordering does not leak at a single server.
        # (action_id is already random-looking, but this makes the transcript cleaner.)
        perm = list(range(len(req0)))
        random.shuffle(perm)
        req0 = [req0[i] for i in perm]
        req1 = [req1[i] for i in perm]

        payload0 = {"db": str(cfg.db_name), "requests": req0}
        payload1 = {"db": str(cfg.db_name), "requests": req1}

        total_keys = int(len(req0)) * int(cfg.fixed_n_keys)
        _trace_pir(
            server_id=0,
            endpoint="/pir/query_batch_multi_signed",
            db=str(cfg.db_name),
            n_keys=total_keys,
            domain_size=int(cfg.domain_size),
            action_id=None,
            signed=True,
            n_subreq=int(len(req0)),
            keys_per_subreq=int(cfg.fixed_n_keys),
        )
        _trace_pir(
            server_id=1,
            endpoint="/pir/query_batch_multi_signed",
            db=str(cfg.db_name),
            n_keys=total_keys,
            domain_size=int(cfg.domain_size),
            action_id=None,
            signed=True,
            n_subreq=int(len(req0)),
            keys_per_subreq=int(cfg.fixed_n_keys),
        )

        with self._lock:
            self._inflight = int(getattr(self, "_inflight", 0)) + 1
        _HTTP_POOL.submit(self._do_call, payload0, payload1, batch)

    def _flush_once(self) -> None:
        """
        Synchronous flush helper (unit-test friendly).

        Production traffic shaping uses the lane schedulers + async dispatch in
        `_dispatch_tick`; tests call `_flush_once()` directly to validate
        constant-shape padding behavior without background threads.
        """
        cfg = self.cfg
        batch: list[tuple[str, list[str], list[str], Future]] = []
        with self._lock:
            if self._pending:
                take = min(int(cfg.pad_to), len(self._pending))
                batch = self._pending[:take]
                self._pending = self._pending[take:]

        if not batch and not bool(cfg.cover_traffic):
            return

        pad_to = int(cfg.pad_to)
        req0: list[dict[str, Any]] = []
        req1: list[dict[str, Any]] = []
        for action_id, k0s, k1s, _f in batch:
            req0.append({"action_id": str(action_id), "dpf_keys_b64": list(k0s)})
            req1.append({"action_id": str(action_id), "dpf_keys_b64": list(k1s)})
        while len(req0) < pad_to:
            aid, k0s, k1s = self._mk_dummy_req()
            req0.append({"action_id": aid, "dpf_keys_b64": k0s})
            req1.append({"action_id": aid, "dpf_keys_b64": k1s})

        perm = list(range(len(req0)))
        random.shuffle(perm)
        req0 = [req0[i] for i in perm]
        req1 = [req1[i] for i in perm]

        payload0 = {"db": str(cfg.db_name), "requests": req0}
        payload1 = {"db": str(cfg.db_name), "requests": req1}
        self._do_call(payload0, payload1, batch)

    def _do_call(self, payload0: dict[str, Any], payload1: dict[str, Any], batch: list[tuple[str, list[str], list[str], Future]]) -> None:
        cfg = self.cfg
        u0 = str(self.policy0_url).rstrip("/")
        u1 = str(self.policy1_url).rstrip("/")
        # Unit tests sometimes construct mixers via __new__ (to avoid background threads) and
        # don't populate UDS attributes. Default to HTTP-only in that case.
        uds0 = (str(getattr(self, "policy0_uds_path", "") or "").strip() or None)
        uds1 = (str(getattr(self, "policy1_uds_path", "") or "").strip() or None)
        m0: dict[str, tuple[list[int], dict[str, Any]]] | None = None
        m1: dict[str, tuple[list[int], dict[str, Any]]] | None = None
        try:
            if _pir_bin_enabled():
                try:
                    reqs0_raw: list[tuple[str, list[bytes]]] = []
                    reqs1_raw: list[tuple[str, list[bytes]]] = []
                    for sub0, sub1 in zip((payload0.get("requests") or []), (payload1.get("requests") or [])):
                        if not isinstance(sub0, dict) or not isinstance(sub1, dict):
                            raise ValueError("bad_subrequest_shape")
                        aid0 = str(sub0.get("action_id") or "")
                        aid1 = str(sub1.get("action_id") or "")
                        if aid0 != aid1:
                            raise ValueError("action_id_mismatch")
                        ks0 = [base64.b64decode(str(x)) for x in (sub0.get("dpf_keys_b64") or [])]
                        ks1 = [base64.b64decode(str(x)) for x in (sub1.get("dpf_keys_b64") or [])]
                        reqs0_raw.append((aid0, ks0))
                        reqs1_raw.append((aid0, ks1))
                    b0 = _pack_pir_multi_signed_req(db_name=str(cfg.db_name), reqs=reqs0_raw)
                    b1 = _pack_pir_multi_signed_req(db_name=str(cfg.db_name), reqs=reqs1_raw)
                    h = {"content-type": "application/octet-stream"}
                    f0 = _HTTP_POOL.submit(
                        _uds_or_http_post_octet,
                        uds_path=uds0,
                        base_url=u0,
                        path="/pir/query_batch_multi_signed_bin",
                        body=b0,
                        timeout_s=int(cfg.timeout_s),
                        headers=h,
                    )
                    f1 = _HTTP_POOL.submit(
                        _uds_or_http_post_octet,
                        uds_path=uds1,
                        base_url=u1,
                        path="/pir/query_batch_multi_signed_bin",
                        body=b1,
                        timeout_s=int(cfg.timeout_s),
                        headers=h,
                    )
                    m0 = _parse_multi_signed_resp(f0.result())
                    m1 = _parse_multi_signed_resp(f1.result())
                except Exception:
                    m0 = None
                    m1 = None

            if m0 is None or m1 is None:
                f0 = _HTTP_POOL.submit(
                    _uds_or_http_post_json,
                    uds_path=uds0,
                    base_url=u0,
                    path="/pir/query_batch_multi_signed",
                    obj=payload0,
                    timeout_s=int(cfg.timeout_s),
                )
                f1 = _HTTP_POOL.submit(
                    _uds_or_http_post_json,
                    uds_path=uds1,
                    base_url=u1,
                    path="/pir/query_batch_multi_signed",
                    obj=payload1,
                    timeout_s=int(cfg.timeout_s),
                )
                j0 = f0.result()
                j1 = f1.result()
                m0 = {}
                m1 = {}
                for it in (j0.get("responses") or []):
                    if not isinstance(it, dict):
                        continue
                    aid = str(it.get("action_id") or "")
                    if not aid:
                        continue
                    a = [int(x) & 1 for x in (it.get("ans_shares") or [])]
                    pr = it.get("proof")
                    m0[aid] = (a, pr if isinstance(pr, dict) else {})
                for it in (j1.get("responses") or []):
                    if not isinstance(it, dict):
                        continue
                    aid = str(it.get("action_id") or "")
                    if not aid:
                        continue
                    a = [int(x) & 1 for x in (it.get("ans_shares") or [])]
                    pr = it.get("proof")
                    m1[aid] = (a, pr if isinstance(pr, dict) else {})
        except Exception as e:
            for _aid, _k0, _k1, fut in batch:
                try:
                    fut.set_exception(e)
                except Exception:
                    pass
            return
        finally:
            with self._lock:
                if hasattr(self, "_inflight"):
                    self._inflight = max(0, int(getattr(self, "_inflight", 0)) - 1)
        if m0 is None or m1 is None:
            for _aid, _k0, _k1, fut in batch:
                try:
                    fut.set_exception(RuntimeError("pir_mixer_no_response_map"))
                except Exception:
                    pass
            return

        for aid, _k0, _k1, fut in batch:
            try:
                a0, p0 = m0.get(str(aid), (None, None))  # type: ignore[assignment]
                a1, p1 = m1.get(str(aid), (None, None))  # type: ignore[assignment]
                if not isinstance(a0, list) or not isinstance(a1, list) or len(a0) != len(a1):
                    raise ValueError("bad_policy_server_batch_response")
                recon = [(int(x) ^ int(y)) & 1 for x, y in zip(a0, a1)]
                ev = {
                    "policy0": p0,
                    "policy1": p1,
                    "a0": a0,
                    "a1": a1,
                    "db": str(cfg.db_name),
                    "action_id": str(aid),
                    "mixed": True,
                }
                fut.set_result((recon, ev))
            except Exception as e:
                try:
                    fut.set_exception(e)
                except Exception:
                    pass

    def _run_lane(self, lane: int) -> None:
        interval_s = max(0.001, float(self.cfg.interval_ms) / 1000.0)
        # Stagger lanes to reduce burstiness.
        if self._lanes > 1:
            self._stop.wait(timeout=(interval_s * float(int(lane) % int(self._lanes)) / float(self._lanes)))
        while not self._stop.is_set():
            t0 = time.perf_counter()
            self._dispatch_tick()
            dt = time.perf_counter() - t0
            # Optional eager mode: when queue is full, don't artificially wait.
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
                # Wait until the next tick, but wake early when new real work arrives.
                self._wakeup.wait(timeout=sleep_s)
                self._wakeup.clear()


class MixedPirClient:
    """
    PirClient wrapper that optionally enables cover-traffic + microbatch mixing for
    signed bitset queries.
    """

    def __init__(self, base: PirClient, *, mix: PirMixConfig | None = None) -> None:
        self._base = base
        self.domain_size = int(base.domain_size)
        self._mix_cfg = mix
        self._mixer: _SignedBitBatchMixer | None = None
        if mix and mix.enabled:
            self._mixer = _SignedBitBatchMixer(
                policy0_url=base.policy0_url,
                policy1_url=base.policy1_url,
                cfg=mix,
                policy0_uds_path=getattr(base, "policy0_uds_path", None),
                policy1_uds_path=getattr(base, "policy1_uds_path", None),
            )

    @property
    def policy0_url(self) -> str:
        return self._base.policy0_url

    @property
    def policy1_url(self) -> str:
        return self._base.policy1_url

    def close(self) -> None:
        if self._mixer:
            self._mixer.close()

    # Delegate non-mixed APIs.
    def query_bit(self, db_name: str, idx: int, timeout_s: int = 10, *, domain_size: int | None = None) -> int:
        return self._base.query_bit(db_name, idx, timeout_s=timeout_s, domain_size=domain_size)

    def query_bits(self, db_name: str, idxs: Iterable[int], timeout_s: int = 10, *, domain_size: int | None = None) -> List[int]:
        return self._base.query_bits(db_name, idxs, timeout_s=timeout_s, domain_size=domain_size)

    def query_block(self, db_name: str, idx: int, *, block_size: int, timeout_s: int = 10, domain_size: int | None = None) -> bytes:
        return self._base.query_block(db_name, idx, block_size=block_size, timeout_s=timeout_s, domain_size=domain_size)

    def query_blocks(self, db_name: str, idxs: Iterable[int], *, block_size: int, timeout_s: int = 10, domain_size: int | None = None) -> List[bytes]:
        return self._base.query_blocks(db_name, idxs, block_size=block_size, timeout_s=timeout_s, domain_size=domain_size)

    def query_blocks_signed(
        self,
        db_name: str,
        idxs: Iterable[int],
        *,
        block_size: int,
        action_id: str,
        timeout_s: int = 10,
        domain_size: int | None = None,
    ) -> Tuple[List[bytes], Dict[str, Any]]:
        return self._base.query_blocks_signed(db_name, idxs, block_size=block_size, action_id=action_id, timeout_s=timeout_s, domain_size=domain_size)

    def query_bits_single_server_cleartext_signed(
        self,
        db_name: str,
        idxs: Iterable[int],
        *,
        action_id: str,
        server_id: int = 0,
        timeout_s: int = 10,
        domain_size: int | None = None,
    ) -> tuple[list[int], dict[str, Any]]:
        return self._base.query_bits_single_server_cleartext_signed(
            db_name,
            idxs,
            action_id=action_id,
            server_id=server_id,
            timeout_s=timeout_s,
            domain_size=domain_size,
        )

    def query_bits_signed(
        self,
        db_name: str,
        idxs: Iterable[int],
        *,
        action_id: str,
        timeout_s: int = 10,
        domain_size: int | None = None,
    ) -> Tuple[List[int], Dict[str, Any]]:
        # If mixing isn't enabled (or db doesn't match), fall back to direct.
        mix = self._mix_cfg
        if not self._mixer or not mix or not mix.enabled:
            return self._base.query_bits_signed(db_name, idxs, action_id=action_id, timeout_s=timeout_s, domain_size=domain_size)
        if str(db_name) != str(mix.db_name):
            return self._base.query_bits_signed(db_name, idxs, action_id=action_id, timeout_s=timeout_s, domain_size=domain_size)

        idx_list = list(idxs)
        if not idx_list:
            return [], {"policy0": None, "policy1": None}
        ds = int(domain_size or mix.domain_size)
        if int(ds) != int(mix.domain_size):
            raise ValueError("mixed_pir_domain_size_mismatch")
        nbits = _domain_bits(ds)
        keys0: list[str] = []
        keys1: list[str] = []
        for idx in idx_list:
            if idx < 0 or idx >= ds:
                raise ValueError("idx out of range")
            k0, k1 = gen_dpf_keys(alpha=int(idx), beta=1, domain_bits=nbits)
            keys0.append(base64.b64encode(k0).decode("ascii"))
            keys1.append(base64.b64encode(k1).decode("ascii"))

        fut = self._mixer.submit(action_id=str(action_id), keys0_b64=keys0, keys1_b64=keys1)
        recon, ev = fut.result(timeout=max(1.0, float(timeout_s) + 5.0))
        return list(recon), dict(ev or {})
