import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI
from pydantic import BaseModel, Field
from pathlib import Path
import os
import json
import base64
import hashlib
import hmac
import time
from .config import settings
from .db import BitsetDB
from .mpc_engine import Gate, MpcSession, MpcSessionStore

db = BitsetDB(settings.data_dir)
mpc_store = MpcSessionStore()

@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.load()
    yield

app = FastAPI(title=f"PolicyServer{settings.server_id}", version="0.1", lifespan=lifespan)

class PirQuery(BaseModel):
    db: str
    dpf_key_b64: str = Field(..., description="DPF/FSS key share (base64).")


class PirQueryBatch(BaseModel):
    db: str
    dpf_keys_b64: list[str]


class PirQueryBatchSigned(PirQueryBatch):
    action_id: str = Field(..., description="Opaque action identifier (bound into the MAC).")

class PirQueryBatchSubReq(BaseModel):
    action_id: str = Field(..., description="Opaque action identifier (bound into the MAC).")
    dpf_keys_b64: list[str]


class PirQueryBatchMultiSigned(BaseModel):
    db: str
    requests: list[PirQueryBatchSubReq] = Field(default_factory=list)


class PirIdxBatch(BaseModel):
    db: str
    idxs: list[int]


class PirIdxBatchSigned(PirIdxBatch):
    action_id: str = Field(..., description="Opaque action identifier (bound into the MAC).")

class MpcGate(BaseModel):
    op: str
    out: int
    a: int | None = None
    b: int | None = None
    value: int | None = None


class MpcInitReq(BaseModel):
    action_id: str
    program_id: str
    request_sha256: str
    n_wires: int
    gates: list[MpcGate]
    input_shares: dict[str, int] = Field(default_factory=dict, description="wire_index(str)->bit_share(0/1)")
    outputs: dict[str, int] = Field(default_factory=dict, description="output_name->wire_index")
    ttl_seconds: int = 30


class MpcAndMaskReq(BaseModel):
    action_id: str
    gate_index: int
    a_share: int
    b_share: int
    c_share: int

class MpcTripleShare(BaseModel):
    gate_index: int
    a_share: int
    b_share: int
    c_share: int


class MpcAndMaskBatchReq(BaseModel):
    action_id: str
    triples: list[MpcTripleShare] = Field(default_factory=list)

class MpcAndMaskMultiSubReq(BaseModel):
    action_id: str
    triples: list[MpcTripleShare] = Field(default_factory=list)


class MpcAndMaskMultiReq(BaseModel):
    requests: list[MpcAndMaskMultiSubReq] = Field(default_factory=list)


class MpcAndFinishReq(BaseModel):
    action_id: str
    gate_index: int
    d: int
    e: int

class MpcAndFinishItem(BaseModel):
    gate_index: int
    d: int
    e: int


class MpcAndFinishBatchReq(BaseModel):
    action_id: str
    opens: list[MpcAndFinishItem] = Field(default_factory=list)

class MpcAndFinishMultiSubReq(BaseModel):
    action_id: str
    opens: list[MpcAndFinishItem] = Field(default_factory=list)


class MpcAndFinishMultiReq(BaseModel):
    requests: list[MpcAndFinishMultiSubReq] = Field(default_factory=list)


class MpcFinalizeReq(BaseModel):
    action_id: str

@app.get("/health")
def health():
    return {"ok": True, "server_id": settings.server_id}

@app.get("/meta")
def meta():
    data_dir = Path(settings.data_dir)
    out: dict = {}
    p = data_dir / "meta.json"
    if p.exists():
        try:
            out.update(json.loads(p.read_text()))
        except Exception:
            out["meta_error"] = "failed_to_parse_meta_json"
    a = data_dir / "dfa_alphabet.json"
    if a.exists():
        try:
            out["dfa_alphabet"] = json.loads(a.read_text())
        except Exception:
            out["dfa_alphabet_error"] = "failed_to_parse_dfa_alphabet_json"
    return out

@app.post("/pir/query")
def pir_query(q: PirQuery):
    ans = db.query_one(q.db, q.dpf_key_b64, party=settings.server_id)
    return {"ans_share": ans}


@app.post("/pir/query_batch")
def pir_query_batch(q: PirQueryBatch):
    ans = db.query_batch(q.db, q.dpf_keys_b64, party=settings.server_id)
    return {"ans_shares": ans}


@app.post("/pir/query_block_batch")
def pir_query_block_batch(q: PirQueryBatch):
    blocks_b64 = db.query_block_batch(q.db, q.dpf_keys_b64, party=settings.server_id)
    return {"block_shares_b64": blocks_b64}


@app.post("/pir/query_idx_batch")
def pir_query_idx_batch(q: PirIdxBatch):
    ans = db.query_idx_batch(q.db, q.idxs)
    return {"ans_bits": ans}


def _require_mac_key() -> bytes:
    kid, key = _active_mac_key()
    if not key:
        raise RuntimeError("POLICY_MAC_KEY not configured")
    return key


_MAC_KEYS = None
_ACTIVE_KID = None


def _parse_mac_keys(s: str) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for part in (s or "").split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            kid, hexkey = part.split(":", 1)
        else:
            kid, hexkey = "0", part
        kid = kid.strip() or "0"
        hexkey = hexkey.strip()
        if not hexkey:
            continue
        out[kid] = bytes.fromhex(hexkey)
    return out


def _active_mac_key() -> tuple[str, bytes]:
    global _MAC_KEYS, _ACTIVE_KID
    if _MAC_KEYS is None:
        s = os.getenv("POLICY_MAC_KEYS", "").strip()
        if s:
            _MAC_KEYS = _parse_mac_keys(s)
        elif settings.mac_key_hex:
            _MAC_KEYS = {"0": bytes.fromhex(settings.mac_key_hex)}
        else:
            _MAC_KEYS = {}
        _ACTIVE_KID = (os.getenv("POLICY_MAC_ACTIVE_KID", "").strip() or (next(iter(_MAC_KEYS.keys()), "0")))
    kid = str(_ACTIVE_KID or "0")
    key = _MAC_KEYS.get(kid) or b""
    return kid, key


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _mac_b64(key: bytes, payload: dict) -> str:
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    mac = hmac.new(key, msg, hashlib.sha256).digest()
    return base64.b64encode(mac).decode("ascii")


@app.post("/pir/query_batch_signed")
def pir_query_batch_signed(q: PirQueryBatchSigned):
    kid, key = _active_mac_key()
    if not key:
        raise RuntimeError("POLICY_MAC_KEY not configured")
    ts = int(time.time())
    ans = db.query_batch(q.db, q.dpf_keys_b64, party=settings.server_id)

    keys_concat = b"".join(base64.b64decode(k) for k in q.dpf_keys_b64)
    keys_sha256 = _sha256_hex(keys_concat)
    resp_bytes = bytes([int(x) & 1 for x in ans])
    resp_sha256 = _sha256_hex(resp_bytes)

    payload = {
        "v": 1,
        "kind": "bit",
        "server_id": int(settings.server_id),
        "kid": str(kid),
        "ts": ts,
        "action_id": str(q.action_id),
        "db": str(q.db),
        "keys_sha256": keys_sha256,
        "resp_sha256": resp_sha256,
    }
    return {
        "ans_shares": ans,
        "proof": {
            **payload,
            "mac_b64": _mac_b64(key, payload),
        },
    }


@app.post("/pir/query_batch_multi_signed")
def pir_query_batch_multi_signed(q: PirQueryBatchMultiSigned):
    """
    Mixed/batched signed PIR endpoint.

    This is used by the gateway-side microbatch mixer to send many action_id subrequests
    in a single HTTP call per policy server. Each subrequest still receives an individual
    MAC proof bound to (action_id, db, keys_sha256, resp_sha256).
    """
    kid, key = _active_mac_key()
    if not key:
        raise RuntimeError("POLICY_MAC_KEY not configured")
    ts = int(time.time())
    out: list[dict] = []
    for sub in (q.requests or []):
        ans = db.query_batch(q.db, sub.dpf_keys_b64, party=settings.server_id)
        keys_concat = b"".join(base64.b64decode(k) for k in (sub.dpf_keys_b64 or []))
        keys_sha256 = _sha256_hex(keys_concat)
        resp_bytes = bytes([int(x) & 1 for x in ans])
        resp_sha256 = _sha256_hex(resp_bytes)
        payload = {
            "v": 1,
            "kind": "bit",
            "server_id": int(settings.server_id),
            "kid": str(kid),
            "ts": ts,
            "action_id": str(sub.action_id),
            "db": str(q.db),
            "keys_sha256": keys_sha256,
            "resp_sha256": resp_sha256,
        }
        out.append(
            {
                "action_id": str(sub.action_id),
                "ans_shares": ans,
                "proof": {**payload, "mac_b64": _mac_b64(key, payload)},
            }
        )
    return {"responses": out}


@app.post("/pir/query_block_batch_signed")
def pir_query_block_batch_signed(q: PirQueryBatchSigned):
    kid, key = _active_mac_key()
    if not key:
        raise RuntimeError("POLICY_MAC_KEY not configured")
    ts = int(time.time())
    blocks_b64 = db.query_block_batch(q.db, q.dpf_keys_b64, party=settings.server_id)

    keys_concat = b"".join(base64.b64decode(k) for k in q.dpf_keys_b64)
    keys_sha256 = _sha256_hex(keys_concat)
    resp_concat = b"".join(base64.b64decode(b) for b in blocks_b64)
    resp_sha256 = _sha256_hex(resp_concat)

    payload = {
        "v": 1,
        "kind": "block",
        "server_id": int(settings.server_id),
        "kid": str(kid),
        "ts": ts,
        "action_id": str(q.action_id),
        "db": str(q.db),
        "keys_sha256": keys_sha256,
        "resp_sha256": resp_sha256,
    }
    return {
        "block_shares_b64": blocks_b64,
        "proof": {
            **payload,
            "mac_b64": _mac_b64(key, payload),
        },
    }


@app.post("/pir/query_idx_batch_signed")
def pir_query_idx_batch_signed(q: PirIdxBatchSigned):
    kid, key = _active_mac_key()
    if not key:
        raise RuntimeError("POLICY_MAC_KEY not configured")
    ts = int(time.time())
    idxs = [int(x) for x in (q.idxs or [])]
    ans = db.query_idx_batch(q.db, idxs)

    idx_json = json.dumps(idxs, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    idxs_sha256 = _sha256_hex(idx_json)
    resp_bytes = bytes([int(x) & 1 for x in ans])
    resp_sha256 = _sha256_hex(resp_bytes)

    payload = {
        "v": 1,
        "kind": "idx",
        "server_id": int(settings.server_id),
        "kid": str(kid),
        "ts": ts,
        "action_id": str(q.action_id),
        "db": str(q.db),
        "idxs_sha256": idxs_sha256,
        "resp_sha256": resp_sha256,
    }
    return {
        "ans_bits": ans,
        "proof": {
            **payload,
            "mac_b64": _mac_b64(key, payload),
        },
    }


@app.post("/mpc/init")
def mpc_init(req: MpcInitReq):
    # Initialize/overwrite an MPC session keyed by action_id.
    party = int(settings.server_id)
    gates: list[Gate] = []
    for g in req.gates:
        gates.append(Gate(op=str(g.op), out=int(g.out), a=(int(g.a) if g.a is not None else None), b=(int(g.b) if g.b is not None else None), value=(int(g.value) if g.value is not None else None)))
    # JSON object keys come in as strings.
    input_shares: dict[int, int] = {}
    for k, v in (req.input_shares or {}).items():
        input_shares[int(k)] = int(v) & 1

    sess = MpcSession(
        action_id=req.action_id,
        program_id=req.program_id,
        request_sha256=req.request_sha256,
        party=party,
        n_wires=int(req.n_wires),
        gates=gates,
        input_shares=input_shares,
        outputs=dict(req.outputs or {}),
        ttl_seconds=int(req.ttl_seconds),
    )
    mpc_store.init(req.action_id, sess)
    return {"ok": True, "party": party, "gates": len(gates)}


@app.post("/mpc/and_mask")
def mpc_and_mask(req: MpcAndMaskReq):
    sess = mpc_store.get(req.action_id)
    d_share, e_share = sess.and_mask(gate_index=int(req.gate_index), a_share=int(req.a_share), b_share=int(req.b_share), c_share=int(req.c_share))
    return {"d_share": int(d_share) & 1, "e_share": int(e_share) & 1}

@app.post("/mpc/and_mask_batch")
def mpc_and_mask_batch(req: MpcAndMaskBatchReq):
    sess = mpc_store.get(req.action_id)
    items = [(int(t.gate_index), int(t.a_share), int(t.b_share), int(t.c_share)) for t in (req.triples or [])]
    d_shares, e_shares = sess.and_mask_batch(items)
    return {"d_shares": [int(x) & 1 for x in d_shares], "e_shares": [int(x) & 1 for x in e_shares]}

@app.post("/mpc/and_mask_multi")
def mpc_and_mask_multi(req: MpcAndMaskMultiReq):
    out: list[dict] = []
    for sub in (req.requests or []):
        try:
            sess = mpc_store.get(sub.action_id)
            items = [(int(t.gate_index), int(t.a_share), int(t.b_share), int(t.c_share)) for t in (sub.triples or [])]
            d_shares, e_shares = sess.and_mask_batch(items)
            out.append(
                {
                    "action_id": str(sub.action_id),
                    "ok": True,
                    "d_shares": [int(x) & 1 for x in d_shares],
                    "e_shares": [int(x) & 1 for x in e_shares],
                }
            )
        except Exception as e:
            out.append({"action_id": str(sub.action_id), "ok": False, "error": str(e)[:200], "d_shares": [], "e_shares": []})
    return {"responses": out}


@app.post("/mpc/and_finish")
def mpc_and_finish(req: MpcAndFinishReq):
    sess = mpc_store.get(req.action_id)
    z = sess.and_finish(gate_index=int(req.gate_index), d=int(req.d), e=int(req.e))
    return {"z_share": int(z) & 1}

@app.post("/mpc/and_finish_batch")
def mpc_and_finish_batch(req: MpcAndFinishBatchReq):
    sess = mpc_store.get(req.action_id)
    items = [(int(it.gate_index), int(it.d), int(it.e)) for it in (req.opens or [])]
    zs = sess.and_finish_batch(items)
    return {"z_shares": [int(x) & 1 for x in zs], "ok": True}

@app.post("/mpc/and_finish_multi")
def mpc_and_finish_multi(req: MpcAndFinishMultiReq):
    out: list[dict] = []
    for sub in (req.requests or []):
        try:
            sess = mpc_store.get(sub.action_id)
            items = [(int(it.gate_index), int(it.d), int(it.e)) for it in (sub.opens or [])]
            zs = sess.and_finish_batch(items)
            out.append({"action_id": str(sub.action_id), "ok": True, "z_shares": [int(x) & 1 for x in zs]})
        except Exception as e:
            out.append({"action_id": str(sub.action_id), "ok": False, "error": str(e)[:200], "z_shares": []})
    return {"responses": out}


@app.post("/mpc/finalize")
def mpc_finalize(req: MpcFinalizeReq):
    sess = mpc_store.pop(req.action_id)
    if not sess:
        return {"ok": False, "error": "missing_session"}
    kid, key = _active_mac_key()
    if not key:
        raise RuntimeError("POLICY_MAC_KEY not configured")

    outs = sess.finalize()
    commit_tag_share = os.urandom(16)
    commit_tag_share_b64 = base64.b64encode(commit_tag_share).decode("ascii")
    ts = int(time.time())
    payload = {
        "v": 1,
        "kind": "commit",
        "server_id": int(settings.server_id),
        "kid": str(kid),
        "ts": ts,
        "action_id": str(sess.action_id),
        "program_id": str(sess.program_id),
        "request_sha256": str(sess.request_sha256),
        "outputs": {k: int(v) & 1 for k, v in outs.items()},
        "commit_tag_share_b64": commit_tag_share_b64,
    }
    return {
        "ok": True,
        "outputs": outs,
        "proof": {
            **payload,
            "mac_b64": _mac_b64(key, payload),
        },
    }

def main():
    access_log = bool(int(os.getenv("ACCESS_LOG", "0")))
    uds = (os.getenv("POLICY_UDS_PATH") or "").strip()
    if uds:
        p = Path(uds)
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass
        uvicorn.run("policy_server.server:app", uds=uds, reload=False, access_log=access_log)
        return
    host = (os.getenv("POLICY_BIND") or "127.0.0.1").strip() or "127.0.0.1"
    uvicorn.run("policy_server.server:app", host=host, port=settings.port, reload=False, access_log=access_log)

if __name__ == "__main__":
    main()
