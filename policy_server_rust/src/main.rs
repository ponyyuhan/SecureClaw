use axum::{
    body::{Body, Bytes},
    extract::State,
    http::StatusCode,
    http::{header, HeaderValue},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use rayon::prelude::*;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tower::ServiceExt as _;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;

type HmacSha256 = Hmac<Sha256>;

const SEED_BYTES: usize = 16;
const BIN_MAGIC: &[u8; 4] = b"MPIR";
const BIN_VER: u8 = 1;

// Binary PIR wire message types (HTTP body, Content-Type: application/octet-stream).
const BIN_MSG_PIR_BATCH: u8 = 1;
const BIN_MSG_PIR_BATCH_SIGNED: u8 = 2;
const BIN_MSG_PIR_MULTI_SIGNED: u8 = 3;

struct BinCur<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> BinCur<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.i.saturating_add(n) > self.b.len() {
            return Err("bin_truncated".to_string());
        }
        let out = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16_le(&mut self) -> Result<u16, String> {
        let x = self.take(2)?;
        Ok(u16::from_le_bytes([x[0], x[1]]))
    }

    fn u32_le(&mut self) -> Result<u32, String> {
        let x = self.take(4)?;
        Ok(u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
    }

    fn bytes_u32(&mut self) -> Result<&'a [u8], String> {
        let n = self.u32_le()? as usize;
        self.take(n)
    }

    fn str_u32(&mut self) -> Result<String, String> {
        let x = self.bytes_u32()?;
        std::str::from_utf8(x)
            .map(|s| s.to_string())
            .map_err(|_| "bin_bad_utf8".to_string())
    }
}

fn octet_response(buf: Vec<u8>) -> Response {
    let mut resp = Response::new(Body::from(buf));
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    resp
}

#[derive(Clone)]
struct AppState {
    server_id: u8,
    data_dir: PathBuf,
    mac_keys: HashMap<String, Vec<u8>>, // kid -> key bytes
    active_kid: String,
    bitsets: Arc<HashMap<String, Arc<Vec<u8>>>>,
    bitset_ones: Arc<HashMap<String, Arc<Vec<u32>>>>,
    blocks: Arc<HashMap<String, (Arc<Vec<u8>>, usize)>>,
    mpc_sessions: Arc<Mutex<HashMap<String, MpcSession>>>,
}

#[derive(Debug, Clone, Deserialize)]
struct MpcGate {
    op: String,
    out: usize,
    a: Option<usize>,
    b: Option<usize>,
    value: Option<u8>,
}

#[derive(Debug)]
struct MpcSession {
    program_id: String,
    request_sha256: String,
    created_at: u64,
    ttl_seconds: u64,
    gates: Vec<MpcGate>,
    wires: Vec<Option<u8>>,
    outputs: HashMap<String, usize>,
    pending: HashMap<usize, (u8, u8, u8)>, // gate_index -> (a,b,c) shares
}

impl MpcSession {
    fn expired(&self, now: u64) -> bool {
        now.saturating_sub(self.created_at) > self.ttl_seconds
    }

    fn wire(&self, idx: usize) -> Result<u8, String> {
        self.wires
            .get(idx)
            .and_then(|v| *v)
            .map(|v| v & 1)
            .ok_or_else(|| "wire_not_ready".to_string())
    }

    fn set_wire(&mut self, idx: usize, v: u8) -> Result<(), String> {
        if idx >= self.wires.len() {
            return Err("wire_oob".to_string());
        }
        self.wires[idx] = Some(v & 1);
        Ok(())
    }

    fn eval_local(&mut self, party: u8) -> Result<(), String> {
        // Best-effort compute XOR/NOT/CONST gates whose inputs are ready.
        // This intentionally skips AND gates; those are handled via Beaver triples.
        for gi in 0..self.gates.len() {
            let g = self.gates[gi].clone();
            if g.out >= self.wires.len() {
                return Err("wire_oob".to_string());
            }
            if self.wires[g.out].is_some() {
                continue;
            }
            let op = g.op.to_ascii_uppercase();
            if op == "AND" {
                continue;
            }
            if op == "XOR" {
                let a = g.a.ok_or_else(|| "bad_gate".to_string())?;
                let b = g.b.ok_or_else(|| "bad_gate".to_string())?;
                if self.wires.get(a).and_then(|v| *v).is_none() || self.wires.get(b).and_then(|v| *v).is_none() {
                    continue;
                }
                let v = self.wire(a)? ^ self.wire(b)?;
                self.set_wire(g.out, v)?;
                continue;
            }
            if op == "NOT" {
                let a = g.a.ok_or_else(|| "bad_gate".to_string())?;
                if self.wires.get(a).and_then(|v| *v).is_none() {
                    continue;
                }
                let v = self.wire(a)? ^ if party == 0 { 1 } else { 0 };
                self.set_wire(g.out, v)?;
                continue;
            }
            if op == "CONST" {
                let v = g.value.unwrap_or(0) & 1;
                self.set_wire(g.out, if party == 0 { v } else { 0 })?;
                continue;
            }
            return Err("unknown_gate".to_string());
        }
        Ok(())
    }

    fn and_mask(&mut self, party: u8, gate_index: usize, a_share: u8, b_share: u8, c_share: u8) -> Result<(u8, u8), String> {
        if gate_index >= self.gates.len() {
            return Err("gate_oob".to_string());
        }
        self.eval_local(party)?;
        let g = &self.gates[gate_index];
        if g.op.to_ascii_uppercase() != "AND" {
            return Err("not_and_gate".to_string());
        }
        let a = g.a.ok_or_else(|| "bad_gate".to_string())?;
        let b = g.b.ok_or_else(|| "bad_gate".to_string())?;
        if self.wires.get(a).and_then(|v| *v).is_none() || self.wires.get(b).and_then(|v| *v).is_none() {
            return Err("and_inputs_not_ready".to_string());
        }
        self.pending.insert(gate_index, (a_share & 1, b_share & 1, c_share & 1));
        let d_share = self.wire(a)? ^ (a_share & 1);
        let e_share = self.wire(b)? ^ (b_share & 1);
        Ok((d_share & 1, e_share & 1))
    }

    fn and_finish(&mut self, party: u8, gate_index: usize, d: u8, e: u8) -> Result<u8, String> {
        if gate_index >= self.gates.len() {
            return Err("gate_oob".to_string());
        }
        let g = &self.gates[gate_index];
        if g.op.to_ascii_uppercase() != "AND" {
            return Err("not_and_gate".to_string());
        }
        let (a_share, b_share, c_share) = self.pending.remove(&gate_index).ok_or_else(|| "missing_triple".to_string())?;
        let dd = d & 1;
        let ee = e & 1;
        let mut z = (c_share ^ (dd & b_share) ^ (ee & a_share)) & 1;
        if party == 0 {
            z ^= (dd & ee) & 1;
        }
        self.set_wire(g.out, z)?;
        self.eval_local(party)?;
        Ok(z & 1)
    }

    fn finalize(&mut self, party: u8) -> Result<HashMap<String, u8>, String> {
        self.eval_local(party)?;
        if !self.pending.is_empty() {
            return Err("unfinished_and".to_string());
        }
        let mut out = HashMap::new();
        for (k, wi) in self.outputs.iter() {
            out.insert(k.clone(), self.wire(*wi)? & 1);
        }
        Ok(out)
    }
}

#[derive(Deserialize)]
struct MpcInitReq {
    action_id: String,
    program_id: String,
    request_sha256: String,
    n_wires: usize,
    gates: Vec<MpcGate>,
    input_shares: HashMap<String, u8>,
    outputs: HashMap<String, usize>,
    ttl_seconds: Option<u64>,
}

#[derive(Deserialize)]
struct MpcAndMaskReq {
    action_id: String,
    gate_index: usize,
    a_share: u8,
    b_share: u8,
    c_share: u8,
}

#[derive(Deserialize)]
struct MpcTripleShare {
    gate_index: usize,
    a_share: u8,
    b_share: u8,
    c_share: u8,
}

#[derive(Deserialize)]
struct MpcAndMaskBatchReq {
    action_id: String,
    triples: Vec<MpcTripleShare>,
}

#[derive(Deserialize)]
struct MpcAndMaskMultiSubReq {
    action_id: String,
    triples: Vec<MpcTripleShare>,
}

#[derive(Deserialize)]
struct MpcAndMaskMultiReq {
    requests: Vec<MpcAndMaskMultiSubReq>,
}

#[derive(Deserialize)]
struct MpcAndFinishReq {
    action_id: String,
    gate_index: usize,
    d: u8,
    e: u8,
}

#[derive(Deserialize)]
struct MpcAndOpen {
    gate_index: usize,
    d: u8,
    e: u8,
}

#[derive(Deserialize)]
struct MpcAndFinishBatchReq {
    action_id: String,
    opens: Vec<MpcAndOpen>,
}

#[derive(Deserialize)]
struct MpcAndFinishMultiSubReq {
    action_id: String,
    opens: Vec<MpcAndOpen>,
}

#[derive(Deserialize)]
struct MpcAndFinishMultiReq {
    requests: Vec<MpcAndFinishMultiSubReq>,
}

#[derive(Deserialize)]
struct MpcFinalizeReq {
    action_id: String,
}

#[derive(Debug)]
struct DpfKey {
    version: u8,
    domain_bits: u8,
    seed0: [u8; SEED_BYTES],
    cw_last: u8,
    cws: Vec<CorrectionWord>,
}

#[derive(Debug, Clone)]
struct CorrectionWord {
    s_cw: [u8; SEED_BYTES],
    t_l: u8,
    t_r: u8,
}

fn decode_dpf_key(data: &[u8]) -> Result<DpfKey, String> {
    if data.len() < 1 + 1 + SEED_BYTES + 1 {
        return Err("truncated key".to_string());
    }
    let version = data[0];
    if version != 1 && version != 2 {
        return Err("unsupported key version".to_string());
    }
    let domain_bits = data[1];
    if domain_bits == 0 || domain_bits > 30 {
        return Err("domain_bits out of supported range".to_string());
    }
    let mut seed0 = [0u8; SEED_BYTES];
    seed0.copy_from_slice(&data[2..2 + SEED_BYTES]);
    let cw_last = data[2 + SEED_BYTES] & 1;
    let rest = &data[2 + SEED_BYTES + 1..];
    let expected = (domain_bits as usize) * (SEED_BYTES + 2);
    if rest.len() != expected {
        return Err("bad key length".to_string());
    }
    let mut cws = Vec::with_capacity(domain_bits as usize);
    let mut off = 0usize;
    for _ in 0..domain_bits {
        let mut s_cw = [0u8; SEED_BYTES];
        s_cw.copy_from_slice(&rest[off..off + SEED_BYTES]);
        let t_l = rest[off + SEED_BYTES] & 1;
        let t_r = rest[off + SEED_BYTES + 1] & 1;
        cws.push(CorrectionWord { s_cw, t_l, t_r });
        off += SEED_BYTES + 2;
    }
    Ok(DpfKey {
        version,
        domain_bits,
        seed0,
        cw_last,
        cws,
    })
}

#[inline]
fn xor16(a: &[u8; SEED_BYTES], b: &[u8; SEED_BYTES]) -> [u8; SEED_BYTES] {
    // 16-byte XOR: use u128 so LLVM can map it to efficient vector ops.
    let x = u128::from_le_bytes(*a) ^ u128::from_le_bytes(*b);
    x.to_le_bytes()
}

#[inline]
fn prg_v2(seed: &[u8; SEED_BYTES]) -> ([u8; SEED_BYTES], u8, [u8; SEED_BYTES], u8) {
    let mut h = Sha512::new();
    h.update(seed);
    h.update(b"prg");
    let d = h.finalize();
    let mut s_l = [0u8; SEED_BYTES];
    s_l.copy_from_slice(&d[0..SEED_BYTES]);
    let t_l = d[SEED_BYTES] & 1;
    let mut s_r = [0u8; SEED_BYTES];
    s_r.copy_from_slice(&d[SEED_BYTES + 1..SEED_BYTES + 1 + SEED_BYTES]);
    let t_r = d[2 * SEED_BYTES + 1] & 1;
    (s_l, t_l, s_r, t_r)
}

#[inline]
fn prg_v1(seed: &[u8; SEED_BYTES]) -> ([u8; SEED_BYTES], u8, [u8; SEED_BYTES], u8) {
    let mut h0 = Sha256::new();
    h0.update(seed);
    h0.update([0u8]);
    let d0 = h0.finalize();
    let mut h1 = Sha256::new();
    h1.update(seed);
    h1.update([1u8]);
    let d1 = h1.finalize();
    let mut s_l = [0u8; SEED_BYTES];
    s_l.copy_from_slice(&d0[0..SEED_BYTES]);
    let t_l = d0[d0.len() - 1] & 1;
    let mut s_r = [0u8; SEED_BYTES];
    s_r.copy_from_slice(&d1[0..SEED_BYTES]);
    let t_r = d1[d1.len() - 1] & 1;
    (s_l, t_l, s_r, t_r)
}

#[inline]
fn convert_bit_v2(seed: &[u8; SEED_BYTES]) -> u8 {
    seed[0] & 1
}

#[inline]
fn convert_bit_v1(seed: &[u8; SEED_BYTES]) -> u8 {
    let mut h = Sha256::new();
    h.update(seed);
    h.update(b"convert");
    let d = h.finalize();
    d[0] & 1
}

#[inline]
fn xor_inplace_u64(dst: &mut [u8], src: &[u8]) {
    let n = dst.len().min(src.len());
    let mut i = 0usize;
    // Word-wise XOR for better compiled/vectorized throughput on O(N) paths.
    while i + 8 <= n {
        let a = unsafe { std::ptr::read_unaligned(dst.as_ptr().add(i) as *const u64) };
        let b = unsafe { std::ptr::read_unaligned(src.as_ptr().add(i) as *const u64) };
        let x = a ^ b;
        unsafe { std::ptr::write_unaligned(dst.as_mut_ptr().add(i) as *mut u64, x) };
        i += 8;
    }
    while i < n {
        dst[i] ^= src[i];
        i += 1;
    }
}

#[inline]
fn prefer_sparse(domain_size: usize, domain_bits: usize, ones_len: usize) -> bool {
    // Dense PIR parity share eval is O(N). Sparse eval is O(|ones| * log N).
    // Use sparse only when it's expected to be much cheaper (>=4x).
    if domain_size == 0 {
        return true;
    }
    let sparse_cost = ones_len.saturating_mul(domain_bits.saturating_add(1));
    sparse_cost.saturating_mul(4) < domain_size
}

fn eval_point_share(key: &DpfKey, x: usize, party: u8) -> Result<u8, String> {
    if party > 1 {
        return Err("party must be 0/1".to_string());
    }
    let domain_size = 1usize << (key.domain_bits as usize);
    if x >= domain_size {
        return Err("x out of range".to_string());
    }

    let mut s = key.seed0;
    let mut t = party & 1;
    for level in 0..(key.domain_bits as usize) {
        let cw = &key.cws[level];
        let (mut s_l, mut t_l, mut s_r, mut t_r) = if key.version == 1 {
            prg_v1(&s)
        } else {
            prg_v2(&s)
        };
        if t == 1 {
            s_l = xor16(&s_l, &cw.s_cw);
            t_l ^= cw.t_l;
            s_r = xor16(&s_r, &cw.s_cw);
            t_r ^= cw.t_r;
        }
        let shift = (key.domain_bits as usize) - 1 - level;
        let xb = (x >> shift) & 1;
        if xb == 0 {
            s = s_l;
            t = t_l & 1;
        } else {
            s = s_r;
            t = t_r & 1;
        }
    }

    let out = if key.version == 1 {
        convert_bit_v1(&s)
    } else {
        convert_bit_v2(&s)
    };
    Ok((out ^ (t & key.cw_last)) & 1)
}

fn eval_parity_share_sparse(key: &DpfKey, ones: &[u32], party: u8) -> Result<u8, String> {
    if party > 1 {
        return Err("party must be 0/1".to_string());
    }
    let domain_size = 1usize << (key.domain_bits as usize);
    let mut ans: u8 = 0;
    for &idx in ones.iter() {
        let i = idx as usize;
        if i >= domain_size {
            continue;
        }
        ans ^= eval_point_share(key, i, party)? & 1;
    }
    Ok(ans & 1)
}

fn eval_parity_share(key_bytes: &[u8], db: &[u8], party: u8) -> Result<u8, String> {
    let key = decode_dpf_key(key_bytes)?;
    let domain_size = 1usize << (key.domain_bits as usize);
    let nbytes = (domain_size + 7) / 8;
    if db.len() != nbytes {
        return Err("db length mismatch".to_string());
    }
    if party > 1 {
        return Err("party must be 0/1".to_string());
    }

    // When the domain is large enough, compute the bitset inner-product in 64-bit chunks:
    // pack leaf output bits into a word-wide mask, then use popcount parity on (mask & db_word).
    // This reduces byte-level loads and branches on the O(N) path.
    let use_words = domain_size >= 64 && (db.len() % 8 == 0);

    let mut ans: u8 = 0;
    let mut cur_word: usize = 0;
    let mut mask: u64 = 0;
    let mut stack: Vec<(u8, [u8; SEED_BYTES], u8, u32)> = Vec::with_capacity(domain_size / 2);
    stack.push((0, key.seed0, party, 0));

    while let Some((level, seed, t, node_idx)) = stack.pop() {
        if level == key.domain_bits {
            let out = if key.version == 1 {
                convert_bit_v1(&seed)
            } else {
                convert_bit_v2(&seed)
            };
            let out_bit = (out ^ (t & key.cw_last)) & 1;
            let leaf = node_idx as usize;
            if use_words {
                let word = leaf >> 6;
                if word != cur_word {
                    // Flush previous 64-leaf chunk.
                    let byte_off = cur_word * 8;
                    if byte_off + 8 <= db.len() {
                        let db_word = unsafe { std::ptr::read_unaligned(db.as_ptr().add(byte_off) as *const u64) };
                        let db_word = u64::from_le(db_word);
                        ans ^= (((mask & db_word).count_ones() & 1) as u8) & 1;
                    }
                    cur_word = word;
                    mask = 0;
                }
                let bit = (leaf & 63) as u32;
                mask |= (out_bit as u64) << bit;
            } else {
                // Branchless per-leaf dot-product for small domains.
                let b = (db[leaf / 8] >> (leaf % 8)) & 1;
                ans ^= (b & out_bit) & 1;
            }
            continue;
        }

        let cw = &key.cws[level as usize];
        let (mut s_l, mut t_l, mut s_r, mut t_r) = if key.version == 1 {
            prg_v1(&seed)
        } else {
            prg_v2(&seed)
        };
        if t == 1 {
            s_l = xor16(&s_l, &cw.s_cw);
            t_l ^= cw.t_l;
            s_r = xor16(&s_r, &cw.s_cw);
            t_r ^= cw.t_r;
        }

        // Right then left (deterministic, like the Python stack DFS).
        stack.push((level + 1, s_r, t_r & 1, (node_idx << 1) | 1));
        stack.push((level + 1, s_l, t_l & 1, (node_idx << 1) | 0));
    }
    if use_words {
        // Flush final chunk.
        let byte_off = cur_word * 8;
        if byte_off + 8 <= db.len() {
            let db_word = unsafe { std::ptr::read_unaligned(db.as_ptr().add(byte_off) as *const u64) };
            let db_word = u64::from_le(db_word);
            ans ^= (((mask & db_word).count_ones() & 1) as u8) & 1;
        }
    }
    Ok(ans & 1)
}

fn eval_block_share(key_bytes: &[u8], db: &[u8], block_size: usize, party: u8) -> Result<Vec<u8>, String> {
    if block_size == 0 || block_size > 4096 {
        return Err("bad block_size".to_string());
    }
    let key = decode_dpf_key(key_bytes)?;
    let domain_size = 1usize << (key.domain_bits as usize);
    if db.len() != domain_size * block_size {
        return Err("db length mismatch".to_string());
    }
    if party > 1 {
        return Err("party must be 0/1".to_string());
    }

    let mut acc = vec![0u8; block_size];
    let mut stack: Vec<(u8, [u8; SEED_BYTES], u8, u32)> = Vec::with_capacity(domain_size / 2);
    stack.push((0, key.seed0, party, 0));

    while let Some((level, seed, t, node_idx)) = stack.pop() {
        if level == key.domain_bits {
            let out = if key.version == 1 {
                convert_bit_v1(&seed)
            } else {
                convert_bit_v2(&seed)
            };
            let out_bit = (out ^ (t & key.cw_last)) & 1;
            if out_bit == 1 {
                let leaf = node_idx as usize;
                let off = leaf * block_size;
                let blk = &db[off..off + block_size];
                xor_inplace_u64(&mut acc, blk);
            }
            continue;
        }

        let cw = &key.cws[level as usize];
        let (mut s_l, mut t_l, mut s_r, mut t_r) = if key.version == 1 {
            prg_v1(&seed)
        } else {
            prg_v2(&seed)
        };
        if t == 1 {
            s_l = xor16(&s_l, &cw.s_cw);
            t_l ^= cw.t_l;
            s_r = xor16(&s_r, &cw.s_cw);
            t_r ^= cw.t_r;
        }

        stack.push((level + 1, s_r, t_r & 1, (node_idx << 1) | 1));
        stack.push((level + 1, s_l, t_l & 1, (node_idx << 1) | 0));
    }
    Ok(acc)
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn parse_mac_keys(s: &str) -> HashMap<String, Vec<u8>> {
    let mut out = HashMap::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (kid, hexkey) = if let Some((a, b)) = part.split_once(':') {
            (a.trim(), b.trim())
        } else {
            ("0", part)
        };
        if hexkey.is_empty() {
            continue;
        }
        if let Ok(bytes) = hex::decode(hexkey) {
            out.insert(kid.to_string(), bytes);
        }
    }
    out
}

fn canonical_json_bytes(payload: &BTreeMap<&str, Value>) -> Vec<u8> {
    // BTreeMap keeps keys sorted, matching Python json.dumps(sort_keys=True,separators=(",",":")) for ASCII payloads.
    serde_json::to_vec(payload).unwrap_or_else(|_| b"{}".to_vec())
}

fn sign_payload(mac_key: &[u8], payload: &BTreeMap<&str, Value>) -> String {
    let msg = canonical_json_bytes(payload);
    let mut mac = HmacSha256::new_from_slice(mac_key).expect("hmac key");
    mac.update(&msg);
    let out = mac.finalize().into_bytes();
    B64.encode(out)
}

#[derive(Deserialize)]
struct PirQueryBatch {
    db: String,
    dpf_keys_b64: Vec<String>,
}

#[derive(Deserialize)]
struct PirQueryBatchSigned {
    db: String,
    dpf_keys_b64: Vec<String>,
    action_id: String,
}

#[derive(Deserialize)]
struct PirQueryBatchSubReq {
    action_id: String,
    dpf_keys_b64: Vec<String>,
}

#[derive(Deserialize)]
struct PirQueryBatchMultiSigned {
    db: String,
    requests: Vec<PirQueryBatchSubReq>,
}

#[derive(Deserialize)]
struct PirIdxBatch {
    db: String,
    idxs: Vec<usize>,
}

#[derive(Deserialize)]
struct PirIdxBatchSigned {
    db: String,
    idxs: Vec<usize>,
    action_id: String,
}

#[derive(Serialize)]
struct PirAnsBatch {
    ans_shares: Vec<u8>,
}

#[derive(Serialize)]
struct PirAnsBatchSigned {
    ans_shares: Vec<u8>,
    proof: Value,
}

#[derive(Serialize)]
struct PirSubAnsBatchSigned {
    action_id: String,
    ans_shares: Vec<u8>,
    proof: Value,
}

#[derive(Serialize)]
struct PirAnsBatchMultiSigned {
    responses: Vec<PirSubAnsBatchSigned>,
}

#[derive(Serialize)]
struct PirIdxAns {
    ans_bits: Vec<u8>,
}

#[derive(Serialize)]
struct PirIdxAnsSigned {
    ans_bits: Vec<u8>,
    proof: Value,
}

#[derive(Serialize)]
struct PirBlockBatch {
    block_shares_b64: Vec<String>,
}

#[derive(Serialize)]
struct PirBlockBatchSigned {
    block_shares_b64: Vec<String>,
    proof: Value,
}

async fn health(State(st): State<AppState>) -> Json<Value> {
    Json(json!({"ok": true, "server_id": st.server_id}))
}

async fn meta(State(st): State<AppState>) -> Json<Value> {
    let mut out = serde_json::Map::new();
    let p = st.data_dir.join("meta.json");
    if let Ok(s) = fs::read_to_string(&p) {
        if let Ok(v) = serde_json::from_str::<Value>(&s) {
            if let Some(obj) = v.as_object() {
                for (k, v) in obj.iter() {
                    out.insert(k.clone(), v.clone());
                }
            }
        } else {
            out.insert("meta_error".to_string(), Value::from("failed_to_parse_meta_json"));
        }
    }
    let a = st.data_dir.join("dfa_alphabet.json");
    if let Ok(s) = fs::read_to_string(&a) {
        if let Ok(v) = serde_json::from_str::<Value>(&s) {
            out.insert("dfa_alphabet".to_string(), v);
        } else {
            out.insert(
                "dfa_alphabet_error".to_string(),
                Value::from("failed_to_parse_dfa_alphabet_json"),
            );
        }
    }
    out.insert(
        "transport".to_string(),
        json!({
            "pir_binary": true,
            "magic": "MPIR",
            "version": BIN_VER
        }),
    );
    Json(Value::Object(out))
}

fn get_bitset<'a>(st: &'a AppState, name: &str) -> Result<Arc<Vec<u8>>, String> {
    st.bitsets
        .get(name)
        .cloned()
        .ok_or_else(|| format!("unknown bitset db: {name}"))
}

fn get_bitset_ones<'a>(st: &'a AppState, name: &str) -> Result<Arc<Vec<u32>>, String> {
    st.bitset_ones
        .get(name)
        .cloned()
        .ok_or_else(|| format!("unknown bitset db: {name}"))
}

fn get_block_db<'a>(st: &'a AppState, name: &str) -> Result<(Arc<Vec<u8>>, usize), String> {
    st.blocks
        .get(name)
        .cloned()
        .ok_or_else(|| format!("unknown block db: {name}"))
}

#[inline]
fn bit_at(db: &[u8], idx: usize) -> u8 {
    if idx >= (db.len() * 8) {
        return 0;
    }
    (db[idx / 8] >> (idx % 8)) & 1
}

async fn pir_query_batch(State(st): State<AppState>, Json(q): Json<PirQueryBatch>) -> Result<Json<PirAnsBatch>, (StatusCode, String)> {
    let db = get_bitset(&st, &q.db).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let ones = get_bitset_ones(&st, &q.db).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let party = st.server_id;
    let mode = env::var("PIR_EVAL_MODE").unwrap_or_else(|_| "auto".to_string());
    let mode = mode.trim().to_ascii_lowercase();
    let domain_size = db.len() * 8;
    let mut tmp = domain_size;
    let mut domain_bits = 0usize;
    while tmp > 1 {
        domain_bits += 1;
        tmp >>= 1;
    }
    let use_sparse = if mode == "sparse" {
        true
    } else if mode == "dense" {
        false
    } else {
        prefer_sparse(domain_size, domain_bits, ones.len())
    };
    let ans: Result<Vec<u8>, String> = q
        .dpf_keys_b64
        .par_iter()
        .map(|k| {
            let kb = B64
                .decode(k.as_bytes())
                .map_err(|_| "bad base64 key".to_string())?;
            if use_sparse {
                let key = decode_dpf_key(&kb)?;
                eval_parity_share_sparse(&key, &ones, party)
            } else {
                eval_parity_share(&kb, &db, party)
            }
        })
        .collect();
    let ans = ans.map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(PirAnsBatch { ans_shares: ans }))
}

async fn pir_query_block_batch(
    State(st): State<AppState>,
    Json(q): Json<PirQueryBatch>,
) -> Result<Json<PirBlockBatch>, (StatusCode, String)> {
    let (db, block_size) = get_block_db(&st, &q.db).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let party = st.server_id;
    let out: Result<Vec<String>, String> = q
        .dpf_keys_b64
        .par_iter()
        .map(|k| {
            let kb = B64
                .decode(k.as_bytes())
                .map_err(|_| "bad base64 key".to_string())?;
            let share = eval_block_share(&kb, &db, block_size, party)?;
            Ok(B64.encode(share))
        })
        .collect();
    let out = out.map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(PirBlockBatch {
        block_shares_b64: out,
    }))
}

async fn pir_query_idx_batch(
    State(st): State<AppState>,
    Json(q): Json<PirIdxBatch>,
) -> Result<Json<PirIdxAns>, (StatusCode, String)> {
    let db = get_bitset(&st, &q.db).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let bits: Vec<u8> = q.idxs.par_iter().map(|idx| bit_at(&db, *idx)).collect();
    Ok(Json(PirIdxAns { ans_bits: bits }))
}

async fn pir_query_batch_signed(
    State(st): State<AppState>,
    Json(q): Json<PirQueryBatchSigned>,
) -> Result<Json<PirAnsBatchSigned>, (StatusCode, String)> {
    let db = get_bitset(&st, &q.db).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let ones = get_bitset_ones(&st, &q.db).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let party = st.server_id;
    let mode = env::var("PIR_EVAL_MODE").unwrap_or_else(|_| "auto".to_string());
    let mode = mode.trim().to_ascii_lowercase();
    let domain_size = db.len() * 8;
    let mut tmp = domain_size;
    let mut domain_bits = 0usize;
    while tmp > 1 {
        domain_bits += 1;
        tmp >>= 1;
    }
    let use_sparse = if mode == "sparse" {
        true
    } else if mode == "dense" {
        false
    } else {
        prefer_sparse(domain_size, domain_bits, ones.len())
    };

    let decoded_keys: Result<Vec<Vec<u8>>, String> = q
        .dpf_keys_b64
        .iter()
        .map(|k| B64.decode(k.as_bytes()).map_err(|_| "bad base64 key".to_string()))
        .collect();
    let decoded_keys = decoded_keys.map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let ans: Result<Vec<u8>, String> = decoded_keys
        .par_iter()
        .map(|kb| {
            if use_sparse {
                let key = decode_dpf_key(kb)?;
                eval_parity_share_sparse(&key, &ones, party)
            } else {
                eval_parity_share(kb, &db, party)
            }
        })
        .collect();
    let ans = ans.map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let mut keys_concat = Vec::new();
    for kb in decoded_keys.iter() {
        keys_concat.extend_from_slice(kb);
    }
    let keys_sha256 = sha256_hex(&keys_concat);
    let resp_sha256 = sha256_hex(&ans.iter().map(|x| x & 1).collect::<Vec<u8>>());

    let ts = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()) as i64;

    let kid = st.active_kid.clone();
    let key = st
        .mac_keys
        .get(&kid)
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "missing mac key".to_string()))?;

    let mut payload: BTreeMap<&str, Value> = BTreeMap::new();
    payload.insert("v", Value::from(1));
    payload.insert("kind", Value::from("bit"));
    payload.insert("server_id", Value::from(st.server_id as i64));
    payload.insert("kid", Value::from(kid.clone()));
    payload.insert("ts", Value::from(ts));
    payload.insert("action_id", Value::from(q.action_id.clone()));
    payload.insert("db", Value::from(q.db.clone()));
    payload.insert("keys_sha256", Value::from(keys_sha256));
    payload.insert("resp_sha256", Value::from(resp_sha256));

    let mac_b64 = sign_payload(key, &payload);
    let mut proof_obj = serde_json::Map::new();
    for (k, v) in payload.into_iter() {
        proof_obj.insert(k.to_string(), v);
    }
    proof_obj.insert("mac_b64".to_string(), Value::from(mac_b64));
    Ok(Json(PirAnsBatchSigned {
        ans_shares: ans,
        proof: Value::Object(proof_obj),
    }))
}

async fn pir_query_batch_bin(State(st): State<AppState>, body: Bytes) -> Result<Response, (StatusCode, String)> {
    let mut c = BinCur::new(&body);
    let magic = c.take(4).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    if magic != BIN_MAGIC {
        return Err((StatusCode::BAD_REQUEST, "bin_bad_magic".to_string()));
    }
    let ver = c.u8().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    if ver != BIN_VER {
        return Err((StatusCode::BAD_REQUEST, "bin_bad_version".to_string()));
    }
    let msg = c.u8().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    if msg != BIN_MSG_PIR_BATCH {
        return Err((StatusCode::BAD_REQUEST, "bin_bad_msg".to_string()));
    }
    let _ = c.u16_le().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let db_name = c.str_u32().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let n_keys = c.u32_le().map_err(|e| (StatusCode::BAD_REQUEST, e))? as usize;
    let key_len = c.u16_le().map_err(|e| (StatusCode::BAD_REQUEST, e))? as usize;
    if n_keys == 0 || key_len == 0 || key_len > 4096 {
        return Err((StatusCode::BAD_REQUEST, "bin_bad_shape".to_string()));
    }
    let keys_blob = c
        .take(n_keys.saturating_mul(key_len))
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let mut keys: Vec<&[u8]> = Vec::with_capacity(n_keys);
    for i in 0..n_keys {
        let off = i * key_len;
        keys.push(&keys_blob[off..off + key_len]);
    }

    let db = get_bitset(&st, &db_name).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let ones = get_bitset_ones(&st, &db_name).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let party = st.server_id;
    let mode = env::var("PIR_EVAL_MODE").unwrap_or_else(|_| "auto".to_string());
    let mode = mode.trim().to_ascii_lowercase();
    let domain_size = db.len() * 8;
    let mut tmp = domain_size;
    let mut domain_bits = 0usize;
    while tmp > 1 {
        domain_bits += 1;
        tmp >>= 1;
    }
    let use_sparse = if mode == "sparse" {
        true
    } else if mode == "dense" {
        false
    } else {
        prefer_sparse(domain_size, domain_bits, ones.len())
    };

    let ans: Result<Vec<u8>, String> = keys
        .par_iter()
        .map(|kb| {
            if use_sparse {
                let key = decode_dpf_key(kb)?;
                eval_parity_share_sparse(&key, &ones, party)
            } else {
                eval_parity_share(kb, &db, party)
            }
        })
        .collect();
    let ans = ans.map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let mut out = Vec::with_capacity(4 + 1 + 1 + 2 + 4 + ans.len());
    out.extend_from_slice(BIN_MAGIC);
    out.push(BIN_VER);
    out.push(BIN_MSG_PIR_BATCH);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(n_keys as u32).to_le_bytes());
    out.extend_from_slice(&ans);
    Ok(octet_response(out))
}

async fn pir_query_batch_signed_bin(State(st): State<AppState>, body: Bytes) -> Result<Response, (StatusCode, String)> {
    let mut c = BinCur::new(&body);
    let magic = c.take(4).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    if magic != BIN_MAGIC {
        return Err((StatusCode::BAD_REQUEST, "bin_bad_magic".to_string()));
    }
    let ver = c.u8().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    if ver != BIN_VER {
        return Err((StatusCode::BAD_REQUEST, "bin_bad_version".to_string()));
    }
    let msg = c.u8().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    if msg != BIN_MSG_PIR_BATCH_SIGNED {
        return Err((StatusCode::BAD_REQUEST, "bin_bad_msg".to_string()));
    }
    let _ = c.u16_le().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let db_name = c.str_u32().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let action_id = c.str_u32().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let n_keys = c.u32_le().map_err(|e| (StatusCode::BAD_REQUEST, e))? as usize;
    let key_len = c.u16_le().map_err(|e| (StatusCode::BAD_REQUEST, e))? as usize;
    if n_keys == 0 || key_len == 0 || key_len > 4096 {
        return Err((StatusCode::BAD_REQUEST, "bin_bad_shape".to_string()));
    }
    let keys_blob = c
        .take(n_keys.saturating_mul(key_len))
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let mut keys: Vec<&[u8]> = Vec::with_capacity(n_keys);
    for i in 0..n_keys {
        let off = i * key_len;
        keys.push(&keys_blob[off..off + key_len]);
    }

    let db = get_bitset(&st, &db_name).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let ones = get_bitset_ones(&st, &db_name).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let party = st.server_id;
    let mode = env::var("PIR_EVAL_MODE").unwrap_or_else(|_| "auto".to_string());
    let mode = mode.trim().to_ascii_lowercase();
    let domain_size = db.len() * 8;
    let mut tmp = domain_size;
    let mut domain_bits = 0usize;
    while tmp > 1 {
        domain_bits += 1;
        tmp >>= 1;
    }
    let use_sparse = if mode == "sparse" {
        true
    } else if mode == "dense" {
        false
    } else {
        prefer_sparse(domain_size, domain_bits, ones.len())
    };

    let ans: Result<Vec<u8>, String> = keys
        .par_iter()
        .map(|kb| {
            if use_sparse {
                let key = decode_dpf_key(kb)?;
                eval_parity_share_sparse(&key, &ones, party)
            } else {
                eval_parity_share(kb, &db, party)
            }
        })
        .collect();
    let ans = ans.map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    // keys_sha256 and resp_sha256 are over raw bytes / shares (same as JSON endpoint).
    let mut hk = Sha256::new();
    for kb in keys.iter() {
        hk.update(kb);
    }
    let keys_sha256 = hex::encode(hk.finalize());

    let mut hr = Sha256::new();
    hr.update(&ans);
    let resp_sha256 = hex::encode(hr.finalize());

    let ts = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()) as i64;

    let kid = st.active_kid.clone();
    let key = st
        .mac_keys
        .get(&kid)
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "missing mac key".to_string()))?;

    let mut payload: BTreeMap<&str, Value> = BTreeMap::new();
    payload.insert("v", Value::from(1));
    payload.insert("kind", Value::from("bit"));
    payload.insert("server_id", Value::from(st.server_id as i64));
    payload.insert("kid", Value::from(kid.clone()));
    payload.insert("ts", Value::from(ts));
    payload.insert("action_id", Value::from(action_id.clone()));
    payload.insert("db", Value::from(db_name.clone()));
    payload.insert("keys_sha256", Value::from(keys_sha256));
    payload.insert("resp_sha256", Value::from(resp_sha256));

    let mac_b64 = sign_payload(key, &payload);
    let mut proof_obj = serde_json::Map::new();
    for (k, v) in payload.into_iter() {
        proof_obj.insert(k.to_string(), v);
    }
    proof_obj.insert("mac_b64".to_string(), Value::from(mac_b64));
    let proof_bytes = serde_json::to_vec(&Value::Object(proof_obj))
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "bad_proof_json".to_string()))?;

    let mut out = Vec::with_capacity(4 + 1 + 1 + 2 + 4 + ans.len() + 4 + proof_bytes.len());
    out.extend_from_slice(BIN_MAGIC);
    out.push(BIN_VER);
    out.push(BIN_MSG_PIR_BATCH_SIGNED);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(n_keys as u32).to_le_bytes());
    out.extend_from_slice(&ans);
    out.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&proof_bytes);
    Ok(octet_response(out))
}

async fn pir_query_batch_multi_signed(
    State(st): State<AppState>,
    Json(q): Json<PirQueryBatchMultiSigned>,
) -> Result<Json<PirAnsBatchMultiSigned>, (StatusCode, String)> {
    let db = get_bitset(&st, &q.db).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let ones = get_bitset_ones(&st, &q.db).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let party = st.server_id;
    let mode = env::var("PIR_EVAL_MODE").unwrap_or_else(|_| "auto".to_string());
    let mode = mode.trim().to_ascii_lowercase();
    let domain_size = db.len() * 8;
    let mut tmp = domain_size;
    let mut domain_bits = 0usize;
    while tmp > 1 {
        domain_bits += 1;
        tmp >>= 1;
    }
    let use_sparse = if mode == "sparse" {
        true
    } else if mode == "dense" {
        false
    } else {
        prefer_sparse(domain_size, domain_bits, ones.len())
    };

    let ts = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()) as i64;

    let kid = st.active_kid.clone();
    let key = st
        .mac_keys
        .get(&kid)
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "missing mac key".to_string()))?;

    let responses: Result<Vec<PirSubAnsBatchSigned>, (StatusCode, String)> = q
        .requests
        .par_iter()
        .map(|sub| {
            let decoded_keys: Result<Vec<Vec<u8>>, (StatusCode, String)> = sub
                .dpf_keys_b64
                .iter()
                .map(|k| {
                    B64.decode(k.as_bytes())
                        .map_err(|_| (StatusCode::BAD_REQUEST, "bad base64 key".to_string()))
                })
                .collect();
            let decoded_keys = decoded_keys?;

            let ans: Result<Vec<u8>, (StatusCode, String)> = decoded_keys
                .iter()
                .map(|kb| {
                    if use_sparse {
                        let key = decode_dpf_key(kb).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
                        eval_parity_share_sparse(&key, &ones, party).map_err(|e| (StatusCode::BAD_REQUEST, e))
                    } else {
                        eval_parity_share(kb, &db, party).map_err(|e| (StatusCode::BAD_REQUEST, e))
                    }
                })
                .collect();
            let ans = ans?;

            let mut keys_concat = Vec::new();
            for kb in decoded_keys.iter() {
                keys_concat.extend_from_slice(kb);
            }
            let keys_sha256 = sha256_hex(&keys_concat);
            let resp_sha256 = sha256_hex(&ans.iter().map(|x| x & 1).collect::<Vec<u8>>());

            let mut payload: BTreeMap<&str, Value> = BTreeMap::new();
            payload.insert("v", Value::from(1));
            payload.insert("kind", Value::from("bit"));
            payload.insert("server_id", Value::from(st.server_id as i64));
            payload.insert("kid", Value::from(kid.clone()));
            payload.insert("ts", Value::from(ts));
            payload.insert("action_id", Value::from(sub.action_id.clone()));
            payload.insert("db", Value::from(q.db.clone()));
            payload.insert("keys_sha256", Value::from(keys_sha256));
            payload.insert("resp_sha256", Value::from(resp_sha256));

            let mac_b64 = sign_payload(key, &payload);
            let mut proof_obj = serde_json::Map::new();
            for (k, v) in payload.into_iter() {
                proof_obj.insert(k.to_string(), v);
            }
            proof_obj.insert("mac_b64".to_string(), Value::from(mac_b64));

            Ok(PirSubAnsBatchSigned {
                action_id: sub.action_id.clone(),
                ans_shares: ans,
                proof: Value::Object(proof_obj),
            })
        })
        .collect();

    let responses = responses?;
    Ok(Json(PirAnsBatchMultiSigned { responses }))
}

async fn pir_query_batch_multi_signed_bin(State(st): State<AppState>, body: Bytes) -> Result<Response, (StatusCode, String)> {
    let mut c = BinCur::new(&body);
    let magic = c.take(4).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    if magic != BIN_MAGIC {
        return Err((StatusCode::BAD_REQUEST, "bin_bad_magic".to_string()));
    }
    let ver = c.u8().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    if ver != BIN_VER {
        return Err((StatusCode::BAD_REQUEST, "bin_bad_version".to_string()));
    }
    let msg = c.u8().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    if msg != BIN_MSG_PIR_MULTI_SIGNED {
        return Err((StatusCode::BAD_REQUEST, "bin_bad_msg".to_string()));
    }
    let _ = c.u16_le().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let db_name = c.str_u32().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let n_sub = c.u32_le().map_err(|e| (StatusCode::BAD_REQUEST, e))? as usize;
    let keys_per = c.u32_le().map_err(|e| (StatusCode::BAD_REQUEST, e))? as usize;
    let key_len = c.u16_le().map_err(|e| (StatusCode::BAD_REQUEST, e))? as usize;
    if n_sub == 0 || n_sub > 2048 || keys_per == 0 || keys_per > 4096 || key_len == 0 || key_len > 4096 {
        return Err((StatusCode::BAD_REQUEST, "bin_bad_shape".to_string()));
    }

    struct Sub<'a> {
        action_id: String,
        keys: Vec<&'a [u8]>,
    }
    let mut subs: Vec<Sub> = Vec::with_capacity(n_sub);
    for _ in 0..n_sub {
        let action_id = c.str_u32().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        let kb = c
            .take(keys_per.saturating_mul(key_len))
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        let mut keys: Vec<&[u8]> = Vec::with_capacity(keys_per);
        for i in 0..keys_per {
            let off = i * key_len;
            keys.push(&kb[off..off + key_len]);
        }
        subs.push(Sub { action_id, keys });
    }

    let db = get_bitset(&st, &db_name).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let ones = get_bitset_ones(&st, &db_name).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let party = st.server_id;
    let mode = env::var("PIR_EVAL_MODE").unwrap_or_else(|_| "auto".to_string());
    let mode = mode.trim().to_ascii_lowercase();
    let domain_size = db.len() * 8;
    let mut tmp = domain_size;
    let mut domain_bits = 0usize;
    while tmp > 1 {
        domain_bits += 1;
        tmp >>= 1;
    }
    let use_sparse = if mode == "sparse" {
        true
    } else if mode == "dense" {
        false
    } else {
        prefer_sparse(domain_size, domain_bits, ones.len())
    };

    let ts = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()) as i64;

    let kid = st.active_kid.clone();
    let mac_key = st
        .mac_keys
        .get(&kid)
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "missing mac key".to_string()))?;

    // Evaluate all subrequests. Include action_id in each response so ordering is not security-sensitive.
    let responses: Result<Vec<(String, Vec<u8>, Vec<u8>)>, String> = subs
        .par_iter()
        .map(|sub| {
            let ans: Result<Vec<u8>, String> = sub
                .keys
                .iter()
                .map(|kb| {
                    if use_sparse {
                        let key = decode_dpf_key(kb)?;
                        eval_parity_share_sparse(&key, &ones, party)
                    } else {
                        eval_parity_share(kb, &db, party)
                    }
                })
                .collect();
            let ans = ans?;

            let mut hk = Sha256::new();
            for kb in sub.keys.iter() {
                hk.update(kb);
            }
            let keys_sha256 = hex::encode(hk.finalize());
            let mut hr = Sha256::new();
            hr.update(&ans);
            let resp_sha256 = hex::encode(hr.finalize());

            let mut payload: BTreeMap<&str, Value> = BTreeMap::new();
            payload.insert("v", Value::from(1));
            payload.insert("kind", Value::from("bit"));
            payload.insert("server_id", Value::from(st.server_id as i64));
            payload.insert("kid", Value::from(kid.clone()));
            payload.insert("ts", Value::from(ts));
            payload.insert("action_id", Value::from(sub.action_id.clone()));
            payload.insert("db", Value::from(db_name.clone()));
            payload.insert("keys_sha256", Value::from(keys_sha256));
            payload.insert("resp_sha256", Value::from(resp_sha256));

            let mac_b64 = sign_payload(mac_key, &payload);
            let mut proof_obj = serde_json::Map::new();
            for (k, v) in payload.into_iter() {
                proof_obj.insert(k.to_string(), v);
            }
            proof_obj.insert("mac_b64".to_string(), Value::from(mac_b64));
            let proof_bytes = serde_json::to_vec(&Value::Object(proof_obj)).map_err(|_| "bad_proof_json".to_string())?;

            Ok((sub.action_id.clone(), ans, proof_bytes))
        })
        .collect();
    let responses = responses.map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let mut out = Vec::new();
    out.extend_from_slice(BIN_MAGIC);
    out.push(BIN_VER);
    out.push(BIN_MSG_PIR_MULTI_SIGNED);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(n_sub as u32).to_le_bytes());
    for (aid, ans, proof_bytes) in responses.into_iter() {
        out.extend_from_slice(&(aid.as_bytes().len() as u32).to_le_bytes());
        out.extend_from_slice(aid.as_bytes());
        out.extend_from_slice(&(ans.len() as u32).to_le_bytes());
        out.extend_from_slice(&ans);
        out.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&proof_bytes);
    }
    Ok(octet_response(out))
}

async fn pir_query_block_batch_signed(
    State(st): State<AppState>,
    Json(q): Json<PirQueryBatchSigned>,
) -> Result<Json<PirBlockBatchSigned>, (StatusCode, String)> {
    let (db, block_size) = get_block_db(&st, &q.db).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let party = st.server_id;

    let decoded_keys: Result<Vec<Vec<u8>>, String> = q
        .dpf_keys_b64
        .iter()
        .map(|k| B64.decode(k.as_bytes()).map_err(|_| "bad base64 key".to_string()))
        .collect();
    let decoded_keys = decoded_keys.map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let shares: Result<Vec<Vec<u8>>, String> = decoded_keys
        .par_iter()
        .map(|kb| eval_block_share(kb, &db, block_size, party))
        .collect();
    let shares = shares.map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let block_shares_b64: Vec<String> = shares.iter().map(|b| B64.encode(b)).collect();

    let mut keys_concat = Vec::new();
    for kb in decoded_keys.iter() {
        keys_concat.extend_from_slice(kb);
    }
    let keys_sha256 = sha256_hex(&keys_concat);
    let mut resp_concat = Vec::new();
    for b in shares.iter() {
        resp_concat.extend_from_slice(b);
    }
    let resp_sha256 = sha256_hex(&resp_concat);

    let ts = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()) as i64;

    let kid = st.active_kid.clone();
    let key = st
        .mac_keys
        .get(&kid)
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "missing mac key".to_string()))?;

    let mut payload: BTreeMap<&str, Value> = BTreeMap::new();
    payload.insert("v", Value::from(1));
    payload.insert("kind", Value::from("block"));
    payload.insert("server_id", Value::from(st.server_id as i64));
    payload.insert("kid", Value::from(kid.clone()));
    payload.insert("ts", Value::from(ts));
    payload.insert("action_id", Value::from(q.action_id.clone()));
    payload.insert("db", Value::from(q.db.clone()));
    payload.insert("keys_sha256", Value::from(keys_sha256));
    payload.insert("resp_sha256", Value::from(resp_sha256));

    let mac_b64 = sign_payload(key, &payload);
    let mut proof_obj = serde_json::Map::new();
    for (k, v) in payload.into_iter() {
        proof_obj.insert(k.to_string(), v);
    }
    proof_obj.insert("mac_b64".to_string(), Value::from(mac_b64));

    Ok(Json(PirBlockBatchSigned {
        block_shares_b64,
        proof: Value::Object(proof_obj),
    }))
}

async fn pir_query_idx_batch_signed(
    State(st): State<AppState>,
    Json(q): Json<PirIdxBatchSigned>,
) -> Result<Json<PirIdxAnsSigned>, (StatusCode, String)> {
    let db = get_bitset(&st, &q.db).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let bits: Vec<u8> = q.idxs.par_iter().map(|idx| bit_at(&db, *idx)).collect();

    let idx_json = serde_json::to_vec(&q.idxs).unwrap_or_else(|_| b"[]".to_vec());
    let idxs_sha256 = sha256_hex(&idx_json);
    let resp_sha256 = sha256_hex(&bits.iter().map(|x| x & 1).collect::<Vec<u8>>());

    let ts = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()) as i64;

    let kid = st.active_kid.clone();
    let key = st
        .mac_keys
        .get(&kid)
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "missing mac key".to_string()))?;

    let mut payload: BTreeMap<&str, Value> = BTreeMap::new();
    payload.insert("v", Value::from(1));
    payload.insert("kind", Value::from("idx"));
    payload.insert("server_id", Value::from(st.server_id as i64));
    payload.insert("kid", Value::from(kid.clone()));
    payload.insert("ts", Value::from(ts));
    payload.insert("action_id", Value::from(q.action_id.clone()));
    payload.insert("db", Value::from(q.db.clone()));
    payload.insert("idxs_sha256", Value::from(idxs_sha256));
    payload.insert("resp_sha256", Value::from(resp_sha256));

    let mac_b64 = sign_payload(key, &payload);
    let mut proof_obj = serde_json::Map::new();
    for (k, v) in payload.into_iter() {
        proof_obj.insert(k.to_string(), v);
    }
    proof_obj.insert("mac_b64".to_string(), Value::from(mac_b64));

    Ok(Json(PirIdxAnsSigned {
        ans_bits: bits,
        proof: Value::Object(proof_obj),
    }))
}

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn cleanup_mpc_sessions(map: &mut HashMap<String, MpcSession>) {
    let now = now_s();
    map.retain(|_, s| !s.expired(now));
}

async fn mpc_init(State(st): State<AppState>, Json(req): Json<MpcInitReq>) -> Result<Json<Value>, (StatusCode, String)> {
    let mut wires: Vec<Option<u8>> = vec![None; req.n_wires];
    for (k, v) in req.input_shares.iter() {
        let idx: usize = k.parse::<usize>().map_err(|_| (StatusCode::BAD_REQUEST, "bad_wire_index".to_string()))?;
        if idx >= wires.len() {
            return Err((StatusCode::BAD_REQUEST, "wire_oob".to_string()));
        }
        wires[idx] = Some(v & 1);
    }
    let ttl = req.ttl_seconds.unwrap_or(30);
    let sess = MpcSession {
        program_id: req.program_id.clone(),
        request_sha256: req.request_sha256.clone(),
        created_at: now_s(),
        ttl_seconds: ttl,
        gates: req.gates.clone(),
        wires,
        outputs: req.outputs.clone(),
        pending: HashMap::new(),
    };

    let mut map = st.mpc_sessions.lock().unwrap();
    cleanup_mpc_sessions(&mut map);
    map.insert(req.action_id.clone(), sess);
    Ok(Json(json!({"ok": true, "party": st.server_id, "gates": req.gates.len()})))
}

async fn mpc_and_mask(State(st): State<AppState>, Json(req): Json<MpcAndMaskReq>) -> Result<Json<Value>, (StatusCode, String)> {
    let mut map = st.mpc_sessions.lock().unwrap();
    cleanup_mpc_sessions(&mut map);
    let sess = map.get_mut(&req.action_id).ok_or_else(|| (StatusCode::BAD_REQUEST, "missing_session".to_string()))?;
    let (d, e) = sess
        .and_mask(st.server_id, req.gate_index, req.a_share, req.b_share, req.c_share)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!({"d_share": d & 1, "e_share": e & 1})))
}

async fn mpc_and_mask_batch(
    State(st): State<AppState>,
    Json(req): Json<MpcAndMaskBatchReq>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let mut map = st.mpc_sessions.lock().unwrap();
    cleanup_mpc_sessions(&mut map);
    let sess = map
        .get_mut(&req.action_id)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "missing_session".to_string()))?;

    sess.eval_local(st.server_id)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let mut d_shares: Vec<u8> = Vec::with_capacity(req.triples.len());
    let mut e_shares: Vec<u8> = Vec::with_capacity(req.triples.len());
    for t in req.triples.iter() {
        if t.gate_index >= sess.gates.len() {
            return Err((StatusCode::BAD_REQUEST, "gate_oob".to_string()));
        }
        let g = &sess.gates[t.gate_index];
        if g.op.to_ascii_uppercase() != "AND" {
            return Err((StatusCode::BAD_REQUEST, "not_and_gate".to_string()));
        }
        let a = g.a.ok_or_else(|| (StatusCode::BAD_REQUEST, "bad_gate".to_string()))?;
        let b = g.b.ok_or_else(|| (StatusCode::BAD_REQUEST, "bad_gate".to_string()))?;
        // Require inputs ready.
        let _ = sess
            .wire(a)
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        let _ = sess
            .wire(b)
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

        sess.pending.insert(
            t.gate_index,
            (t.a_share & 1, t.b_share & 1, t.c_share & 1),
        );
        let d_share = (sess.wire(a).unwrap() ^ (t.a_share & 1)) & 1;
        let e_share = (sess.wire(b).unwrap() ^ (t.b_share & 1)) & 1;
        d_shares.push(d_share);
        e_shares.push(e_share);
    }

    Ok(Json(json!({"d_shares": d_shares, "e_shares": e_shares})))
}

async fn mpc_and_mask_multi(
    State(st): State<AppState>,
    Json(req): Json<MpcAndMaskMultiReq>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let mut map = st.mpc_sessions.lock().unwrap();
    cleanup_mpc_sessions(&mut map);

    let mut responses: Vec<Value> = Vec::with_capacity(req.requests.len());
    for sub in req.requests.iter() {
        let sess = match map.get_mut(&sub.action_id) {
            Some(s) => s,
            None => {
                responses.push(json!({"action_id": sub.action_id, "ok": false, "error": "missing_session", "d_shares": [], "e_shares": []}));
                continue;
            }
        };

        if let Err(e) = sess.eval_local(st.server_id) {
            responses.push(json!({"action_id": sub.action_id, "ok": false, "error": e, "d_shares": [], "e_shares": []}));
            continue;
        }

        let mut d_shares: Vec<u8> = Vec::with_capacity(sub.triples.len());
        let mut e_shares: Vec<u8> = Vec::with_capacity(sub.triples.len());
        let mut ok = true;
        let mut err_msg: String = String::new();
        for t in sub.triples.iter() {
            if t.gate_index >= sess.gates.len() {
                ok = false;
                err_msg = "gate_oob".to_string();
                break;
            }
            let g = &sess.gates[t.gate_index];
            if g.op.to_ascii_uppercase() != "AND" {
                ok = false;
                err_msg = "not_and_gate".to_string();
                break;
            }
            let a = match g.a {
                Some(v) => v,
                None => {
                    ok = false;
                    err_msg = "bad_gate".to_string();
                    break;
                }
            };
            let b = match g.b {
                Some(v) => v,
                None => {
                    ok = false;
                    err_msg = "bad_gate".to_string();
                    break;
                }
            };
            if sess.wire(a).is_err() || sess.wire(b).is_err() {
                ok = false;
                err_msg = "and_inputs_not_ready".to_string();
                break;
            }

            sess.pending.insert(t.gate_index, (t.a_share & 1, t.b_share & 1, t.c_share & 1));
            let d_share = (sess.wire(a).unwrap() ^ (t.a_share & 1)) & 1;
            let e_share = (sess.wire(b).unwrap() ^ (t.b_share & 1)) & 1;
            d_shares.push(d_share);
            e_shares.push(e_share);
        }

        if ok {
            responses.push(json!({"action_id": sub.action_id, "ok": true, "d_shares": d_shares, "e_shares": e_shares}));
        } else {
            responses.push(json!({"action_id": sub.action_id, "ok": false, "error": err_msg, "d_shares": [], "e_shares": []}));
        }
    }

    Ok(Json(json!({"responses": responses})))
}

async fn mpc_and_finish(State(st): State<AppState>, Json(req): Json<MpcAndFinishReq>) -> Result<Json<Value>, (StatusCode, String)> {
    let mut map = st.mpc_sessions.lock().unwrap();
    cleanup_mpc_sessions(&mut map);
    let sess = map.get_mut(&req.action_id).ok_or_else(|| (StatusCode::BAD_REQUEST, "missing_session".to_string()))?;
    let z = sess
        .and_finish(st.server_id, req.gate_index, req.d, req.e)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!({"z_share": z & 1})))
}

async fn mpc_and_finish_batch(
    State(st): State<AppState>,
    Json(req): Json<MpcAndFinishBatchReq>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let mut map = st.mpc_sessions.lock().unwrap();
    cleanup_mpc_sessions(&mut map);
    let sess = map
        .get_mut(&req.action_id)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "missing_session".to_string()))?;

    let mut z_shares: Vec<u8> = Vec::with_capacity(req.opens.len());
    for it in req.opens.iter() {
        if it.gate_index >= sess.gates.len() {
            return Err((StatusCode::BAD_REQUEST, "gate_oob".to_string()));
        }
        let g = &sess.gates[it.gate_index];
        if g.op.to_ascii_uppercase() != "AND" {
            return Err((StatusCode::BAD_REQUEST, "not_and_gate".to_string()));
        }
        let (a_share, b_share, c_share) = sess
            .pending
            .remove(&it.gate_index)
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "missing_triple".to_string()))?;
        let dd = it.d & 1;
        let ee = it.e & 1;
        let mut z = (c_share ^ (dd & b_share) ^ (ee & a_share)) & 1;
        if st.server_id == 0 {
            z ^= (dd & ee) & 1;
        }
        sess.set_wire(g.out, z)
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        z_shares.push(z & 1);
    }

    sess.eval_local(st.server_id)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!({"ok": true, "z_shares": z_shares})))
}

async fn mpc_and_finish_multi(
    State(st): State<AppState>,
    Json(req): Json<MpcAndFinishMultiReq>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let mut map = st.mpc_sessions.lock().unwrap();
    cleanup_mpc_sessions(&mut map);

    let mut responses: Vec<Value> = Vec::with_capacity(req.requests.len());
    for sub in req.requests.iter() {
        let sess = match map.get_mut(&sub.action_id) {
            Some(s) => s,
            None => {
                responses.push(json!({"action_id": sub.action_id, "ok": false, "error": "missing_session", "z_shares": []}));
                continue;
            }
        };

        let mut z_shares: Vec<u8> = Vec::with_capacity(sub.opens.len());
        let mut ok = true;
        let mut err_msg: String = String::new();

        for it in sub.opens.iter() {
            if it.gate_index >= sess.gates.len() {
                ok = false;
                err_msg = "gate_oob".to_string();
                break;
            }
            let g = &sess.gates[it.gate_index];
            if g.op.to_ascii_uppercase() != "AND" {
                ok = false;
                err_msg = "not_and_gate".to_string();
                break;
            }
            let (a_share, b_share, c_share) = match sess.pending.remove(&it.gate_index) {
                Some(x) => x,
                None => {
                    ok = false;
                    err_msg = "missing_triple".to_string();
                    break;
                }
            };
            let dd = it.d & 1;
            let ee = it.e & 1;
            let mut z = (c_share ^ (dd & b_share) ^ (ee & a_share)) & 1;
            if st.server_id == 0 {
                z ^= (dd & ee) & 1;
            }
            if let Err(e) = sess.set_wire(g.out, z) {
                ok = false;
                err_msg = e;
                break;
            }
            z_shares.push(z & 1);
        }

        if ok {
            if let Err(e) = sess.eval_local(st.server_id) {
                responses.push(json!({"action_id": sub.action_id, "ok": false, "error": e, "z_shares": []}));
                continue;
            }
            responses.push(json!({"action_id": sub.action_id, "ok": true, "z_shares": z_shares}));
        } else {
            responses.push(json!({"action_id": sub.action_id, "ok": false, "error": err_msg, "z_shares": []}));
        }
    }

    Ok(Json(json!({"responses": responses})))
}

async fn mpc_finalize(State(st): State<AppState>, Json(req): Json<MpcFinalizeReq>) -> Result<Json<Value>, (StatusCode, String)> {
    let mut sess = {
        let mut map = st.mpc_sessions.lock().unwrap();
        cleanup_mpc_sessions(&mut map);
        map.remove(&req.action_id)
    }
    .ok_or_else(|| (StatusCode::BAD_REQUEST, "missing_session".to_string()))?;

    let outs = sess.finalize(st.server_id).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let kid = st.active_kid.clone();
    let key = st
        .mac_keys
        .get(&kid)
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "missing mac key".to_string()))?;

    let mut tag = [0u8; 16];
    OsRng.fill_bytes(&mut tag);
    let tag_b64 = B64.encode(tag);
    let ts = now_s() as i64;

    let mut outs_obj = serde_json::Map::new();
    for (k, v) in outs.iter() {
        outs_obj.insert(k.clone(), Value::from((*v & 1) as i64));
    }

    let mut payload: BTreeMap<&str, Value> = BTreeMap::new();
    payload.insert("v", Value::from(1));
    payload.insert("kind", Value::from("commit"));
    payload.insert("server_id", Value::from(st.server_id as i64));
    payload.insert("kid", Value::from(kid.clone()));
    payload.insert("ts", Value::from(ts));
    payload.insert("action_id", Value::from(req.action_id.clone()));
    payload.insert("program_id", Value::from(sess.program_id.clone()));
    payload.insert("request_sha256", Value::from(sess.request_sha256.clone()));
    payload.insert("outputs", Value::Object(outs_obj));
    payload.insert("commit_tag_share_b64", Value::from(tag_b64.clone()));

    let mac_b64 = sign_payload(key, &payload);
    let mut proof_obj = serde_json::Map::new();
    for (k, v) in payload.into_iter() {
        proof_obj.insert(k.to_string(), v);
    }
    proof_obj.insert("mac_b64".to_string(), Value::from(mac_b64));

    Ok(Json(json!({
        "ok": true,
        "outputs": outs,
        "proof": Value::Object(proof_obj),
    })))
}

fn bitset_ones(db: &[u8]) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::new();
    for (byte_i, &b) in db.iter().enumerate() {
        if b == 0 {
            continue;
        }
        let mut bb = b;
        while bb != 0 {
            let tz = bb.trailing_zeros() as usize;
            out.push((byte_i * 8 + tz) as u32);
            bb &= bb - 1;
        }
    }
    out
}

fn load_bitsets(data_dir: &Path) -> (HashMap<String, Arc<Vec<u8>>>, HashMap<String, Arc<Vec<u32>>>) {
    let mut bitsets: HashMap<String, Arc<Vec<u8>>> = HashMap::new();
    let mut ones: HashMap<String, Arc<Vec<u32>>> = HashMap::new();
    if let Ok(rd) = fs::read_dir(data_dir) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension().and_then(|s| s.to_str()) == Some("bitset") {
                if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                    if let Ok(b) = fs::read(&p) {
                        ones.insert(stem.to_string(), Arc::new(bitset_ones(&b)));
                        bitsets.insert(stem.to_string(), Arc::new(b));
                    }
                }
            }
        }
    }
    (bitsets, ones)
}

fn load_blocks(data_dir: &Path) -> HashMap<String, (Arc<Vec<u8>>, usize)> {
    let mut out = HashMap::new();

    // Best-effort: read meta to get DFA block_size.
    let mut dfa_block: Option<(String, usize)> = None;
    let meta_path = data_dir.join("meta.json");
    if let Ok(s) = fs::read_to_string(&meta_path) {
        if let Ok(v) = serde_json::from_str::<Value>(&s) {
            if let Some(dfa) = v.get("dfa") {
                let db = dfa
                    .get("db")
                    .and_then(|x| x.as_str())
                    .unwrap_or("dfa_transitions")
                    .to_string();
                let bs = dfa.get("block_size").and_then(|x| x.as_u64()).unwrap_or(4) as usize;
                dfa_block = Some((db, bs));
            }
        }
    }

    if let Ok(rd) = fs::read_dir(data_dir) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension().and_then(|s| s.to_str()) == Some("blk") {
                if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                    if let Ok(b) = fs::read(&p) {
                        let bs = dfa_block
                            .as_ref()
                            .and_then(|(name, sz)| if name == stem { Some(*sz) } else { None })
                            .unwrap_or(4);
                        out.insert(stem.to_string(), (Arc::new(b), bs));
                    }
                }
            }
        }
    }
    out
}

#[tokio::main]
async fn main() {
    let server_id: u8 = env::var("SERVER_ID")
        .ok()
        .and_then(|s| s.parse::<u8>().ok())
        .unwrap_or(0);
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(9001);
    let data_dir = env::var("DATA_DIR").unwrap_or_else(|_| "policy_server/data".to_string());
    let data_dir = PathBuf::from(data_dir);

    let mut mac_keys = HashMap::new();
    let mac_keys_env = env::var("POLICY_MAC_KEYS").unwrap_or_default();
    if !mac_keys_env.trim().is_empty() {
        mac_keys = parse_mac_keys(&mac_keys_env);
    } else if let Ok(hexkey) = env::var("POLICY_MAC_KEY") {
        if !hexkey.trim().is_empty() {
            mac_keys.insert("0".to_string(), hex::decode(hexkey.trim()).unwrap_or_default());
        }
    }
    let active_kid = env::var("POLICY_MAC_ACTIVE_KID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| mac_keys.keys().next().cloned().unwrap_or_else(|| "0".to_string()));

    let (bitsets, bitset_ones) = load_bitsets(&data_dir);
    let bitsets = Arc::new(bitsets);
    let bitset_ones = Arc::new(bitset_ones);
    let blocks = Arc::new(load_blocks(&data_dir));

    let st = AppState {
        server_id,
        data_dir,
        mac_keys,
        active_kid,
        bitsets,
        bitset_ones,
        blocks,
        mpc_sessions: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/meta", get(meta))
        .route("/pir/query_batch", post(pir_query_batch))
        .route("/pir/query_batch_bin", post(pir_query_batch_bin))
        .route("/pir/query_block_batch", post(pir_query_block_batch))
        .route("/pir/query_idx_batch", post(pir_query_idx_batch))
        .route("/pir/query_batch_signed", post(pir_query_batch_signed))
        .route("/pir/query_batch_signed_bin", post(pir_query_batch_signed_bin))
        .route("/pir/query_batch_multi_signed", post(pir_query_batch_multi_signed))
        .route("/pir/query_batch_multi_signed_bin", post(pir_query_batch_multi_signed_bin))
        .route("/pir/query_block_batch_signed", post(pir_query_block_batch_signed))
        .route("/pir/query_idx_batch_signed", post(pir_query_idx_batch_signed))
        .route("/mpc/init", post(mpc_init))
        .route("/mpc/and_mask", post(mpc_and_mask))
        .route("/mpc/and_mask_batch", post(mpc_and_mask_batch))
        .route("/mpc/and_mask_multi", post(mpc_and_mask_multi))
        .route("/mpc/and_finish", post(mpc_and_finish))
        .route("/mpc/and_finish_batch", post(mpc_and_finish_batch))
        .route("/mpc/and_finish_multi", post(mpc_and_finish_multi))
        .route("/mpc/finalize", post(mpc_finalize))
        .with_state(st);

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

    // Optional Unix-domain-socket listener for same-host deployments.
    // This is best-effort and does not replace the TCP listener (keeps the artifact
    // scripts backwards-compatible).
    if let Ok(p) = env::var("POLICY_UDS_PATH") {
        let uds_path = p.trim().to_string();
        if !uds_path.is_empty() {
            let app2 = app.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_unix(uds_path, app2).await {
                    eprintln!("[policy_server] uds serve error: {}", e);
                }
            });
        }
    }

    axum::serve(listener, app).tcp_nodelay(true).await.unwrap();
}

async fn serve_unix(uds_path: String, app: Router) -> std::io::Result<()> {
    // Clean up stale socket file (common when a previous run crashed).
    if let Some(parent) = Path::new(&uds_path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::remove_file(&uds_path);
    let listener = tokio::net::UnixListener::bind(&uds_path)?;
    loop {
        let (stream, _addr) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let tower_service = app.clone().map_request(|req: axum::http::Request<Incoming>| req.map(Body::new));
        let hyper_service = TowerToHyperService::new(tower_service);
        tokio::spawn(async move {
            let _ = Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, hyper_service)
                .await;
        });
    }
}
