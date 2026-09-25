from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Dict, List, Tuple

from fss.dpf import eval_dpf_pir_block_share, eval_dpf_pir_parity_share, eval_dpf_pir_parity_share_sparse


class BitsetDB:
    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self._bitsets: Dict[str, bytes] = {}
        self._blocks: Dict[str, Tuple[bytes, int]] = {}  # name -> (data, block_size)
        self._ones: Dict[str, Tuple[int, ...]] = {}  # name -> sorted indices where bitset has 1s

    def load(self) -> None:
        # Load all bitset DBs present on disk (keeps the server generic as we add new DBs).
        bitset_paths = sorted(self.data_dir.glob("*.bitset"))
        if not bitset_paths:
            raise FileNotFoundError(f"No .bitset DB files found under: {self.data_dir}")
        for p in bitset_paths:
            name = p.stem
            bs = p.read_bytes()
            self._bitsets[name] = bs

            # Precompute set-bit indices for a fast sparse inner-product path.
            ones: list[int] = []
            for byte_i, b in enumerate(bs):
                if b == 0:
                    continue
                for bit in range(8):
                    if (b >> bit) & 1:
                        ones.append(byte_i * 8 + bit)
            self._ones[name] = tuple(ones)

        # Optional block DBs (fixed-size blocks). Currently only DFA transitions are used by the demo,
        # but we load any *.blk for extensibility.
        for p in sorted(self.data_dir.glob("*.blk")):
            name = p.stem
            # Build script uses block_size=4; if you add more block DBs, encode block_size in meta.json.
            self._blocks[name] = (p.read_bytes(), 4)

    def _prefer_sparse(self, db_name: str) -> bool:
        """
        Heuristic: sparse evaluation costs O(|ones|*logN), dense costs O(N).
        Prefer sparse only when it is expected to be much cheaper (>=4x).
        """
        bs = self._bitsets.get(db_name) or b""
        nbits = len(bs) * 8
        if nbits <= 0 or (nbits & (nbits - 1)) != 0:
            return False
        domain_bits = nbits.bit_length() - 1
        ones = self._ones.get(db_name) or ()
        sparse_cost = len(ones) * (domain_bits + 1)
        dense_cost = nbits
        return sparse_cost * 4 < dense_cost

    def query_one(self, db_name: str, dpf_key_b64: str, *, party: int) -> int:
        if db_name not in self._bitsets:
            raise KeyError(f"Unknown db: {db_name}")
        key = base64.b64decode(dpf_key_b64)
        db = self._bitsets[db_name]
        mode = (os.getenv("PIR_EVAL_MODE", "auto") or "auto").strip().lower()
        use_sparse = mode == "sparse" or (mode == "auto" and self._prefer_sparse(db_name))
        if use_sparse:
            ones = self._ones.get(db_name) or ()
            return int(eval_dpf_pir_parity_share_sparse(key_bytes=key, ones=ones, party=party)) & 1
        return int(eval_dpf_pir_parity_share(key_bytes=key, db_bitset=db, party=party)) & 1

    def query_batch(self, db_name: str, dpf_keys_b64: List[str], *, party: int) -> List[int]:
        if db_name not in self._bitsets:
            raise KeyError(f"Unknown db: {db_name}")
        db = self._bitsets[db_name]
        mode = (os.getenv("PIR_EVAL_MODE", "auto") or "auto").strip().lower()
        use_sparse = mode == "sparse" or (mode == "auto" and self._prefer_sparse(db_name))
        ones = self._ones.get(db_name) or ()
        out: list[int] = []
        for k in dpf_keys_b64:
            key = base64.b64decode(k)
            if use_sparse:
                out.append(int(eval_dpf_pir_parity_share_sparse(key_bytes=key, ones=ones, party=party)) & 1)
            else:
                out.append(int(eval_dpf_pir_parity_share(key_bytes=key, db_bitset=db, party=party)) & 1)
        return out

    def query_block_batch(self, db_name: str, dpf_keys_b64: List[str], *, party: int) -> List[str]:
        if db_name not in self._blocks:
            raise KeyError(f"Unknown block db: {db_name}")
        db, block_size = self._blocks[db_name]
        out: list[str] = []
        for k in dpf_keys_b64:
            key = base64.b64decode(k)
            share = eval_dpf_pir_block_share(key_bytes=key, db_blocks=db, block_size=block_size, party=party)
            out.append(base64.b64encode(share).decode("ascii"))
        return out

    def query_idx_batch(self, db_name: str, idxs: List[int]) -> List[int]:
        """
        Single-server cleartext baseline query.

        This intentionally leaks query indices to the policy server and is used only
        for baseline/ablation experiments.
        """
        if db_name not in self._bitsets:
            raise KeyError(f"Unknown db: {db_name}")
        db = self._bitsets[db_name]
        nbits = len(db) * 8
        out: list[int] = []
        for idx in idxs:
            i = int(idx)
            if i < 0 or i >= nbits:
                out.append(0)
                continue
            out.append(int((db[i // 8] >> (i % 8)) & 1))
        return out
