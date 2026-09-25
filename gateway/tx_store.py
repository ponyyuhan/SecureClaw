from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class TxRecord:
    tx_id: str
    intent_id: str
    action_id: str
    request_sha256: str
    caller: str
    session: str
    created_at: float
    ttl_seconds: int
    preview: Dict[str, Any]
    revoked: bool = False

    def expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl_seconds


class TxStore:
    """PREVIEW->COMMIT transaction store in the trusted gateway boundary."""

    def __init__(self, db_path: str | None = None):
        self._store: Dict[str, TxRecord] = {}
        self._db_path = (db_path or os.getenv("TX_DB_PATH", "").strip()) or None
        self._db: sqlite3.Connection | None = None
        self._lock = threading.Lock()
        if self._db_path:
            self._db = sqlite3.connect(self._db_path, check_same_thread=False)
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS tx (
                  tx_id TEXT PRIMARY KEY,
                  intent_id TEXT NOT NULL,
                  action_id TEXT NOT NULL,
                  request_sha256 TEXT NOT NULL,
                  caller TEXT NOT NULL,
                  session TEXT NOT NULL,
                  created_at REAL NOT NULL,
                  ttl_seconds INTEGER NOT NULL,
                  preview_json TEXT NOT NULL,
                  revoked INTEGER NOT NULL
                )
                """
            )
            self._db.commit()

    def mint(
        self,
        *,
        intent_id: str,
        action_id: str,
        request_sha256: str,
        caller: str,
        session: str,
        preview: Dict[str, Any],
        ttl_seconds: int = 120,
    ) -> TxRecord:
        tx_id = f"tx_{secrets.token_urlsafe(16)}"
        rec = TxRecord(
            tx_id=tx_id,
            intent_id=str(intent_id),
            action_id=str(action_id),
            request_sha256=str(request_sha256),
            caller=str(caller),
            session=str(session),
            created_at=time.time(),
            ttl_seconds=int(ttl_seconds),
            preview=dict(preview or {}),
        )
        self._store[tx_id] = rec
        if self._db is not None:
            with self._lock:
                self._db.execute(
                    """
                    INSERT OR REPLACE INTO tx
                    (tx_id,intent_id,action_id,request_sha256,caller,session,created_at,ttl_seconds,preview_json,revoked)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        rec.tx_id,
                        rec.intent_id,
                        rec.action_id,
                        rec.request_sha256,
                        rec.caller,
                        rec.session,
                        float(rec.created_at),
                        int(rec.ttl_seconds),
                        json.dumps(rec.preview, ensure_ascii=True),
                        1 if rec.revoked else 0,
                    ),
                )
                self._db.commit()
        return rec

    def get(self, tx_id: str) -> Optional[TxRecord]:
        rec = self._store.get(tx_id)
        if not rec and self._db is not None:
            with self._lock:
                row = self._db.execute(
                    """
                    SELECT tx_id,intent_id,action_id,request_sha256,caller,session,created_at,ttl_seconds,preview_json,revoked
                    FROM tx WHERE tx_id=?
                    """,
                    (tx_id,),
                ).fetchone()
            if row:
                try:
                    preview = json.loads(row[8])
                except Exception:
                    preview = {}
                rec = TxRecord(
                    tx_id=str(row[0]),
                    intent_id=str(row[1]),
                    action_id=str(row[2]),
                    request_sha256=str(row[3]),
                    caller=str(row[4]),
                    session=str(row[5]),
                    created_at=float(row[6]),
                    ttl_seconds=int(row[7]),
                    preview=dict(preview) if isinstance(preview, dict) else {},
                    revoked=bool(int(row[9])),
                )
                self._store[rec.tx_id] = rec

        if not rec:
            return None
        if rec.revoked:
            return None
        if rec.expired():
            self._store.pop(tx_id, None)
            if self._db is not None:
                with self._lock:
                    self._db.execute("DELETE FROM tx WHERE tx_id=?", (tx_id,))
                    self._db.commit()
            return None
        return rec

    def revoke(self, tx_id: str) -> bool:
        rec = self._store.get(tx_id)
        if not rec and self._db is not None:
            rec = self.get(tx_id)
        if not rec:
            return False
        rec.revoked = True
        if self._db is not None:
            with self._lock:
                self._db.execute("UPDATE tx SET revoked=1 WHERE tx_id=?", (tx_id,))
                self._db.commit()
        return True

    def revoke_session(self, session: str) -> int:
        """
        Revoke all outstanding tx for a given session.

        This is a coarse emergency stop: once a session is revoked, any previously minted
        PREVIEW tokens are invalidated and cannot be committed.
        """
        n = 0
        for rec in self._store.values():
            if rec.session == session and not rec.revoked:
                rec.revoked = True
                n += 1
        if self._db is not None:
            with self._lock:
                cur = self._db.execute("UPDATE tx SET revoked=1 WHERE session=? AND revoked=0", (session,))
                self._db.commit()
                if cur.rowcount and int(cur.rowcount) > n:
                    n = int(cur.rowcount)
        return int(n)
