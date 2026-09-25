import time
import secrets
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, List
import json
import os
import sqlite3
import threading

@dataclass
class HandleRecord:
    handle: str
    label: str
    sensitivity: str  # LOW/MED/HIGH
    created_at: float
    ttl_seconds: int
    session: str
    caller: str  # untrusted identity string (for binding / audit)
    issuer_intent: str
    value: Any  # stored only in gateway TCB (demo)
    allowed_sinks: List[str]
    revoked: bool = False

    def expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl_seconds

class HandleStore:
    def __init__(self, db_path: str | None = None):
        self._store: Dict[str, HandleRecord] = {}
        self._db_path = (db_path or os.getenv("HANDLE_DB_PATH", "").strip()) or None
        self._db: sqlite3.Connection | None = None
        self._lock = threading.Lock()
        if self._db_path:
            self._db = sqlite3.connect(self._db_path, check_same_thread=False)
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS handles (
                  handle TEXT PRIMARY KEY,
                  label TEXT NOT NULL,
                  sensitivity TEXT NOT NULL,
                  created_at REAL NOT NULL,
                  ttl_seconds INTEGER NOT NULL,
                  session TEXT NOT NULL,
                  caller TEXT NOT NULL,
                  issuer_intent TEXT NOT NULL,
                  value_json TEXT NOT NULL,
                  allowed_sinks_json TEXT NOT NULL,
                  revoked INTEGER NOT NULL
                )
                """
            )
            self._db.commit()

    def mint(
        self,
        *,
        label: str,
        sensitivity: str,
        value: Any,
        allowed_sinks: List[str],
        session: str,
        ttl_seconds: int = 600,
        caller: str = "unknown",
        issuer_intent: str = "unknown",
    ) -> HandleRecord:
        hid = f"h_{secrets.token_urlsafe(16)}"
        rec = HandleRecord(
            handle=hid,
            label=label,
            sensitivity=sensitivity,
            created_at=time.time(),
            ttl_seconds=ttl_seconds,
            session=session,
            caller=caller,
            issuer_intent=issuer_intent,
            value=value,
            allowed_sinks=allowed_sinks,
        )
        self._store[hid] = rec
        if self._db is not None:
            try:
                value_json = json.dumps(rec.value, ensure_ascii=True)
            except Exception:
                value_json = json.dumps({"repr": repr(rec.value)}, ensure_ascii=True)
            try:
                sinks_json = json.dumps(list(rec.allowed_sinks or []), ensure_ascii=True)
            except Exception:
                sinks_json = json.dumps([], ensure_ascii=True)
            with self._lock:
                self._db.execute(
                    """
                    INSERT OR REPLACE INTO handles
                    (handle,label,sensitivity,created_at,ttl_seconds,session,caller,issuer_intent,value_json,allowed_sinks_json,revoked)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        rec.handle,
                        rec.label,
                        rec.sensitivity,
                        float(rec.created_at),
                        int(rec.ttl_seconds),
                        rec.session,
                        rec.caller,
                        rec.issuer_intent,
                        value_json,
                        sinks_json,
                        1 if rec.revoked else 0,
                    ),
                )
                self._db.commit()
        return rec

    def get(self, hid: str) -> Optional[HandleRecord]:
        rec = self._store.get(hid)
        if not rec and self._db is not None:
            with self._lock:
                row = self._db.execute(
                    """
                    SELECT handle,label,sensitivity,created_at,ttl_seconds,session,caller,issuer_intent,value_json,allowed_sinks_json,revoked
                    FROM handles WHERE handle=?
                    """,
                    (hid,),
                ).fetchone()
            if row:
                try:
                    value = json.loads(row[8])
                except Exception:
                    value = row[8]
                try:
                    allowed = json.loads(row[9])
                except Exception:
                    allowed = []
                rec = HandleRecord(
                    handle=str(row[0]),
                    label=str(row[1]),
                    sensitivity=str(row[2]),
                    created_at=float(row[3]),
                    ttl_seconds=int(row[4]),
                    session=str(row[5]),
                    caller=str(row[6]),
                    issuer_intent=str(row[7]),
                    value=value,
                    allowed_sinks=list(allowed) if isinstance(allowed, list) else [],
                    revoked=bool(int(row[10])),
                )
                self._store[hid] = rec

        if not rec:
            return None
        if rec.revoked:
            return None
        if rec.expired():
            self._store.pop(hid, None)
            if self._db is not None:
                with self._lock:
                    self._db.execute("DELETE FROM handles WHERE handle=?", (hid,))
                    self._db.commit()
            return None
        return rec

    def revoke(self, hid: str) -> bool:
        rec = self._store.get(hid)
        if not rec and self._db is not None:
            # Load for validation / cache update.
            rec = self.get(hid)
        if not rec:
            return False
        rec.revoked = True
        if self._db is not None:
            with self._lock:
                self._db.execute("UPDATE handles SET revoked=1 WHERE handle=?", (hid,))
                self._db.commit()
        return True

    def revoke_session(self, session: str) -> int:
        n = 0
        for rec in self._store.values():
            if rec.session == session and not rec.revoked:
                rec.revoked = True
                n += 1
        if self._db is not None:
            with self._lock:
                cur = self._db.execute("UPDATE handles SET revoked=1 WHERE session=? AND revoked=0", (session,))
                self._db.commit()
                # sqlite rowcount is best-effort; fall back to cache-based count.
                if cur.rowcount and cur.rowcount > n:
                    n = int(cur.rowcount)
        return n

    def describe(self, hid: str) -> Optional[Dict[str, Any]]:
        rec = self.get(hid)
        if not rec:
            return None
        # do NOT reveal value
        return {
            "handle": rec.handle,
            "label": rec.label,
            "sensitivity": rec.sensitivity,
            "ttl_seconds": rec.ttl_seconds,
            "caller": rec.caller,
            "issuer_intent": rec.issuer_intent,
        }
