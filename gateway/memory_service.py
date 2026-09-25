from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


def _default_memory_db_path() -> str:
    return str(Path(__file__).resolve().parents[1] / "artifact_out" / "memory.sqlite")


@dataclass(frozen=True, slots=True)
class MemoryRecord:
    memory_id: str
    namespace: str
    key: str
    session: str
    caller: str
    sensitivity: str
    created_at: float
    updated_at: float
    value: Dict[str, Any]
    revoked: bool = False


class MemoryService:
    """
    Persistent mediated memory store.

    No plaintext is returned directly to callers; callers must obtain handles through
    gateway intents and declassify explicitly.
    """

    def __init__(self, db_path: str | None = None):
        self._db_path = (db_path or os.getenv("MEMORY_DB_PATH", "").strip()) or _default_memory_db_path()
        self._db = sqlite3.connect(self._db_path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS memory_entries (
                  memory_id TEXT PRIMARY KEY,
                  namespace TEXT NOT NULL,
                  key TEXT NOT NULL,
                  session TEXT NOT NULL,
                  caller TEXT NOT NULL,
                  sensitivity TEXT NOT NULL,
                  created_at REAL NOT NULL,
                  updated_at REAL NOT NULL,
                  value_json TEXT NOT NULL,
                  revoked INTEGER NOT NULL
                )
                """
            )
            self._db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_memory_ns_key_session ON memory_entries(namespace, key, session, caller)"
            )
            self._db.commit()

    def upsert(
        self,
        *,
        namespace: str,
        key: str,
        value: Dict[str, Any],
        sensitivity: str,
        session: str,
        caller: str,
    ) -> MemoryRecord:
        ns = str(namespace or "default")
        kk = str(key or "").strip()
        if not kk:
            raise ValueError("missing memory key")
        sens = str(sensitivity or "MED").upper()
        now = float(time.time())
        with self._lock:
            row = self._db.execute(
                """
                SELECT memory_id, created_at FROM memory_entries
                WHERE namespace=? AND key=? AND session=? AND caller=? AND revoked=0
                """,
                (ns, kk, str(session), str(caller)),
            ).fetchone()
            if row:
                memory_id = str(row[0])
                created_at = float(row[1])
            else:
                memory_id = f"mem_{secrets.token_urlsafe(12)}"
                created_at = now
            self._db.execute(
                """
                INSERT INTO memory_entries(memory_id, namespace, key, session, caller, sensitivity, created_at, updated_at, value_json, revoked)
                VALUES(?,?,?,?,?,?,?,?,?,0)
                ON CONFLICT(memory_id)
                DO UPDATE SET sensitivity=excluded.sensitivity, updated_at=excluded.updated_at, value_json=excluded.value_json, revoked=0
                """,
                (
                    memory_id,
                    ns,
                    kk,
                    str(session),
                    str(caller),
                    sens,
                    float(created_at),
                    now,
                    json.dumps(dict(value or {}), ensure_ascii=True),
                ),
            )
            self._db.commit()
        return MemoryRecord(
            memory_id=memory_id,
            namespace=ns,
            key=kk,
            session=str(session),
            caller=str(caller),
            sensitivity=sens,
            created_at=created_at,
            updated_at=now,
            value=dict(value or {}),
            revoked=False,
        )

    def get_by_key(self, *, namespace: str, key: str, session: str, caller: str) -> Optional[MemoryRecord]:
        ns = str(namespace or "default")
        kk = str(key or "").strip()
        if not kk:
            return None
        with self._lock:
            row = self._db.execute(
                """
                SELECT memory_id, namespace, key, session, caller, sensitivity, created_at, updated_at, value_json, revoked
                FROM memory_entries
                WHERE namespace=? AND key=? AND session=? AND caller=?
                """,
                (ns, kk, str(session), str(caller)),
            ).fetchone()
        if not row:
            return None
        return self._row_to_record(row)

    def list_keys(self, *, namespace: str, session: str, caller: str, limit: int = 100) -> list[str]:
        ns = str(namespace or "default")
        n = int(limit)
        if n < 1:
            n = 1
        if n > 500:
            n = 500
        with self._lock:
            rows = self._db.execute(
                """
                SELECT key FROM memory_entries
                WHERE namespace=? AND session=? AND caller=? AND revoked=0
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (ns, str(session), str(caller), n),
            ).fetchall()
        return [str(r[0]) for r in rows if r and r[0]]

    def revoke(self, *, namespace: str, key: str, session: str, caller: str) -> bool:
        ns = str(namespace or "default")
        kk = str(key or "").strip()
        if not kk:
            return False
        with self._lock:
            cur = self._db.execute(
                """
                UPDATE memory_entries
                SET revoked=1, updated_at=?
                WHERE namespace=? AND key=? AND session=? AND caller=? AND revoked=0
                """,
                (float(time.time()), ns, kk, str(session), str(caller)),
            )
            self._db.commit()
        return bool(cur.rowcount and int(cur.rowcount) > 0)

    def _row_to_record(self, row: tuple[Any, ...]) -> Optional[MemoryRecord]:
        try:
            revoked = bool(int(row[9]))
        except Exception:
            revoked = False
        if revoked:
            return None
        try:
            value = json.loads(str(row[8]))
        except Exception:
            value = {"raw": str(row[8])}
        if not isinstance(value, dict):
            value = {"value": value}
        return MemoryRecord(
            memory_id=str(row[0]),
            namespace=str(row[1]),
            key=str(row[2]),
            session=str(row[3]),
            caller=str(row[4]),
            sensitivity=str(row[5]),
            created_at=float(row[6]),
            updated_at=float(row[7]),
            value=value,
            revoked=revoked,
        )
