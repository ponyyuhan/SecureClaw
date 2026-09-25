from __future__ import annotations

import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


def _default_delegation_db_path() -> str:
    return str(Path(__file__).resolve().parents[1] / "artifact_out" / "delegation.sqlite")


@dataclass(frozen=True, slots=True)
class RevocationRecord:
    jti: str
    revoked_at: float
    session: str
    caller: str
    reason: str


class DelegationStore:
    """
    Persistent revocation list for delegation tokens.

    The delegation token itself is stateless and signed. Revocation is enforced by
    consulting this deny-list on every authorized call.
    """

    def __init__(self, db_path: str | None = None):
        self._db_path = (db_path or os.getenv("DELEGATION_DB_PATH", "").strip()) or _default_delegation_db_path()
        self._db = sqlite3.connect(self._db_path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS delegation_revocations (
                  jti TEXT PRIMARY KEY,
                  revoked_at REAL NOT NULL,
                  session TEXT NOT NULL,
                  caller TEXT NOT NULL,
                  reason TEXT NOT NULL
                )
                """
            )
            self._db.commit()

    def revoke(self, *, jti: str, session: str, caller: str, reason: str = "") -> bool:
        jj = str(jti or "").strip()
        if not jj:
            return False
        with self._lock:
            self._db.execute(
                """
                INSERT OR REPLACE INTO delegation_revocations(jti, revoked_at, session, caller, reason)
                VALUES(?,?,?,?,?)
                """,
                (jj, float(time.time()), str(session or ""), str(caller or ""), str(reason or "")),
            )
            self._db.commit()
        return True

    def is_revoked(self, jti: str) -> bool:
        jj = str(jti or "").strip()
        if not jj:
            return False
        with self._lock:
            row = self._db.execute("SELECT jti FROM delegation_revocations WHERE jti=?", (jj,)).fetchone()
        return bool(row)

    def get(self, jti: str) -> Optional[RevocationRecord]:
        jj = str(jti or "").strip()
        if not jj:
            return None
        with self._lock:
            row = self._db.execute(
                "SELECT jti, revoked_at, session, caller, reason FROM delegation_revocations WHERE jti=?",
                (jj,),
            ).fetchone()
        if not row:
            return None
        return RevocationRecord(jti=str(row[0]), revoked_at=float(row[1]), session=str(row[2]), caller=str(row[3]), reason=str(row[4]))
