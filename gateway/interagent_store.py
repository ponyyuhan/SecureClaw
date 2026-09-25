from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List


def _default_inter_agent_db_path() -> str:
    return str(Path(__file__).resolve().parents[1] / "artifact_out" / "inter_agent.sqlite")


@dataclass(frozen=True, slots=True)
class InterAgentMessage:
    message_id: str
    session: str
    from_agent: str
    to_agent: str
    payload_handle: str
    attachment_handles: List[str]
    created_at: float
    delivered_at: float


class InterAgentStore:
    def __init__(self, db_path: str | None = None):
        self._db_path = (db_path or os.getenv("INTER_AGENT_DB_PATH", "").strip()) or _default_inter_agent_db_path()
        self._db = sqlite3.connect(self._db_path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS inter_agent_messages (
                  message_id TEXT PRIMARY KEY,
                  session TEXT NOT NULL,
                  from_agent TEXT NOT NULL,
                  to_agent TEXT NOT NULL,
                  payload_handle TEXT NOT NULL,
                  attachment_handles_json TEXT NOT NULL,
                  created_at REAL NOT NULL,
                  delivered_at REAL NOT NULL
                )
                """
            )
            self._db.execute("CREATE INDEX IF NOT EXISTS idx_inter_agent_recv ON inter_agent_messages(session, to_agent, delivered_at, created_at)")
            self._db.commit()

    def enqueue(
        self,
        *,
        session: str,
        from_agent: str,
        to_agent: str,
        payload_handle: str,
        attachment_handles: list[str],
    ) -> InterAgentMessage:
        msg_id = f"c2_{secrets.token_urlsafe(12)}"
        now = float(time.time())
        atts = [str(x) for x in (attachment_handles or []) if str(x).strip()]
        with self._lock:
            self._db.execute(
                """
                INSERT INTO inter_agent_messages
                (message_id, session, from_agent, to_agent, payload_handle, attachment_handles_json, created_at, delivered_at)
                VALUES(?,?,?,?,?,?,?,0)
                """,
                (msg_id, str(session), str(from_agent), str(to_agent), str(payload_handle), json.dumps(atts, ensure_ascii=True), now),
            )
            self._db.commit()
        return InterAgentMessage(
            message_id=msg_id,
            session=str(session),
            from_agent=str(from_agent),
            to_agent=str(to_agent),
            payload_handle=str(payload_handle),
            attachment_handles=atts,
            created_at=now,
            delivered_at=0.0,
        )

    def recv(
        self,
        *,
        session: str,
        to_agent: str,
        limit: int = 10,
        mark_delivered: bool = True,
    ) -> List[InterAgentMessage]:
        n = int(limit)
        if n < 1:
            n = 1
        if n > 100:
            n = 100
        with self._lock:
            rows = self._db.execute(
                """
                SELECT message_id, session, from_agent, to_agent, payload_handle, attachment_handles_json, created_at, delivered_at
                FROM inter_agent_messages
                WHERE session=? AND to_agent=? AND delivered_at=0
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (str(session), str(to_agent), n),
            ).fetchall()
            out: list[InterAgentMessage] = []
            ids: list[str] = []
            for row in rows:
                try:
                    atts = json.loads(str(row[5]))
                except Exception:
                    atts = []
                if not isinstance(atts, list):
                    atts = []
                msg = InterAgentMessage(
                    message_id=str(row[0]),
                    session=str(row[1]),
                    from_agent=str(row[2]),
                    to_agent=str(row[3]),
                    payload_handle=str(row[4]),
                    attachment_handles=[str(x) for x in atts if str(x).strip()],
                    created_at=float(row[6]),
                    delivered_at=float(row[7]),
                )
                out.append(msg)
                ids.append(msg.message_id)
            if mark_delivered and ids:
                now = float(time.time())
                qs = ",".join(["?"] * len(ids))
                self._db.execute(
                    f"UPDATE inter_agent_messages SET delivered_at=? WHERE message_id IN ({qs})",
                    tuple([now] + ids),
                )
                self._db.commit()
        return out

    def count_pending(self, *, session: str, to_agent: str) -> int:
        with self._lock:
            row = self._db.execute(
                "SELECT COUNT(*) FROM inter_agent_messages WHERE session=? AND to_agent=? AND delivered_at=0",
                (str(session), str(to_agent)),
            ).fetchone()
        if not row:
            return 0
        try:
            return int(row[0])
        except Exception:
            return 0
