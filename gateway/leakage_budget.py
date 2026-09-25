from __future__ import annotations

import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict


def _default_budget_db_path() -> str:
    return str(Path(__file__).resolve().parents[1] / "artifact_out" / "leakage_budget.sqlite")


@dataclass(frozen=True, slots=True)
class BudgetDecision:
    ok: bool
    channel: str
    limit: int
    spent: int
    requested: int
    remaining: int

    def to_dict(self) -> dict[str, int | str | bool]:
        return {
            "ok": bool(self.ok),
            "channel": str(self.channel),
            "limit": int(self.limit),
            "spent": int(self.spent),
            "requested": int(self.requested),
            "remaining": int(self.remaining),
        }


class LeakageBudget:
    """
    Session/caller-scoped leakage budget model.

    Units are abstract "characters disclosed" for now; channels can map to different
    units later (e.g. bytes, records, requests) while keeping the same interface.
    """

    def __init__(self, db_path: str | None = None):
        self.enabled = bool(int(os.getenv("LEAKAGE_BUDGET_ENABLED", "1")))
        self._limits: Dict[str, int] = {
            "C1": int(os.getenv("LEAKAGE_BUDGET_C1", "8192")),
            "C2": int(os.getenv("LEAKAGE_BUDGET_C2", "4096")),
            "C3": int(os.getenv("LEAKAGE_BUDGET_C3", "-1")),
            "C4": int(os.getenv("LEAKAGE_BUDGET_C4", "-1")),
            "C5": int(os.getenv("LEAKAGE_BUDGET_C5", "4096")),
            "C6": int(os.getenv("LEAKAGE_BUDGET_C6", "-1")),
            "C7": int(os.getenv("LEAKAGE_BUDGET_C7", "-1")),
        }
        self._db_path = (db_path or os.getenv("LEAKAGE_BUDGET_DB_PATH", "").strip()) or _default_budget_db_path()
        self._db = sqlite3.connect(self._db_path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS leakage_budget (
                  session TEXT NOT NULL,
                  caller TEXT NOT NULL,
                  channel TEXT NOT NULL,
                  spent INTEGER NOT NULL,
                  updated_at REAL NOT NULL,
                  PRIMARY KEY(session, caller, channel)
                )
                """
            )
            self._db.commit()

    def limit(self, channel: str) -> int:
        ch = str(channel).upper()
        return int(self._limits.get(ch, -1))

    def _get_spent_locked(self, *, session: str, caller: str, channel: str) -> int:
        row = self._db.execute(
            "SELECT spent FROM leakage_budget WHERE session=? AND caller=? AND channel=?",
            (str(session), str(caller), str(channel)),
        ).fetchone()
        if not row:
            return 0
        try:
            return int(row[0])
        except Exception:
            return 0

    def consume(self, *, session: str, caller: str, channel: str, units: int) -> BudgetDecision:
        ch = str(channel).upper().strip() or "C1"
        req = int(units)
        if req < 0:
            req = 0
        lim = self.limit(ch)
        if not self.enabled or lim < 0:
            return BudgetDecision(ok=True, channel=ch, limit=lim, spent=0, requested=req, remaining=-1)

        with self._lock:
            spent = self._get_spent_locked(session=str(session), caller=str(caller), channel=ch)
            nxt = spent + req
            if nxt > lim:
                return BudgetDecision(ok=False, channel=ch, limit=lim, spent=spent, requested=req, remaining=max(0, lim - spent))
            self._db.execute(
                """
                INSERT INTO leakage_budget(session, caller, channel, spent, updated_at)
                VALUES(?,?,?,?,?)
                ON CONFLICT(session, caller, channel)
                DO UPDATE SET spent=excluded.spent, updated_at=excluded.updated_at
                """,
                (str(session), str(caller), ch, int(nxt), float(time.time())),
            )
            self._db.commit()
            return BudgetDecision(ok=True, channel=ch, limit=lim, spent=nxt, requested=req, remaining=max(0, lim - nxt))

    def snapshot(self, *, session: str, caller: str) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        with self._lock:
            rows = self._db.execute(
                "SELECT channel, spent FROM leakage_budget WHERE session=? AND caller=?",
                (str(session), str(caller)),
            ).fetchall()
        for ch, spent in rows:
            chs = str(ch)
            lim = self.limit(chs)
            sp = int(spent)
            out[chs] = {"spent": sp, "limit": lim, "remaining": (-1 if lim < 0 else max(0, lim - sp))}
        return out
