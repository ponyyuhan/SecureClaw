from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional


class SecretStore:
    """
    Minimal secret store abstraction.

    Demo implementation loads secrets from a JSON file. In production you would
    replace this with OS keychain / Vault / KMS-backed short-lived credentials.
    """

    def __init__(self, *, path: str | None = None) -> None:
        if path is None:
            path = os.getenv("SECRETS_PATH", str(Path(__file__).resolve().parent / "secrets" / "secrets.json"))
        self._path = Path(path)
        self._cache: dict[str, str] | None = None

    def _load(self) -> dict[str, str]:
        if self._cache is not None:
            return self._cache
        try:
            data = json.loads(self._path.read_text())
            if not isinstance(data, dict):
                raise ValueError("bad secrets file format")
            out: dict[str, str] = {}
            for k, v in data.items():
                if isinstance(k, str) and isinstance(v, str):
                    out[k] = v
            self._cache = out
            return out
        except Exception:
            self._cache = {}
            return {}

    def get(self, name: str) -> Optional[str]:
        name = str(name or "")
        if not name:
            return None
        return self._load().get(name)

