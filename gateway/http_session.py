from __future__ import annotations

import threading

import requests
from requests.adapters import HTTPAdapter


_TLS = threading.local()


def session_for(_base_url: str) -> requests.Session:
    """
    Return a thread-local requests.Session with a larger connection pool.

    This reduces per-request TCP/TLS setup overhead on hot policy/executor paths and
    provides stable latency under concurrency (PIR/MPC mixing emits parallel calls).
    """
    d = getattr(_TLS, "sessions", None)
    if d is None:
        d = {}
        _TLS.sessions = d
    # Key by base URL string (strip trailing slash so callers can pass either form).
    key = str(_base_url or "").rstrip("/")
    s = d.get(key)
    if s is None:
        s = requests.Session()
        # Keep adapter settings conservative; pool_maxsize is per-host.
        adapter = HTTPAdapter(pool_connections=64, pool_maxsize=64, max_retries=0)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        d[key] = s
    return s
