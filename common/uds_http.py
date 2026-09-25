from __future__ import annotations

import json
import socket
import time
from typing import Any, Dict, Tuple


class UdsHttpError(RuntimeError):
    pass


def _b64_pad(s: str) -> str:
    # base64 urlsafe decode padding helper
    r = len(s) % 4
    if r == 0:
        return s
    return s + ("=" * (4 - r))


def _decode_chunked(body: bytes) -> bytes:
    """
    Minimal HTTP/1.1 chunked transfer decoding.
    """
    out = bytearray()
    i = 0
    n = len(body)
    while True:
        j = body.find(b"\r\n", i)
        if j < 0:
            raise UdsHttpError("bad_chunked_encoding: missing size CRLF")
        size_line = body[i:j].split(b";", 1)[0].strip()
        try:
            sz = int(size_line.decode("ascii"), 16)
        except Exception as e:
            raise UdsHttpError(f"bad_chunk_size: {e}")
        i = j + 2
        if sz == 0:
            # consume trailing CRLF
            k = body.find(b"\r\n", i)
            if k < 0:
                return bytes(out)
            return bytes(out)
        if i + sz > n:
            raise UdsHttpError("bad_chunked_encoding: truncated chunk")
        out += body[i : i + sz]
        i += sz
        if body[i : i + 2] != b"\r\n":
            raise UdsHttpError("bad_chunked_encoding: missing chunk CRLF")
        i += 2


def uds_http_request(
    *,
    uds_path: str,
    method: str,
    path: str,
    headers: Dict[str, str] | None = None,
    body: bytes | None = None,
    timeout_s: float = 10.0,
    max_resp_bytes: int = 10_000_000,
) -> Tuple[int, Dict[str, str], bytes]:
    """
    Perform an HTTP/1.1 request over a Unix domain socket.

    This is intentionally tiny (no external deps) so it can run inside the capsule.
    """
    if not uds_path:
        raise UdsHttpError("missing uds_path")
    if not path.startswith("/"):
        path = "/" + path

    hdrs = {k: v for k, v in (headers or {}).items() if k and v is not None}
    hdrs.setdefault("Host", "localhost")
    hdrs.setdefault("Connection", "close")
    if body is not None:
        hdrs.setdefault("Content-Length", str(len(body)))

    req_lines = [f"{method} {path} HTTP/1.1"]
    for k, v in hdrs.items():
        req_lines.append(f"{k}: {v}")
    req_bytes = ("\r\n".join(req_lines) + "\r\n\r\n").encode("ascii")

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(float(timeout_s))
    try:
        sock.connect(uds_path)
        sock.sendall(req_bytes)
        if body:
            sock.sendall(body)

        chunks: list[bytes] = []
        total = 0
        while True:
            b = sock.recv(64 * 1024)
            if not b:
                break
            chunks.append(b)
            total += len(b)
            if total > int(max_resp_bytes):
                raise UdsHttpError("response_too_large")
    finally:
        try:
            sock.close()
        except Exception:
            pass

    raw = b"".join(chunks)
    sep = raw.find(b"\r\n\r\n")
    if sep < 0:
        raise UdsHttpError("bad_http_response: missing header separator")

    head = raw[:sep].decode("iso-8859-1", errors="replace")
    body_bytes = raw[sep + 4 :]

    lines = head.split("\r\n")
    if not lines:
        raise UdsHttpError("bad_http_response: empty status line")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2:
        raise UdsHttpError(f"bad_http_status_line: {lines[0]!r}")
    try:
        status = int(parts[1])
    except Exception as e:
        raise UdsHttpError(f"bad_http_status_code: {e}")

    resp_headers: dict[str, str] = {}
    for ln in lines[1:]:
        if not ln or ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        resp_headers[k.strip().lower()] = v.strip()

    if resp_headers.get("transfer-encoding", "").lower() == "chunked":
        body_bytes = _decode_chunked(body_bytes)
    return status, resp_headers, body_bytes


def uds_post_json(
    *,
    uds_path: str,
    path: str,
    obj: Dict[str, Any],
    headers: Dict[str, str] | None = None,
    timeout_s: float = 10.0,
) -> Tuple[int, Dict[str, str], Any]:
    payload = json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    status, resp_headers, body = uds_http_request(
        uds_path=uds_path,
        method="POST",
        path=path,
        headers=hdrs,
        body=payload,
        timeout_s=timeout_s,
    )
    ctype = (resp_headers.get("content-type") or "").lower()
    if "application/json" in ctype:
        try:
            return status, resp_headers, json.loads(body.decode("utf-8", errors="replace") or "{}")
        except Exception:
            return status, resp_headers, {"_raw": body[:200].decode("utf-8", errors="replace")}
    return status, resp_headers, body


def wait_uds_http_ok(*, uds_path: str, path: str = "/health", tries: int = 120, timeout_s: float = 0.5) -> None:
    last_err: str | None = None
    for _ in range(int(tries)):
        try:
            st, _hdrs, body = uds_http_request(uds_path=uds_path, method="GET", path=path, timeout_s=timeout_s)
            if st == 200:
                # best-effort parse
                if body:
                    return
                return
        except Exception as e:
            last_err = str(e)
        time.sleep(0.1)
    raise UdsHttpError(f"health check failed over UDS: {uds_path} ({last_err})")

