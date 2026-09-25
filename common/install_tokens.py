from __future__ import annotations

import re


def normalize_install_token(s: str) -> str:
    """
    Canonicalize install semantics tokens for skill ingress checks.

    This function must remain consistent between:
    - policy DB construction (policy_server/build_dbs.py), and
    - gateway-side padding and token selection.
    """
    t = str(s or "").strip().lower()
    if not t:
        return ""
    t = t.replace("\n", " ")
    t = re.sub(r"\s+", " ", t)
    # Normalize pipe spacing: "curl | bash" => "curl|bash"
    t = re.sub(r"\s*\|\s*", "|", t)
    # Normalize common variants.
    t = re.sub(r"\binvoke-expression\b", "invoke-expression", t)
    t = re.sub(r"\bchmod\s*\+\s*x\b", "chmod +x", t)
    t = re.sub(r"\bbase64\s+-\s*d\b", "base64 -d", t)
    return t

