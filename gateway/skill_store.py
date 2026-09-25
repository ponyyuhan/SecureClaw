from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _read_bytes(p: Path) -> bytes:
    return p.read_bytes()


def _walk_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*"):
        if p.is_file():
            out.append(p)
    out.sort(key=lambda x: str(x))
    return out


def _compute_dir_digest(root: Path) -> str:
    h = hashlib.sha256()
    for p in _walk_files(root):
        rel = str(p.relative_to(root)).replace("\\", "/").encode("utf-8")
        h.update(rel + b"\n")
        h.update(_read_bytes(p))
        h.update(b"\n")
    return h.hexdigest()


def _find_skill_md(root: Path) -> Optional[Path]:
    # Common layout: <skill>/SKILL.md or <skill>/skill/SKILL.md. Keep it best-effort.
    for p in [root / "SKILL.md", root / "skill" / "SKILL.md"]:
        if p.exists() and p.is_file():
            return p
    # Otherwise, search shallow.
    for p in list(root.glob("**/SKILL.md"))[:8]:
        if p.is_file():
            return p
    return None


@dataclass(frozen=True, slots=True)
class StagedSkill:
    skill_id: str
    digest: str
    staged_dir: str
    skill_md_relpath: str
    file_count: int


class SkillStore:
    """Staging + enabled registry for skills (demo).

    - Staging is done in the trusted gateway, without executing any code.
    - Enabling is done by the executor (which writes the enabled registry).
    """

    def __init__(self, *, staging_dir: str | None = None, enabled_path: str | None = None):
        repo_root = Path(__file__).resolve().parents[1]
        self.staging_dir = Path(staging_dir or os.getenv("SKILL_STAGING_DIR", "") or (repo_root / "artifact_out" / "skill_staging")).expanduser()
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        self.enabled_path = Path(enabled_path or os.getenv("SKILL_ENABLED_PATH", "") or (repo_root / "artifact_out" / "enabled_skills.json")).expanduser()

    def stage(self, *, source: str, skill_id_hint: str | None = None) -> StagedSkill:
        p = Path(source).expanduser()
        if not p.exists():
            raise FileNotFoundError(f"skill source not found: {p}")

        if p.is_file() and p.suffix.lower() == ".zip":
            digest = _sha256_hex(p.read_bytes())
            out_dir = self.staging_dir / digest
            out_dir.mkdir(parents=True, exist_ok=True)
            # Extract only if directory is empty (best-effort idempotence).
            if not any(out_dir.iterdir()):
                with zipfile.ZipFile(str(p), "r") as zf:
                    zf.extractall(str(out_dir))
            root = out_dir
        elif p.is_dir():
            digest = _compute_dir_digest(p)
            out_dir = self.staging_dir / digest
            if not out_dir.exists():
                shutil.copytree(str(p), str(out_dir))
            root = out_dir
        else:
            raise ValueError("unsupported skill source: expected .zip or directory")

        # Try to locate the actual skill root if everything is nested under a single folder.
        kids = [x for x in root.iterdir() if x.is_dir()]
        if len(kids) == 1 and not (root / "SKILL.md").exists():
            root2 = kids[0]
        else:
            root2 = root

        skill_md = _find_skill_md(root2)
        if not skill_md:
            raise FileNotFoundError("SKILL.md not found in staged package")

        # Determine skill_id.
        skill_id = (skill_id_hint or "").strip()
        if not skill_id:
            skill_id = root2.name
        if not skill_id:
            skill_id = f"skill_{digest[:12]}"

        rel = str(skill_md.relative_to(root)).replace("\\", "/")
        file_count = len(_walk_files(root))
        return StagedSkill(skill_id=skill_id, digest=digest, staged_dir=str(root), skill_md_relpath=rel, file_count=file_count)

    def read_skill_md(self, staged: StagedSkill) -> str:
        root = Path(staged.staged_dir)
        p = root / staged.skill_md_relpath
        if not p.exists():
            # Fallback: search again in case relpath changed.
            p2 = _find_skill_md(root)
            if not p2:
                raise FileNotFoundError("SKILL.md not found in staged package")
            p = p2
        return p.read_text(encoding="utf-8", errors="replace")

    def list_enabled(self) -> list[dict[str, Any]]:
        if not self.enabled_path.exists():
            return []
        try:
            data = json.loads(self.enabled_path.read_text(encoding="utf-8"))
        except Exception:
            return []
        if isinstance(data, dict) and isinstance(data.get("skills"), list):
            return [x for x in data.get("skills") if isinstance(x, dict)]
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        return []

