from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, List, Optional

from .hardened_file_ops import atomic_write_text, sha256_file

MANIFEST_SCHEMA = 1

ENGINE_FINGERPRINT_FILES = (
    "winws.exe",
    "winws2.exe",
    "cygwin1.dll",
    "WinDivert.dll",
    "Monkey64.sys",
    "WinDivert64.sys",
    "WinDivert.sys",
    "aaaaaaaaa1",
    "stop.bat",
)


def _relative_path(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def snapshot_dir(dir) -> Dict[str, str]:
    root = Path(dir)
    out: Dict[str, str] = {}
    if not root.is_dir():
        return out
    for path in sorted(root.rglob("*")):
        if path.is_file():
            out[_relative_path(root, path)] = sha256_file(path)
    return out


def write_manifest(dir, manifest_path) -> Path:
    root = Path(dir)
    files = snapshot_dir(root)
    payload = {"schema": MANIFEST_SCHEMA, "dir": str(root), "files": files}
    target = Path(manifest_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(target, json.dumps(payload, ensure_ascii=False, indent=2))
    return target


def _load_manifest(manifest_path) -> Dict[str, str]:
    try:
        raw = Path(manifest_path).read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, ValueError):
        return {}
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, dict):
        return {}
    clean: Dict[str, str] = {}
    for key, value in files.items():
        if isinstance(key, str) and isinstance(value, str) and key:
            clean[key] = value.lower()
    return clean


def verify_manifest(dir, manifest_path) -> dict:
    root = Path(dir)
    recorded = _load_manifest(manifest_path)
    current = snapshot_dir(root)
    manifest_file = str(Path(manifest_path).resolve())
    checks: List[dict] = []
    tampered: List[str] = []
    missing: List[str] = []
    added: List[str] = []

    for path in sorted(recorded):
        if path not in current:
            missing.append(path)
            checks.append({"path": path, "status": "missing"})
            continue
        if current[path] == recorded[path]:
            checks.append({"path": path, "status": "ok"})
        else:
            tampered.append(path)
            checks.append({"path": path, "status": "tampered"})

    for path in sorted(current):
        if path in recorded:
            continue
        if str((root / path).resolve()) == manifest_file:
            continue
        added.append(path)
        checks.append({"path": path, "status": "added"})

    return {
        "ok": not (tampered or missing or added),
        "checks": checks,
        "tampered": tampered,
        "missing": missing,
        "added": added,
    }


def fingerprint_engine(engine_dir=None) -> dict:
    if engine_dir is None:
        from winws.paths import engine_dir as resolve_engine_dir

        engine_dir = resolve_engine_dir()
    root = Path(engine_dir) if engine_dir else None
    files: List[dict] = []
    digest = hashlib.sha256()
    for name in ENGINE_FINGERPRINT_FILES:
        candidate = (root / name) if root else None
        exists = bool(candidate is not None and candidate.is_file())
        sha = sha256_file(candidate) if exists else ""
        files.append({"name": name, "sha256": sha if exists else None, "exists": exists})
        digest.update(name.encode("utf-8", errors="replace"))
        digest.update(b":")
        digest.update(sha.encode("ascii", errors="ignore"))
        digest.update(b";")
    return {
        "dir": str(root) if root else "",
        "files": files,
        "aggregate_hash": digest.hexdigest(),
    }