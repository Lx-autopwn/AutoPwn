from __future__ import annotations

import hashlib
import json
from pathlib import Path

from autopwn.config import CACHE_DIR


def cache_key(binary_path: str) -> str:
    p = Path(binary_path).resolve()
    data = p.read_bytes()
    return hashlib.md5(data).hexdigest()


def _cache_path(key: str) -> Path:
    return CACHE_DIR / f"{key}.json"


def save(key: str, data: dict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = _cache_path(key)
    path.write_text(json.dumps(data, indent=2, default=str))


def load(key: str) -> dict | None:
    path = _cache_path(key)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def invalidate(key: str) -> None:
    path = _cache_path(key)
    if path.exists():
        path.unlink()
