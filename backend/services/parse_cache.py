from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

# Cache directory location
CACHE_DIR = Path(".vulngraph_cache")
try:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass


def file_hash(filepath: Path | str) -> str:
    """Compute SHA-256 hash of raw file bytes for content-addressed caching."""
    p = Path(filepath)
    return hashlib.sha256(p.read_bytes()).hexdigest()


def get_cached_parse(filepath: Path | str) -> dict[str, Any] | None:
    """Return cached parse data if cache file exists for current file hash."""
    try:
        h = file_hash(filepath)
        cache_file = CACHE_DIR / f"{h}.json"
        if cache_file.exists():
            return json.loads(cache_file.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None
    return None


def store_parsed(filepath: Path | str, parsed_data: dict[str, Any]) -> None:
    """
    Store parsed data to content-addressed cache.
    Strips raw javalang AST objects or any non-serializable fields.
    """
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        h = file_hash(filepath)
        cache_file = CACHE_DIR / f"{h}.json"

        # Strip non-serializable fields (like raw javalang AST objects)
        clean_data: dict[str, Any] = {}
        for k, v in parsed_data.items():
            if k in ("javalang_ast", "raw_ast"):
                continue
            clean_data[k] = v

        cache_file.write_text(
            json.dumps(clean_data, default=str),
            encoding="utf-8",
            errors="replace",
        )
    except Exception:
        # Cache failure must never abort scanning
        pass
