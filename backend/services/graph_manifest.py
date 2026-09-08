import json
import hashlib
from pathlib import Path
from datetime import datetime
import networkx as nx
from typing import Optional


MANIFEST_FILENAME = ".vulngraph_manifest.json"


def _file_hash(filepath: str) -> str:
    """SHA-256 of file content — change detection."""
    try:
        content = Path(filepath).read_bytes()
        return hashlib.sha256(content).hexdigest()[:16]
    except Exception:
        return ""


def _resolve_manifest_path(project_path: str) -> Path:
    """
    Determine safe Path for loading/saving the project manifest.
    If project_path is on a read-only filesystem (e.g. Docker mounted host /host/... or /mnt/...)
    or not writable, returns a deterministic path in /tmp/vulngraph_manifests/<hash>/.
    """
    norm = str(project_path).replace("\\", "/")

    # Check if path is under read-only host mount
    if norm.startswith("/host/") or norm.startswith("/mnt/"):
        h = hashlib.md5(norm.encode()).hexdigest()[:12]
        cache_dir = Path(f"/tmp/vulngraph_manifests/{h}")
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
            return cache_dir / MANIFEST_FILENAME
        except Exception:
            pass

    # Try local project directory if writable
    p = Path(project_path)
    local_path = p / MANIFEST_FILENAME
    try:
        if p.exists() and p.is_dir():
            test_file = p / ".vulngraph_write_test"
            test_file.touch()
            test_file.unlink(missing_ok=True)
            return local_path
    except Exception:
        pass

    # Fallback to /tmp
    h = hashlib.md5(norm.encode()).hexdigest()[:12]
    cache_dir = Path(f"/tmp/vulngraph_manifests/{h}")
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        return cache_dir / MANIFEST_FILENAME
    except Exception:
        return Path(f"/tmp/{MANIFEST_FILENAME}")


def load_manifest(project_path: str) -> dict:
    """Load existing manifest or return empty one."""
    manifest_path = _resolve_manifest_path(project_path)
    if not manifest_path.exists():
        # Check if local project directory has one
        local_path = Path(project_path) / MANIFEST_FILENAME
        if local_path.exists():
            manifest_path = local_path

    if manifest_path.exists():
        try:
            return json.loads(manifest_path.read_text())
        except Exception:
            pass
    return {
        "version": "1.0",
        "project_path": project_path,
        "last_full_scan": None,
        "files": {},           # {filepath: {"hash": str, "analyzed_at": str}}
        "graph_nodes": 0,
        "graph_edges": 0,
    }


def save_manifest(project_path: str, manifest: dict,
                  G: Optional[nx.DiGraph] = None):
    """Persist manifest to disk safely without crashing on read-only filesystems."""
    if G is not None:
        manifest["graph_nodes"] = G.number_of_nodes()
        manifest["graph_edges"] = G.number_of_edges()

    manifest_path = _resolve_manifest_path(project_path)
    try:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, indent=2))
    except (OSError, PermissionError):
        try:
            # Fallback to /tmp
            h = hashlib.md5(str(project_path).encode()).hexdigest()[:12]
            tmp_path = Path(f"/tmp/vulngraph_manifests/{h}/{MANIFEST_FILENAME}")
            tmp_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path.write_text(json.dumps(manifest, indent=2))
        except Exception:
            # Manifest failure must never crash the scan pipeline
            pass


def get_changed_files(project_path: str, manifest: dict,
                      extensions: tuple = ('.java', '.py')) -> dict:
    """
    Compare current file hashes against manifest.
    Returns {
      "new":     [filepath, ...],   # never seen before
      "changed": [filepath, ...],   # hash differs
      "deleted": [filepath, ...],   # in manifest but not on disk
      "unchanged": [filepath, ...]  # hash matches — skip re-analysis
    }
    """
    current_files = {}
    for ext in extensions:
        for f in Path(project_path).rglob(f"*{ext}"):
            if any(skip in str(f) for skip in
                   ['.git','node_modules','__pycache__','target','build']):
                continue
            current_files[str(f)] = _file_hash(str(f))
    
    manifest_files = manifest.get("files", {})
    
    new_files      = [f for f in current_files
                      if f not in manifest_files]
    changed_files  = [f for f in current_files
                      if f in manifest_files
                      and current_files[f] != manifest_files[f]["hash"]]
    deleted_files  = [f for f in manifest_files
                      if f not in current_files]
    unchanged_files= [f for f in current_files
                      if f in manifest_files
                      and current_files[f] == manifest_files[f]["hash"]]
    
    return {
        "new": new_files,
        "changed": changed_files,
        "deleted": deleted_files,
        "unchanged": unchanged_files,
        "current_hashes": current_files,
    }


def update_manifest_after_scan(manifest: dict, 
                                changed_result: dict) -> dict:
    """Mark analyzed files in the manifest with their current hash."""
    now = datetime.utcnow().isoformat()
    for filepath in (changed_result["new"] + changed_result["changed"]):
        manifest["files"][filepath] = {
            "hash": changed_result["current_hashes"].get(filepath, ""),
            "analyzed_at": now,
        }
    for filepath in changed_result["deleted"]:
        manifest["files"].pop(filepath, None)
    manifest["last_full_scan"] = now
    return manifest
