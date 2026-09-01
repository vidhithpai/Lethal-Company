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


def load_manifest(project_path: str) -> dict:
    """Load existing manifest or return empty one."""
    manifest_path = Path(project_path) / MANIFEST_FILENAME
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
    """Persist manifest to disk."""
    manifest_path = Path(project_path) / MANIFEST_FILENAME
    if G is not None:
        manifest["graph_nodes"] = G.number_of_nodes()
        manifest["graph_edges"] = G.number_of_edges()
    manifest_path.write_text(json.dumps(manifest, indent=2))


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
