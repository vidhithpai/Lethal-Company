from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

import networkx as nx

from backend.services.code_security_graph import (
    get_security_graph,
    set_security_root,
    invalidate_security_graph_cache,
)
from backend.services.git_history import find_git_root, enrich_nodes_with_git

router = APIRouter(prefix="/api/cve", tags=["scan"])

_scan_state: dict = {
    "last_path": None,
    "nodes": 0,
    "edges": 0,
    "sources": 0,
    "sinks": 0,
    "paths_found": 0,
}


class ScanRequest(BaseModel):
    project_path: str


@router.post("/scan")
def scan(req: ScanRequest):
    project_path = (req.project_path or "").strip()
    if not project_path:
        raise HTTPException(status_code=400, detail="project_path is required")

    p = Path(project_path).expanduser().resolve()
    if not p.exists() or not p.is_dir():
        raise HTTPException(
            status_code=400,
            detail=f"project_path must be an existing directory: {p}",
        )

    # Trigger a fresh scan
    set_security_root(p)
    built = get_security_graph(p)

    g = built["graph"]
    nodes = built["nodes"]
    edges = built["edges"]
    sources = built["sources"]
    sinks = built["sinks"]

    # Quick path count estimate (cap to avoid blowup on large graphs)
    paths_found = 0
    for src in sources[:8]:
        for snk in sinks[:8]:
            try:
                if nx.has_path(g, src, snk):
                    paths_found += 1
            except Exception:
                pass

    # Optionally enrich nodes with git blame
    repo_root = find_git_root(str(p))
    if repo_root:
        node_list = [dict(data) for _, data in g.nodes(data=True)]
        enriched = enrich_nodes_with_git(node_list, repo_root)
        for enode in enriched:
            nid = enode.get("id")
            if nid and nid in g:
                for k, v in enode.items():
                    g.nodes[nid][k] = v

    _scan_state.update({
        "last_path": str(p),
        "nodes": len(nodes),
        "edges": len(edges),
        "sources": len(sources),
        "sinks": len(sinks),
        "paths_found": paths_found,
    })

    return {
        "message": "Scan complete",
        "project_path": str(p),
        "nodes": len(nodes),
        "edges": len(edges),
        "sources": len(sources),
        "sinks": len(sinks),
        "paths_found": paths_found,
        "git_root": repo_root,
    }


@router.get("/scan/status")
def scan_status():
    return _scan_state


@router.post("/scan/upload")
async def scan_upload(
    files: list[UploadFile] = File(...),
    folder_name: str = Form("uploaded_project"),
):
    safe_name = (
        "".join(c for c in folder_name if c.isalnum() or c in {"-", "_"}).strip()
        or "uploaded_project"
    )
    base = Path("/tmp/vulngraph_uploads") / safe_name
    base.mkdir(parents=True, exist_ok=True)

    for f in files:
        rel = (f.filename or "file.py").lstrip("/").replace("..", "_")
        out = base / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        content = await f.read()
        out.write_bytes(content)

    set_security_root(base)
    built = get_security_graph(base)
    nodes = built["nodes"]
    edges = built["edges"]
    sources = built["sources"]
    sinks = built["sinks"]

    return {
        "message": f"Uploaded and scanned: {base}",
        "nodes": len(nodes),
        "edges": len(edges),
        "sources": len(sources),
        "sinks": len(sinks),
    }
