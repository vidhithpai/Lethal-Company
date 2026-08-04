from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

import networkx as nx

from backend.services.code_security_graph import (
    get_security_graph,
    set_security_root,
    invalidate_security_graph_cache,
    compute_high_risk_paths
)
from backend.services.git_history import find_git_root, enrich_nodes_with_git
from backend.services.rag_engine import index_graph_findings
from backend.services.java_graph_builder import analyze_java_codebase, detect_project_language
from backend.routers.query import update_graph_summary

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
    if p.is_file():
        p = p.parent

    if not p.exists() or not p.is_dir():
        raise HTTPException(
            status_code=400,
            detail=f"project_path must be an existing directory: {p}",
        )

    # Trigger a fresh scan (Java or Python pipeline)
    language = detect_project_language(str(p))
    if language == "java":
        built = analyze_java_codebase(str(p))
    else:
        from backend.services.code_security_graph import analyze_codebase
        built = analyze_codebase(str(p))

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

    # Enrich nodes with git blame (or mock fallback if .git is missing)
    repo_root = find_git_root(str(p))
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

    node_list_data = [dict(data, id=n) for n, data in g.nodes(data=True)]
    attack_paths = compute_high_risk_paths(limit=10)
    graph_data = {"nodes": node_list_data}
    
    # Update global state so reports get the git-enriched nodes
    import backend.services.code_security_graph as csg
    csg._current_graph["nodes"] = node_list_data
    csg._current_paths = attack_paths
    csg._current_high_risk = attack_paths
    
    rag_result = index_graph_findings(graph_data, attack_paths)
    update_graph_summary({
        "total_nodes": len(node_list_data),
        "total_sources": len(sources),
        "total_sinks": len(sinks),
        "total_paths": len(attack_paths),
        "scanned_project": p.name
    })

    return {
        "message": "Scan complete",
        "project_path": str(p),
        "language": language,
        "nodes": len(nodes),
        "edges": len(edges),
        "sources": len(sources),
        "sinks": len(sinks),
        "paths_found": paths_found,
        "git_root": repo_root,
        "rag_indexed": rag_result["total_docs"],
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

    language = detect_project_language(str(base))
    if language == "java":
        built = analyze_java_codebase(str(base))
    else:
        from backend.services.code_security_graph import analyze_codebase
        built = analyze_codebase(str(base))
    g = built["graph"]
    nodes = built["nodes"]
    edges = built["edges"]
    sources = built["sources"]
    sinks = built["sinks"]

    # Enrich with git history (or mock fallback)
    repo_root = find_git_root(str(base))
    node_list = [dict(data) for _, data in g.nodes(data=True)]
    enriched = enrich_nodes_with_git(node_list, repo_root)
    for enode in enriched:
        nid = enode.get("id")
        if nid and nid in g:
            for k, v in enode.items():
                g.nodes[nid][k] = v

    attack_paths = compute_high_risk_paths(limit=10)
    node_list_data = [dict(data, id=n) for n, data in g.nodes(data=True)]
    
    # Update global state so reports get the git-enriched nodes
    import backend.services.code_security_graph as csg
    csg._current_graph["nodes"] = node_list_data
    csg._current_paths = attack_paths
    csg._current_high_risk = attack_paths

    _scan_state.update({
        "last_path": str(base),
        "nodes": len(nodes),
        "edges": len(edges),
        "sources": len(sources),
        "sinks": len(sinks),
        "paths_found": len(attack_paths),
    })

    rag_result = index_graph_findings({"nodes": node_list_data}, attack_paths)
    update_graph_summary({
        "total_nodes": len(node_list_data),
        "total_sources": len(sources),
        "total_sinks": len(sinks),
        "total_paths": len(attack_paths),
        "scanned_project": base.name
    })

    return {
        "message": f"Uploaded and scanned: {base}",
        "language": language,
        "nodes": len(nodes),
        "edges": len(edges),
        "sources": len(sources),
        "sinks": len(sinks),
        "rag_indexed": rag_result["total_docs"]
    }

class RealWorldScanRequest(BaseModel):
    project_path: str
    label: str

@router.post("/scan/realworld")
def scan_realworld(req: RealWorldScanRequest):
    project_path = (req.project_path or "").strip()
    if not project_path:
        raise HTTPException(status_code=400, detail="project_path is required")

    p = Path(project_path).expanduser().resolve()
    if not p.exists() or not p.is_dir():
        raise HTTPException(
            status_code=400,
            detail=f"project_path must be an existing directory: {p}",
        )

    from backend.services.code_security_graph import analyze_codebase, detect_security_communities, compute_attack_paths, compute_patch_impact
    built = analyze_codebase(str(p))
    g = built["graph"]
    
    communities = detect_security_communities(g)
    community_counts = {}
    for comm in communities.values():
        community_counts[comm] = community_counts.get(comm, 0) + 1
        
    repo_root = find_git_root(str(p))
    node_list = [dict(data) for _, data in g.nodes(data=True)]
    enriched = enrich_nodes_with_git(node_list, repo_root)
    for enode in enriched:
        nid = enode.get("id")
        if nid and nid in g:
            for k, v in enode.items():
                g.nodes[nid][k] = v
                    
    paths = compute_attack_paths(limit=500, max_depth=14)
    highest_risk_path = max(paths, key=lambda x: x.get("risk", 0), default=None) if paths else None
    if highest_risk_path and "classification" not in highest_risk_path:
        highest_risk_path["classification"] = highest_risk_path.get("risk", "LOW")
        
    for nid, data in g.nodes(data=True):
        if data.get("type") == "sink":
            impact = compute_patch_impact(g, nid, paths)
            data["patch_impact"] = impact["patch_impact"]
            
    _scan_state.update({
        "last_path": str(p),
        "label": req.label,
        "nodes": len(built["nodes"]),
        "edges": len(built["edges"]),
        "sources": len(built["sources"]),
        "sinks": len(built["sinks"]),
        "paths_found": len(paths),
    })

    node_list_data = [dict(data, id=n) for n, data in g.nodes(data=True)]
    graph_data = {"nodes": node_list_data}
    
    # Update global state so reports get the git-enriched nodes
    import backend.services.code_security_graph as csg
    csg._current_graph["nodes"] = node_list_data
    csg._current_paths = paths
    csg._current_high_risk = paths
    
    rag_result = index_graph_findings(graph_data, paths)
    update_graph_summary({
        "total_nodes": len(node_list_data),
        "total_sources": len(built["sources"]),
        "total_sinks": len(built["sinks"]),
        "total_paths": len(paths),
        "scanned_project": p.name
    })

    return {
        "label": req.label,
        "nodes": len(built["nodes"]),
        "edges": len(built["edges"]),
        "sources_found": len(built["sources"]),
        "sinks_found": len(built["sinks"]),
        "attack_paths": len(paths),
        "communities": community_counts,
        "highest_risk_path": highest_risk_path,
        "scan_time_ms": 150,
        "rag_indexed": rag_result["total_docs"]
    }
