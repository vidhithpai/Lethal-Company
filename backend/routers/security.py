from __future__ import annotations

from pathlib import Path
from fastapi import APIRouter, HTTPException, Query
import networkx as nx

from backend.services.code_security_graph import (
    compute_attack_paths,
    compute_attack_surface,
    compute_high_risk_paths,
    get_security_graph,
    invalidate_security_graph_cache,
    patch_security_node,
    resolve_node_ref,
    shortest_path_to_target,
    detect_security_communities,
    COMMUNITY_COLORS,
    compute_patch_impact,
)

router = APIRouter(tags=["security"])


@router.get("/api/graph")
def read_graph():
    built = get_security_graph()
    g = built["graph"]
    communities = detect_security_communities(g)
    paths = compute_attack_paths(limit=500, max_depth=14)
    meta = {
        "total_nodes": len(g.nodes),
        "total_sources": len([n for _, n in g.nodes(data=True) if n.get("type") == "source"]),
        "total_sinks": len([n for _, n in g.nodes(data=True) if n.get("type") == "sink"]),
        "total_paths": len(paths),
        "communities_detected": len(set(communities.values())),
        "scanned_project": "Project",
        "scan_time_ms": 150
    }
    
    # Extract live nodes from graph (since git blame is injected post-build)
    live_nodes = [dict(data, id=n) for n, data in g.nodes(data=True)]
    
    return {"nodes": live_nodes, "links": built["edges"], "path": [], "meta": meta}


@router.get("/api/attack-surface")
def read_attack_surface():
    surface = compute_attack_surface()
    return {"nodes": surface, "edges": [], "path": []}


@router.get("/api/attack-paths")
def read_attack_paths(
    limit: int = Query(50, ge=1, le=500),
    max_depth: int = Query(12, ge=1, le=50),
):
    paths = compute_attack_paths(limit=limit, max_depth=max_depth)
    return {"paths": paths}


@router.get("/api/high-risk-paths")
def read_high_risk_paths(limit: int = Query(20, ge=1, le=200)):
    paths = compute_high_risk_paths(limit=limit)
    return {"paths": paths}


@router.get("/api/graph/path")
def read_graph_path(target: str):
    # `target` should be a node id (sink). Returns path array of node ids.
    return {"path": shortest_path_to_target(target)}


@router.post("/api/graph/patch/{node_id:path}")
def patch_graph_node(node_id: str):
    built_before = get_security_graph()
    all_paths = compute_attack_paths(limit=500, max_depth=14)
    impact = compute_patch_impact(built_before["graph"], node_id, all_paths)

    patch_security_node(node_id)
    invalidate_security_graph_cache()
    built = get_security_graph()
    live_nodes = [dict(data, id=n) for n, data in built["graph"].nodes(data=True)]
    return {"nodes": live_nodes, "links": built["edges"], "path": [], "patch_impact": impact.get("patch_impact")}

@router.get("/api/communities")
def read_communities():
    built = get_security_graph()
    g = built["graph"]
    communities = detect_security_communities(g)
    
    groups = {}
    for node_id, comm in communities.items():
        if comm not in groups:
            groups[comm] = {"nodes": [], "count": 0, "color": COMMUNITY_COLORS.get(comm, "#6B7280")}
        groups[comm]["nodes"].append(node_id)
        groups[comm]["count"] += 1
        
    return {
        "communities": groups,
        "summary": f"{len(groups)} communities detected."
    }

@router.get("/api/node/context")
def read_node_context(node_id: str):
    built = get_security_graph()
    g = built["graph"]
    target_id = None

    if node_id in g:
        target_id = node_id
    else:
        # Normalize slashes and attempt fuzzy node lookup
        norm_req = node_id.replace("\\", "/").strip()
        for n in g.nodes:
            norm_n = str(n).replace("\\", "/").strip()
            if norm_n == norm_req or norm_n.endswith(norm_req) or norm_req.endswith(norm_n):
                target_id = n
                break

    if not target_id:
        # Second attempt: match by label or file base
        for n, d in g.nodes(data=True):
            if d.get("label") == node_id or d.get("id") == node_id:
                target_id = n
                break

    if not target_id:
        raise HTTPException(status_code=404, detail=f"Node {node_id} not found")

    node_id = target_id
    node_data = dict(g.nodes[node_id])
    filepath = node_data.get("file")
    line = node_data.get("line", 1)
    context_code = ""

    if filepath and Path(filepath).exists():
        try:
            lines = Path(filepath).read_text(errors="replace").splitlines()
            start = max(0, line - 15)
            end = min(len(lines), line + 15)
            context_code = "\n".join(lines[start:end])
        except Exception:
            context_code = ""

    try:
        upstream_nodes = nx.ancestors(g, node_id)
        upstream_sources = [{"id": n, "label": g.nodes[n].get("label", n)} for n in upstream_nodes if g.nodes[n].get("type") == "source"]
    except Exception:
        upstream_sources = []

    try:
        downstream_nodes = nx.descendants(g, node_id)
        downstream_sinks = [{"id": n, "label": g.nodes[n].get("label", n), "risk": g.nodes[n].get("risk", "LOW")} for n in downstream_nodes if g.nodes[n].get("type") == "sink"]
    except Exception:
        downstream_sinks = []

    all_paths = compute_attack_paths(limit=500, max_depth=14)
    paths_through = [p for p in all_paths if node_id in p.get("path", [])]

    blast_radius = node_data.get("blast_radius", {})
    if not isinstance(blast_radius, dict) and "files_in_commit" not in blast_radius:
        blist = node_data.get("blast_radius", [])
        if isinstance(blist, list):
            blast_radius = {
                "files_in_commit": blist,
                "count": len(blist),
                "description": f"Introduced in commit that touched {len(blist)} files"
            }
        else:
            blast_radius = {"files_in_commit": [], "count": 0, "description": "No git blame data"}

    return {
        "node_id": node_id,
        "type": node_data.get("type"),
        "file": filepath,
        "line": line,
        "context_code": context_code,
        "node": node_data,
        "upstream": {
            "sources": upstream_sources,
            "description": f"{len(upstream_sources)} inputs can taint this node"
        },
        "downstream": {
            "sinks": downstream_sinks,
            "description": f"This node can reach {len(downstream_sinks)} sinks"
        },
        "attack_paths_through": paths_through,
        "sanitizers_on_path": [],
        "blast_radius": blast_radius
    }

@router.get("/api/node/patch-impact")
def read_patch_impact(node_id: str):
    built = get_security_graph()
    g = built["graph"]
    if node_id not in g:
        raise HTTPException(status_code=404, detail="Node not found")
        
    all_paths = compute_attack_paths(limit=500, max_depth=14)
    return compute_patch_impact(g, node_id, all_paths)


@router.get("/api/path")
def get_path(source: str, sink: str, max_depth: int = Query(20, ge=1, le=200), limit: int = Query(50, ge=1, le=500)):
    """
    Required endpoint: /api/path?source=...&sink=...
    Accepts either internal node ids or human labels like 'input()' / 'os.system()'.
    Returns paths as arrays of internal node ids (so the frontend can highlight).
    """
    built = get_security_graph()
    g = built["graph"]

    src_id = resolve_node_ref(source, node_type="source") or resolve_node_ref(source, node_type=None)
    sink_id = resolve_node_ref(sink, node_type="sink") or resolve_node_ref(sink, node_type=None)
    if not src_id or not sink_id:
        raise HTTPException(status_code=404, detail="Source or sink not found in graph")

    paths = []
    try:
        for p in nx.all_simple_paths(g, src_id, sink_id, cutoff=max_depth):
            paths.append(p)
            if len(paths) >= limit:
                break
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        pass

    return {"paths": paths}


@router.get("/api/debug/edges")
def debug_edges(limit: int = Query(500, ge=1, le=5000)):
    built = get_security_graph()
    g = built["graph"]
    edges = []
    for u, v, data in g.edges(data=True):
        edges.append({"source": u, "target": v, "type": data.get("type", ""), "reason": data.get("reason", "")})
        if len(edges) >= limit:
            break
    return {"edges": edges}

