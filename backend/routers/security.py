from __future__ import annotations

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
)

router = APIRouter(tags=["security"])


@router.get("/api/graph")
def read_graph():
    built = get_security_graph()
    # Frontend expects `links`
    return {"nodes": built["nodes"], "links": built["edges"], "path": []}


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
    patch_security_node(node_id)
    invalidate_security_graph_cache()
    built = get_security_graph()
    return {"nodes": built["nodes"], "links": built["edges"], "path": []}


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

