from __future__ import annotations

from fastapi import APIRouter, HTTPException

from backend.services.graph_engine import get_engine

router = APIRouter(prefix="/api/graph", tags=["graph"])


@router.get("")
def read_graph():
    engine = get_engine()
    return engine.get_graph()


@router.get("/path")
def read_path(source: str, target: str):
    engine = get_engine()
    path = engine.get_attack_path(source, target)
    return {"path": path}


@router.post("/patch/{node_id}")
def patch_node(node_id: str):
    engine = get_engine()
    ok = engine.patch_node(node_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Node not found")
    return {"message": "Node patched successfully"}

