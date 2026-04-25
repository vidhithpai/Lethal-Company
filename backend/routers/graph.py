from __future__ import annotations

from fastapi import APIRouter

from ..services.graph_engine import get_engine, use_mock_graph

router = APIRouter(prefix="/api/graph", tags=["graph"])


@router.get("")
def read_graph():
    engine = get_engine()
    payload = engine.get_graph()
    return {"nodes": payload.get("nodes", []), "links": payload.get("edges", [])}


@router.get("/path")
def read_path(target: str):
    engine = get_engine()
    # Changed default source from 'internet' to 'user_device' for OWASP format.
    path = engine.get_attack_path("user_device", target)
    return {"path": path}


@router.post("/use-mock")
def select_mock_graph() -> dict[str, str]:
    use_mock_graph()
    return {"message": "Mock graph activated"}



