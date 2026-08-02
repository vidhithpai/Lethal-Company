from __future__ import annotations

from fastapi import APIRouter

from backend.services.code_security_graph import (
    find_attack_paths,
    get_security_graph,
    use_mock_graph,
)

router = APIRouter(tags=["graph"])


@router.get("")
def read_graph():
    built = get_security_graph()
    return {"nodes": built["nodes"], "links": built["edges"]}


@router.get("/path")
def read_path(target: str):
    built = get_security_graph()
    g = built["graph"]
    sources = [n for n, d in g.nodes(data=True) if d.get("type") == "source"]
    if target not in g:
        return {"path": []}
    paths = find_attack_paths(g, sources, [target], max_depth=15)
    return {"path": paths[0]["path"] if paths else []}


@router.post("/use-mock")
def select_mock_graph() -> dict[str, str]:
    use_mock_graph()
    return {"message": "Mock graph activated"}
