from __future__ import annotations

from fastapi import APIRouter
from backend.services.git_history import (
    find_git_root,
    get_vulnerability_timeline,
    enrich_nodes_with_git,
)
from backend.services.code_security_graph import get_security_graph

router = APIRouter(tags=["git"])


@router.get("/api/git/blame")
def git_blame_report(project_path: str):
    """
    Returns all sink/source nodes enriched with git blame data.
    This is the commit attribution report shown in the side panel.
    """
    repo_root = find_git_root(project_path)
    if not repo_root:
        return {"error": "No .git found", "nodes": []}

    built = get_security_graph()
    nodes = [dict(data) for _, data in built["graph"].nodes(data=True)]
    enriched = enrich_nodes_with_git(nodes, repo_root)
    return {
        "repo_root": repo_root,
        "nodes": [n for n in enriched if "git_blame" in n],
    }


@router.get("/api/git/timeline")
def file_timeline(project_path: str, filepath: str):
    """Commit history for a specific file"""
    repo_root = find_git_root(project_path)
    if not repo_root:
        return {"error": "No .git found", "timeline": []}
    return {
        "timeline": get_vulnerability_timeline(repo_root, filepath)
    }
