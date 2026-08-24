from fastapi import APIRouter, Query, HTTPException
from backend.services.git_history import find_git_root, enrich_nodes_with_git
import subprocess
from pathlib import Path

router = APIRouter(prefix="/api/git", tags=["git"])

@router.get("/blame")
def git_blame(project_path: str = Query(...)):
    try:
        git_root = find_git_root(project_path)
        return {"git_root": git_root, "status": "ok"}
    except Exception as e:
        return {"git_root": None, "status": "no_git", "detail": str(e)}

@router.get("/timeline")
def git_timeline(project_path: str = Query(...), limit: int = Query(20)):
    try:
        import git
        repo = git.Repo(project_path, search_parent_directories=True)
        commits = []
        for c in list(repo.iter_commits(max_count=limit)):
            commits.append({
                "hash": c.hexsha,
                "short_hash": c.hexsha[:7],
                "author": c.author.name,
                "date": c.authored_datetime.isoformat(),
                "message": c.message.strip()[:80],
            })
        return {"commits": commits}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
