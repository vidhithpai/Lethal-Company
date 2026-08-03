from __future__ import annotations

from pathlib import Path
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from backend.services.differential_engine import DifferentialEngine

router = APIRouter(tags=["tdra"])


class AnalyzeRequest(BaseModel):
    repo_path: str
    limit: int = 20


@router.post("/analyze")
def analyze_repo(req: AnalyzeRequest):
    repo_path = (req.repo_path or "").strip()
    if not repo_path:
        raise HTTPException(status_code=400, detail="repo_path is required")

    path = Path(repo_path)
    if not path.exists() or not path.is_dir():
        raise HTTPException(
            status_code=400,
            detail=f"repo_path must be an existing directory: {repo_path}",
        )

    try:
        engine = DifferentialEngine(repo_path)
        pairs = engine.get_commit_pairs(limit=req.limit)
        results = []
        for parent_hash, commit_hash in pairs:
            try:
                res = engine.analyze_commit(parent_hash, commit_hash)
                results.append(res)
            except Exception as e:
                # Log or print error and continue so one failing commit doesn't crash the whole run
                print(f"Error analyzing commit pair {parent_hash} -> {commit_hash}: {e}")
                continue

        # Sort by risk_factor descending
        results.sort(key=lambda x: x["risk_factor"], reverse=True)
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/commit/{commit_hash}")
def get_commit_analysis(commit_hash: str, repo_path: str = Query(...)):
    repo_path = (repo_path or "").strip()
    if not repo_path:
        raise HTTPException(status_code=400, detail="repo_path is required")

    path = Path(repo_path)
    if not path.exists() or not path.is_dir():
        raise HTTPException(
            status_code=400,
            detail=f"repo_path must be an existing directory: {repo_path}",
        )

    try:
        engine = DifferentialEngine(repo_path)
        commit_obj = engine.repo.commit(commit_hash)
        if not commit_obj.parents:
            raise HTTPException(
                status_code=400,
                detail=f"Commit {commit_hash} has no parents for differential analysis",
            )
        parent_hash = commit_obj.parents[0].hexsha
        res = engine.analyze_commit(parent_hash, commit_hash)
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/timeline")
def get_timeline(repo_path: str = Query(...), limit: int = Query(20)):
    repo_path = (repo_path or "").strip()
    if not repo_path:
        raise HTTPException(status_code=400, detail="repo_path is required")

    path = Path(repo_path)
    if not path.exists() or not path.is_dir():
        raise HTTPException(
            status_code=400,
            detail=f"repo_path must be an existing directory: {repo_path}",
        )

    try:
        engine = DifferentialEngine(repo_path)
        pairs = engine.get_commit_pairs(limit=limit)
        results = []
        for parent_hash, commit_hash in pairs:
            try:
                res = engine.analyze_commit(parent_hash, commit_hash)
                results.append(res)
            except Exception as e:
                print(f"Error analyzing commit pair {parent_hash} -> {commit_hash} for timeline: {e}")
                continue

        # Sort by date descending (newest first) for timeline view
        results.sort(key=lambda x: x["date"], reverse=True)
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/risk-summary")
def get_risk_summary(repo_path: str = Query(...)):
    repo_path = (repo_path or "").strip()
    if not repo_path:
        raise HTTPException(status_code=400, detail="repo_path is required")

    path = Path(repo_path)
    if not path.exists() or not path.is_dir():
        raise HTTPException(
            status_code=400,
            detail=f"repo_path must be an existing directory: {repo_path}",
        )

    try:
        engine = DifferentialEngine(repo_path)
        pairs = engine.get_commit_pairs(limit=50)
        
        analyzed_commits = []
        total_new_paths = 0
        total_weakenings = 0
        rf_sum = 0.0
        
        for parent_hash, commit_hash in pairs:
            try:
                res = engine.analyze_commit(parent_hash, commit_hash)
                analyzed_commits.append(res)
                total_new_paths += res["new_attack_paths"]
                total_weakenings += res["guard_weakening_events"]
                rf_sum += res["risk_factor"]
            except Exception as e:
                print(f"Error analyzing commit pair {parent_hash} -> {commit_hash} for risk summary: {e}")
                continue

        num_analyzed = len(analyzed_commits)
        if num_analyzed == 0:
            return {
                "total_commits_analyzed": 0,
                "critical_commits": [],
                "high_commits": [],
                "riskiest_commit": None,
                "avg_risk_factor": 0.0,
                "total_new_paths_introduced": 0,
                "total_guard_weakening_events": 0
            }

        critical_commits = [c for c in analyzed_commits if c["risk_factor"] > 0.7]
        high_commits = [c for c in analyzed_commits if 0.45 <= c["risk_factor"] <= 0.7]
        
        # Find riskiest commit (highest RF)
        riskiest = max(analyzed_commits, key=lambda x: x["risk_factor"])
        avg_rf = round(rf_sum / num_analyzed, 4)

        return {
            "total_commits_analyzed": num_analyzed,
            "critical_commits": critical_commits,
            "high_commits": high_commits,
            "riskiest_commit": riskiest,
            "avg_risk_factor": avg_rf,
            "total_new_paths_introduced": total_new_paths,
            "total_guard_weakening_events": total_weakenings
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

