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
    """
    Lightweight timeline endpoint — reads commit metadata and approximates
    the risk factor from diff stats WITHOUT checking out any commit.
    This means it returns instantly even for large repos.
    """
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
        import git as gitlib
        repo = gitlib.Repo(repo_path)
        commits = list(repo.iter_commits(max_count=limit))
        results = []

        for commit in commits:
            # Count changed lines in Python/Java files via diff stats
            py_java_insertions = 0
            py_java_deletions = 0
            guard_removals = 0  # heuristic: lines with sanitize/guard/validate removed

            if commit.parents:
                try:
                    diffs = commit.parents[0].diff(commit, create_patch=True)
                    for diff in diffs:
                        fname = diff.b_path or diff.a_path or ""
                        if not (fname.endswith(".py") or fname.endswith(".java")):
                            continue
                        patch = diff.diff.decode("utf-8", errors="ignore") if diff.diff else ""
                        for line in patch.splitlines():
                            if line.startswith("+") and not line.startswith("+++"):
                                py_java_insertions += 1
                            elif line.startswith("-") and not line.startswith("---"):
                                py_java_deletions += 1
                                # heuristic: guard removal if line mentions common sanitizer patterns
                                lower = line.lower()
                                if any(kw in lower for kw in [
                                    "sanitize", "escape", "validate", "guard",
                                    "safe", "clean", "filter", "check"
                                ]):
                                    guard_removals += 1
                except Exception:
                    pass

            # RF approximation: normalize by total changed lines
            total_changed = max(py_java_insertions + py_java_deletions, 1)
            # Paths introduced ≈ insertions / 20 (rough: 20 lines = 1 path segment)
            delta_paths_approx = py_java_insertions / 20.0
            delta_guards_approx = guard_removals

            alpha, beta = 0.6, 0.4
            p_base = max(total_changed / 10.0, 1.0)
            g_base = max(total_changed / 5.0, 1.0)
            RF = round(
                alpha * (delta_paths_approx / p_base) +
                beta * (delta_guards_approx / g_base),
                4
            )
            RF = min(RF, 1.0)

            if RF < 0.2:
                severity = "Low"
            elif RF < 0.45:
                severity = "Medium"
            elif RF < 0.7:
                severity = "High"
            else:
                severity = "Critical"

            results.append({
                "commit_hash": commit.hexsha,
                "parent_hash": commit.parents[0].hexsha if commit.parents else None,
                "author": commit.author.name,
                "date": commit.authored_datetime.isoformat(),
                "message": commit.message.strip(),
                "new_attack_paths": round(delta_paths_approx),
                "guard_weakening_events": guard_removals,
                "paths_before": 0,
                "paths_after": round(delta_paths_approx),
                "risk_factor": RF,
                "severity": severity,
                "new_paths_detail": [],
                "removed_guards": [],
                "approx": True,  # flag indicating this is a fast approximation
            })

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

