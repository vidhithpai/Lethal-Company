# ==============================================================================
# MODELING DECISION FOR PER-PATH RISK CONTRIBUTION: OPTION 1 IMPLEMENTED
# ==============================================================================
# We selected OPTION 1. Risk Factor (RF) is a DIFFERENTIAL metric that compares
# program graph state changes between consecutive commits (new paths introduced,
# guards weakened). It is not a property of a single static graph path.
# Therefore, /api/attack-paths (single-graph) is left UNCHANGED.
# Per-path RF shares are served via:
# GET /api/tdra/commit/{commit_hash}/path-contributions?repo_path=...
# ==============================================================================

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from backend.services.differential_engine import DifferentialEngine
from backend.services.statistical_validator import validate_risk_scores as _validate
from backend.services.git_history import find_git_root

router = APIRouter(tags=["tdra"])

# In-memory TTL cache: (repo_path, limit) -> (timestamp, commit_results_list)
_ANALYSIS_CACHE: dict[tuple[str, int], tuple[float, list[dict[str, Any]]]] = {}
_CACHE_TTL_SECONDS = 300  # 5 minutes


class TDRAAnalyzeRequest(BaseModel):
    repo_path: str
    limit: int = 20


class ValidationRequest(BaseModel):
    repo_path: str
    known_vcc_hashes: list[str]
    limit: int = 100


def _get_analyzed_commit_results(repo_path: str, limit: int) -> tuple[list[dict[str, Any]], DifferentialEngine]:
    now = time.time()
    git_root = find_git_root(repo_path)
    if not git_root:
        raise ValueError(f"No git repository found for path: {repo_path}")
    cache_key = (git_root, limit)

    engine = DifferentialEngine(git_root)
    if cache_key in _ANALYSIS_CACHE:
        ts, cached_results = _ANALYSIS_CACHE[cache_key]
        if now - ts < _CACHE_TTL_SECONDS:
            return cached_results, engine

    pairs = engine.get_commit_pairs(limit=limit)
    results = []
    for parent_hash, commit_hash in pairs:
        res = engine.analyze_commit(parent_hash, commit_hash)
        results.append(res)

    _ANALYSIS_CACHE[cache_key] = (now, results)
    return results, engine


@router.post("/analyze")
def analyze_repo(req: TDRAAnalyzeRequest):
    """
    POST /api/tdra/analyze
    Analyzes commit pairs in repo_path and returns differential security results
    sorted by risk_factor descending.
    """
    repo_path = (req.repo_path or "").strip()
    if not repo_path:
        raise HTTPException(status_code=400, detail="repo_path is required")

    git_root = find_git_root(repo_path)
    if not git_root:
        raise HTTPException(status_code=400, detail=f"No git repository found for path: {repo_path}")

    try:
        results, _ = _get_analyzed_commit_results(git_root, req.limit)
        sorted_results = sorted(results, key=lambda x: x.get("risk_factor", x.get("rf_score", 0.0)), reverse=True)
        return {"results": sorted_results, "total_pairs_analyzed": len(sorted_results)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"TDRA analysis failed: {str(e)}")


@router.post("/validate")
def run_validation(req: ValidationRequest):
    """
    POST /api/tdra/validate
    Splits commit RF scores into VCC vs non-VCC groups
    using provided known CVE commit hashes, then runs
    Mann-Whitney U + Cliff's delta.
    """
    repo_path = (req.repo_path or "").strip()
    if not repo_path:
        raise HTTPException(status_code=400, detail="repo_path is required")

    git_root = find_git_root(repo_path)
    if not git_root:
        raise HTTPException(status_code=400, detail=f"No git repository found for path: {repo_path}")

    # Clean and normalize input target hashes
    clean_vcc_hashes = set()
    for h in req.known_vcc_hashes:
        c = h.strip().lower()
        if c:
            clean_vcc_hashes.add(c)

    def is_target_vcc(c_hash: str) -> bool:
        if not c_hash:
            return False
        c_low = c_hash.lower()
        for target in clean_vcc_hashes:
            if c_low == target or c_low.startswith(target) or target.startswith(c_low[:7]):
                return True
        return False

    try:
        engine = DifferentialEngine(git_root)
        results = []

        # Check if we already have warm cached commit results for this git_root
        now = time.time()
        cached = None
        for (k_root, _), (ts, c_results) in _ANALYSIS_CACHE.items():
            if k_root == git_root and (now - ts < _CACHE_TTL_SECONDS) and len(c_results) >= 10:
                cached = c_results
                break

        if cached is not None:
            results = [dict(c) for c in cached]
        else:
            eff_limit = min(req.limit, 30) if req.limit > 30 else max(req.limit, 15)
            c_results, _ = _get_analyzed_commit_results(git_root, eff_limit)
            results = [dict(c) for c in c_results]

        # Check if all requested target VCC hashes are present in results.
        # If any target hash is not in results, directly analyze it via git commit lookup
        analyzed_hashes = {r.get("commit_hash", "").lower() for r in results}
        for target in clean_vcc_hashes:
            matched = any(
                ah == target or ah.startswith(target) or target.startswith(ah[:7])
                for ah in analyzed_hashes
            )
            if not matched:
                try:
                    commit_obj = engine.repo.commit(target)
                    p_hash = commit_obj.parents[0].hexsha if commit_obj.parents else None
                    single_res = engine.analyze_commit(p_hash, commit_obj.hexsha)
                    results.insert(0, single_res)
                    analyzed_hashes.add(commit_obj.hexsha.lower())
                except Exception:
                    pass

        vcc_scores = [r.get("risk_factor", r.get("rf_score", 0.0)) for r in results if is_target_vcc(r.get("commit_hash", ""))]
        non_vcc_scores = [r.get("risk_factor", r.get("rf_score", 0.0)) for r in results if not is_target_vcc(r.get("commit_hash", ""))]

        report = _validate(vcc_scores, non_vcc_scores)
        report["total_commits_analyzed"] = len(results)
        return report
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/risk-summary")
def get_risk_summary(repo_path: str = Query(...), limit: int = Query(20, ge=1, le=200)):
    """
    GET /api/tdra/risk-summary?repo_path=...&limit=20
    Returns aggregated risk summary metrics across analyzed commit pairs.
    Handles empty / single-commit repos gracefully with zero/null fields.
    Reuses DifferentialEngine and in-memory TTL cache to avoid redundant graph builds.
    """
    repo_path = (repo_path or "").strip()
    if not repo_path:
        raise HTTPException(status_code=400, detail="repo_path is required")

    git_root = find_git_root(repo_path)
    if not git_root:
        return {
            "total_commits_analyzed": 0,
            "critical_commits": [],
            "high_commits": [],
            "riskiest_commit": None,
            "avg_risk_factor": 0.0,
            "total_new_paths_introduced": 0,
            "total_guard_weakening_events": 0,
            "source": "no_git",
        }

    try:
        results, _ = _get_analyzed_commit_results(git_root, limit)
        if not results:
            return {
                "total_commits_analyzed": 0,
                "critical_commits": [],
                "high_commits": [],
                "riskiest_commit": None,
                "avg_risk_factor": 0.0,
                "total_new_paths_introduced": 0,
                "total_guard_weakening_events": 0,
                "source": "live",
            }

        critical_commits = [c for c in results if c.get("risk_factor", c.get("rf_score", 0.0)) >= 0.7]
        high_commits = [c for c in results if 0.45 <= c.get("risk_factor", c.get("rf_score", 0.0)) < 0.7]

        sorted_by_rf = sorted(results, key=lambda x: x.get("risk_factor", x.get("rf_score", 0.0)), reverse=True)
        riskiest_commit = sorted_by_rf[0] if sorted_by_rf else None

        total_rf = sum(c.get("risk_factor", c.get("rf_score", 0.0)) for c in results)
        avg_rf = round(total_rf / len(results), 4)

        total_new_paths = sum(c.get("new_attack_paths", 0) for c in results)
        total_guard_weakening = sum(c.get("guard_weakening_events", 0) for c in results)

        return {
            "total_commits_analyzed": len(results),
            "critical_commits": critical_commits,
            "high_commits": high_commits,
            "riskiest_commit": riskiest_commit,
            "avg_risk_factor": avg_rf,
            "total_new_paths_introduced": total_new_paths,
            "total_guard_weakening_events": total_guard_weakening,
            "source": "live",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate risk summary: {str(e)}")


@router.get("/commit/{commit_hash}/path-contributions")
def get_commit_path_contributions(commit_hash: str, repo_path: str = Query(...)):
    """
    GET /api/tdra/commit/{commit_hash}/path-contributions?repo_path=...
    Option 1 Implementation: Computes each newly introduced attack path's fractional
    share of the commit's overall Risk Factor (RF).
    """
    repo_path = (repo_path or "").strip()
    if not repo_path:
        raise HTTPException(status_code=400, detail="repo_path is required")

    git_root = find_git_root(repo_path)
    if not git_root:
        raise HTTPException(status_code=404, detail=f"No git repository found for path: {repo_path}")

    try:
        engine = DifferentialEngine(git_root)
        try:
            commit_obj = engine.repo.commit(commit_hash)
        except Exception:
            raise HTTPException(status_code=404, detail=f"Commit hash '{commit_hash}' not found in repository")

        parent_hash = commit_obj.parents[0].hexsha if commit_obj.parents else None

        analysis = engine.analyze_commit(parent_hash, commit_hash)

        delta_paths = analysis.get("new_attack_paths", 0)
        delta_guards = analysis.get("guard_weakening_events", 0)
        paths_before = analysis.get("paths_before", 1)
        p_before = max(paths_before, 1)

        alpha = 0.6

        per_path_share = round((1.0 / delta_paths) * alpha * (delta_paths / p_before), 4) if delta_paths > 0 else 0.0

        new_paths_contrib = []
        for p in analysis.get("new_paths_detail", []):
            new_paths_contrib.append({
                "path": p,
                "rf_contribution": per_path_share,
                "type": "new_attack_path",
            })

        return {
            "commit_hash": commit_hash,
            "parent_hash": parent_hash or "",
            "total_risk_factor": analysis.get("risk_factor", analysis.get("rf_score", 0.0)),
            "severity": analysis.get("severity", "Low"),
            "new_attack_paths_count": delta_paths,
            "guard_weakening_events_count": delta_guards,
            "new_paths_contributions": new_paths_contrib,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to compute path contributions: {str(e)}")


@router.get("/commit/{commit_hash}")
def get_commit_analysis(commit_hash: str, repo_path: str = Query(...)):
    """
    GET /api/tdra/commit/{commit_hash}?repo_path=...
    Returns single commit differential security analysis.
    """
    repo_path = (repo_path or "").strip()
    if not repo_path:
        raise HTTPException(status_code=400, detail="repo_path is required")

    git_root = find_git_root(repo_path)
    if not git_root:
        raise HTTPException(status_code=404, detail=f"No git repository found for path: {repo_path}")

    try:
        engine = DifferentialEngine(git_root)
        try:
            commit_obj = engine.repo.commit(commit_hash)
        except Exception:
            raise HTTPException(status_code=404, detail=f"Commit hash '{commit_hash}' not found in repository")

        parent_hash = commit_obj.parents[0].hexsha if commit_obj.parents else None
        res = engine.analyze_commit(parent_hash, commit_hash)
        return res
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to analyze commit {commit_hash}: {str(e)}")


@router.get("/timeline")
async def get_tdra_timeline(repo_path: str = Query(...), limit: int = Query(50)):
    import logging
    logger = logging.getLogger("tdra")

    git_root = find_git_root(repo_path)
    logger.info(f"TDRA timeline request: repo_path={repo_path} resolved_git_root={git_root}")

    if not git_root:
        return {
            "timeline": [],
            "source": "no_git",
            "reason": f"No git repository found for {repo_path}",
        }

    try:
        results, _ = _get_analyzed_commit_results(git_root, limit)
        return {"timeline": results, "source": "live", "git_root": git_root}
    except Exception as e:
        import traceback
        logger.error(f"TDRA analysis error: {e}\n{traceback.format_exc()}")
        # Fallback to direct git commit extraction without differential graph calculation
        try:
            import git
            repo = git.Repo(git_root, search_parent_directories=False)
            commits = []
            for c in list(repo.iter_commits(max_count=limit)):
                commits.append({
                    "commit_hash": c.hexsha,
                    "short_hash": c.hexsha[:7],
                    "parent_hash": c.parents[0].hexsha if c.parents else "",
                    "author": c.author.name if c.author else "Unknown",
                    "date": c.authored_datetime.isoformat() if c.authored_datetime else "",
                    "message": c.message.strip() if c.message else "",
                    "changed_files": [],
                    "diff_lines_changed": 0,
                    "new_attack_paths": 0,
                    "guard_weakening_events": 0,
                    "risk_factor": 0.0,
                    "rf_score": 0.0,
                    "severity": "Low",
                    "new_paths_detail": [],
                })
            return {
                "timeline": commits,
                "source": "live",
                "git_root": git_root,
                "warning": f"Raw commits loaded (graph analysis warning: {str(e)[:80]})"
            }
        except Exception as e2:
            return {
                "timeline": [],
                "source": "no_git",
                "reason": f"Git read error: {str(e2)[:150]}"
            }
