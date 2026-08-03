"""
validation.py  –  FastAPI router for TDRA statistical validation
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import List

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from backend.services.differential_engine import DifferentialEngine
from backend.services.cve_benchmark import label_commits, load_known_vcc
from backend.services.statistical_validator import validate_risk_scores

router = APIRouter(tags=["validation"])

# ── Simple in-memory cache (repo_path → report dict) ─────────────────────────
_cache: dict[str, dict] = {}
_cache_lock = threading.Lock()


# ── Request / Response models ─────────────────────────────────────────────────

class ValidationRequest(BaseModel):
    repo_path: str
    known_vcc_commits: List[str] = []   # optional: caller can supply VCC hashes
    use_bundled_vcc: bool = True         # also merge hashes from data/known_vcc_commits.json
    limit: int = 50                      # max commits to analyse


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/api/validation/run")
def run_validation(req: ValidationRequest) -> dict:
    """
    Runs DifferentialEngine over all commits in repo_path (lightweight diff-
    stats mode – no checkout required), labels each commit as VCC or non-VCC,
    then returns a full statistical validation report.
    """
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
        # ── Gather VCC hashes ──────────────────────────────────────────────
        known_vcc: list[str] = list(req.known_vcc_commits)
        if req.use_bundled_vcc:
            known_vcc.extend(load_known_vcc())

        # ── Collect commit RF scores via lightweight timeline ──────────────
        import git as gitlib
        repo = gitlib.Repo(repo_path)
        commits = list(repo.iter_commits(max_count=req.limit))

        all_results: list[dict] = []
        for commit in commits:
            if not commit.parents:
                continue
            py_java_ins = py_java_del = guard_rem = 0
            try:
                diffs = commit.parents[0].diff(commit, create_patch=True)
                for d in diffs:
                    fname = d.b_path or d.a_path or ""
                    if not (fname.endswith(".py") or fname.endswith(".java")):
                        continue
                    patch = d.diff.decode("utf-8", errors="ignore") if d.diff else ""
                    for line in patch.splitlines():
                        if line.startswith("+") and not line.startswith("+++"):
                            py_java_ins += 1
                        elif line.startswith("-") and not line.startswith("---"):
                            py_java_del += 1
                            lower = line.lower()
                            if any(kw in lower for kw in [
                                "sanitize", "escape", "validate", "guard",
                                "safe", "clean", "filter", "check",
                            ]):
                                guard_rem += 1
            except Exception:
                pass

            total = max(py_java_ins + py_java_del, 1)
            delta_p = py_java_ins / 20.0
            alpha, beta = 0.6, 0.4
            RF = min(
                round(
                    alpha * (delta_p / max(total / 10.0, 1.0)) +
                    beta * (guard_rem / max(total / 5.0, 1.0)),
                    4,
                ),
                1.0,
            )
            all_results.append({
                "commit_hash": commit.hexsha,
                "author": commit.author.name,
                "date": commit.authored_datetime.isoformat(),
                "message": commit.message.strip(),
                "risk_factor": RF,
            })

        if not all_results:
            raise HTTPException(
                status_code=422,
                detail="No analysable commits found (need at least 1 with a parent).",
            )

        # ── Label and validate ─────────────────────────────────────────────
        report = label_commits(all_results, known_vcc)
        report["repo_path"] = repo_path
        report["total_commits_analysed"] = len(all_results)

        # ── Cache for GET endpoint ─────────────────────────────────────────
        with _cache_lock:
            _cache[repo_path] = report

        return report

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/api/validation/report")
def get_cached_report(repo_path: str = Query(...)) -> dict:
    """Returns the last cached validation report for repo_path."""
    with _cache_lock:
        report = _cache.get(repo_path.strip())
    if not report:
        raise HTTPException(
            status_code=404,
            detail="No cached report found. Run POST /api/validation/run first.",
        )
    return report
