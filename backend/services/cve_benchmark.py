"""
cve_benchmark.py
================
Loads known VCC (Vulnerability-Contributing Commit) hashes from a local
JSON file and labels a set of commit analysis results as VCC or non-VCC,
then runs statistical validation.
"""
from __future__ import annotations

import json
from pathlib import Path

from .statistical_validator import validate_risk_scores

# Default path relative to the project root (inside the container at /app)
_DEFAULT_VCC_FILE = Path(__file__).parent.parent.parent / "data" / "known_vcc_commits.json"


def load_known_vcc(json_path: str | Path | None = None) -> list[str]:
    """
    Load the list of known VCC commit hashes from the JSON file.
    Returns a flat list of hex hashes (short or full).
    """
    path = Path(json_path) if json_path else _DEFAULT_VCC_FILE
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as fh:
        records = json.load(fh)
    # records is a list of {"repo": ..., "hash": ..., "cve": ...}
    return [r["hash"].lower() for r in records if "hash" in r]


def label_commits(
    all_results: list[dict],
    known_vcc: list[str],
) -> dict:
    """
    Splits commit analysis results into VCC and non-VCC groups,
    then calls validate_risk_scores() to get the full statistical report.

    Parameters
    ----------
    all_results : list of dicts returned by DifferentialEngine.analyze_commit()
    known_vcc   : list of VCC commit hashes (short 7-char or full sha)

    Returns
    -------
    dict with:
        vcc_commits      – list of matching commit result dicts
        non_vcc_commits  – list of non-matching commit result dicts
        validation       – output of validate_risk_scores()
    """
    # Normalise to lowercase for comparison; support both short and full hashes
    vcc_set = {h.lower() for h in known_vcc}

    vcc_results, non_vcc_results = [], []
    for result in all_results:
        full_hash = result.get("commit_hash", "").lower()
        is_vcc = full_hash in vcc_set or any(
            full_hash.startswith(short) or short.startswith(full_hash[:7])
            for short in vcc_set
        )
        if is_vcc:
            vcc_results.append(result)
        else:
            non_vcc_results.append(result)

    vcc_scores = [r["risk_factor"] for r in vcc_results]
    non_vcc_scores = [r["risk_factor"] for r in non_vcc_results]

    validation = validate_risk_scores(vcc_scores, non_vcc_scores)

    return {
        "vcc_commits": vcc_results,
        "non_vcc_commits": non_vcc_results,
        "validation": validation,
    }
