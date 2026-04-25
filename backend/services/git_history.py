"""
git_history.py
Analyzes .git history to find:
1. Which commit introduced a vulnerable line
2. Who authored it
3. When it was introduced
4. What other files changed in the same commit (blast radius)
"""

import subprocess
import os
from pathlib import Path
from datetime import datetime


def find_git_root(path: str) -> str | None:
    """Walk up directory tree to find .git folder"""
    p = Path(path).resolve()
    for parent in [p] + list(p.parents):
        if (parent / ".git").exists():
            return str(parent)
    return None


def git_blame_line(repo_root: str, filepath: str, line_number: int) -> dict:
    """
    Run git blame on a specific line.
    Returns: {commit_hash, author, date, message_summary}
    """
    try:
        rel_path = str(Path(filepath).relative_to(repo_root))
        result = subprocess.run(
            ["git", "-C", repo_root, "blame", "-L",
             f"{line_number},{line_number}", "--porcelain", rel_path],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.splitlines()
        if not lines:
            return {}
        commit_hash = lines[0].split()[0]
        # All-zeros means the file is uncommitted
        if commit_hash == "0" * 40:
            return {"commit": "uncommitted", "author": "local", "date": "unknown", "message": "Not yet committed"}
        info = {"commit": commit_hash[:8]}
        for line in lines[1:]:
            if line.startswith("author "):
                info["author"] = line[7:]
            elif line.startswith("author-time "):
                ts = int(line[12:])
                info["date"] = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")
            elif line.startswith("summary "):
                info["message"] = line[8:]
        return info
    except Exception as e:
        return {"error": str(e)}


def get_commit_diff(repo_root: str, commit_hash: str) -> dict:
    """
    Get files changed in a commit (blast radius).
    """
    try:
        result = subprocess.run(
            ["git", "-C", repo_root, "show", "--stat", "--format=%s", commit_hash],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.splitlines()
        message = lines[0] if lines else ""
        changed_files = [
            l.strip().split("|")[0].strip()
            for l in lines[1:] if "|" in l
        ]
        return {"message": message, "changed_files": changed_files, "blast_radius": len(changed_files)}
    except Exception as e:
        return {"error": str(e)}


def enrich_nodes_with_git(nodes: list[dict], repo_root: str) -> list[dict]:
    """
    For each sink/source node, add git blame data.
    Only runs on nodes that have file + line attributes.
    """
    for node in nodes:
        if node.get("type") in ("sink", "source") and node.get("file") and node.get("line"):
            blame = git_blame_line(repo_root, node["file"], node["line"])
            node["git_blame"] = blame
            if blame.get("commit") and blame["commit"] not in ("uncommitted", ""):
                diff = get_commit_diff(repo_root, blame["commit"])
                node["blast_radius"] = diff.get("changed_files", [])
                node["commit_message"] = diff.get("message", "")
    return nodes


def get_vulnerability_timeline(repo_root: str, filepath: str) -> list[dict]:
    """
    Get commit history for a file to show when vulnerabilities were introduced.
    Returns list of {hash, author, date, message} for last 10 commits.
    """
    try:
        result = subprocess.run(
            ["git", "-C", repo_root, "log", "--oneline", "--follow",
             "-10", "--format=%H|%an|%ad|%s", "--date=short", filepath],
            capture_output=True, text=True, timeout=10
        )
        timeline = []
        for line in result.stdout.splitlines():
            parts = line.split("|", 3)
            if len(parts) == 4:
                timeline.append({
                    "hash": parts[0][:8],
                    "author": parts[1],
                    "date": parts[2],
                    "message": parts[3]
                })
        return timeline
    except Exception:
        return []
