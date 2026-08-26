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
    """Walk up directory tree to find .git folder, with fallback to original repo paths."""
    print(f"[GIT_CHECK] Checking repo_path: '{path}' for .git")
    p = Path(path).resolve()

    # 1. Direct check on p itself (if p has its own .git)
    if (p / ".git").exists():
        print(f"[GIT_CHECK] Code path: REAL GIT BLAME (found direct repo at {p})")
        return str(p)

    # 2. Extract candidate project folder names from path parts (e.g. pygoat, timetable_management)
    path_parts = [part for part in Path(path).parts if part and part not in ("/", "\\", "tmp", "vulngraph_uploads", "app")]
    folder_names = list(dict.fromkeys([p.name] + path_parts[::-1]))

    user_home = Path.home()
    curr = Path.cwd()

    for fname in folder_names:
        if not fname or fname.endswith(".py") or fname.endswith(".java") or fname.endswith(".js"):
            continue

        candidates = [
            curr / fname,
            curr.parent / fname,
            curr.parent / "Demorep" / fname,
            curr.parent / "MajorProject" / "Demorep" / fname,
            user_home / "Documents" / "Projects" / fname,
            user_home / "Documents" / "Projects" / "Demorep" / fname,
            user_home / "Documents" / "Projects" / "MajorProject" / "Demorep" / fname,
            user_home / "Projects" / fname,
            user_home / "Projects" / "Demorep" / fname,
        ]

        for cand in candidates:
            try:
                cand_resolved = cand.resolve()
                dot_git = cand_resolved / ".git"
                if cand_resolved.exists() and dot_git.exists():
                    print(f"[GIT_CHECK] Found fallback repo matching '{fname}' with .git at '{cand_resolved}'")
                    print(f"[GIT_CHECK] Code path: REAL GIT BLAME (fallback to original local path '{cand_resolved}')")
                    return str(cand_resolved)
            except Exception:
                continue

    # 3. Walk up parent directory tree as final fallback
    for parent in list(p.parents):
        dot_git = parent / ".git"
        if dot_git.exists():
            print(f"[GIT_CHECK] Code path: REAL GIT BLAME (found parent repo at {parent})")
            return str(parent)

    print(f"[GIT_CHECK] No .git folder found for '{path}' or its fallback candidates.")
    print(f"[GIT_CHECK] Code path: NO GIT HISTORY AVAILABLE")
    return None


def git_blame_line(repo_root: str, filepath: str, line_number: int) -> dict:
    """
    Run git blame on a specific line.
    Returns: {commit_hash, author, date, message_summary}
    """
    try:
        fp = Path(filepath).resolve()
        rr = Path(repo_root).resolve()
        
        # Try direct relative_to
        try:
            rel_path = str(fp.relative_to(rr))
        except ValueError:
            # Handle uploaded files in /tmp/vulngraph_uploads/<repo_name>/...
            repo_name = rr.name
            parts = fp.parts
            if repo_name in parts:
                idx = parts.index(repo_name)
                rel_path = str(Path(*parts[idx+1:]))
            else:
                rel_path = fp.name
                
        # Check if file exists in target repo
        if not (rr / rel_path).exists():
            # Try searching by filename in repo_root
            matches = list(rr.glob(f"**/{fp.name}"))
            if matches:
                rel_path = str(matches[0].relative_to(rr))
            else:
                print(f"[GIT_CHECK] File '{rel_path}' not found in repo '{repo_root}'")
                return {}

        result = subprocess.run(
            ["git", "-C", str(rr), "blame", "-L",
             f"{line_number},{line_number}", "--porcelain", rel_path],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0 or not result.stdout.strip():
            print(f"[GIT_CHECK] git blame command returned code {result.returncode}. Stderr: {result.stderr.strip()}")
            return {}
            
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
        print(f"[GIT_CHECK] git_blame_line exception: {e}")
        return {"error": str(e)}


def get_commit_diff(repo_root: str, commit_hash: str) -> dict:
    """
    Get files changed in a commit (blast radius).
    """
    if not commit_hash or commit_hash == "uncommitted":
        return {"message": "Not yet committed", "changed_files": [], "blast_radius": 0}
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


def enrich_nodes_with_git(nodes: list[dict], repo_root: str | None) -> list[dict]:
    """
    For each sink/source node, add git blame data.
    Only runs on nodes that have file + line attributes.
    If repo_root is None or git blame fails, no fake mock data is generated.
    """
    print(f"[GIT_CHECK] enrich_nodes_with_git starting with repo_root: '{repo_root}'")
    for node in nodes:
        if node.get("type") in ("sink", "source") and node.get("file") and node.get("line"):
            blame = {}
            if repo_root:
                blame = git_blame_line(repo_root, node["file"], node["line"])
                
            if blame and blame.get("commit") and blame.get("commit") != "uncommitted":
                diff = get_commit_diff(repo_root, blame["commit"])
                node["git_blame"] = blame
                node["blast_radius"] = diff.get("changed_files", [])
                node["commit_message"] = diff.get("message", "")
                print(f"[GIT_CHECK] Enriched node '{node.get('id')}' -> Author: {blame.get('author')}, Commit: {blame.get('commit')}, Msg: '{blame.get('message')}'")
            elif blame and blame.get("commit") == "uncommitted":
                node["git_blame"] = blame
                node["blast_radius"] = []
                node["commit_message"] = "Not yet committed"
                print(f"[GIT_CHECK] Node '{node.get('id')}' is uncommitted")
            else:
                node["git_blame"] = {"error": "No git history available"}
                node["blast_radius"] = []
                node["commit_message"] = ""
                print(f"[GIT_CHECK] No git history available for node '{node.get('id')}'")
            
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

