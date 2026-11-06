from fastapi import APIRouter, Query, HTTPException
from backend.services.git_history import find_git_root, enrich_nodes_with_git
from backend.services.path_guard import resolve_allowed_repo
import subprocess
import re
from pathlib import Path
from typing import Any

router = APIRouter(prefix="/api/git", tags=["git"])

GUARD_ANNOTATIONS = {
    "@Valid", "@Validated", "@NotNull", "@NotBlank",
    "@Pattern", "@Size", "@Min", "@Max", "@Positive",
    "@PreAuthorize", "@Secured", "@RolesAllowed"
}


def _find_nodes_for_file_line(current_nodes: dict, file_path: str, line_no: int) -> list[dict]:
    fp_norm = Path(file_path).as_posix().lower()
    fp_name = Path(file_path).name.lower()
    nodes = current_nodes.get((fp_norm, line_no))
    if not nodes:
        nodes = current_nodes.get((fp_name, line_no))
    return nodes or []


def _has_parent_guard(parent_guard_lines: set, file_path: str, line_no: int) -> bool:
    fp_norm = Path(file_path).as_posix().lower()
    fp_name = Path(file_path).name.lower()
    return (fp_norm, line_no) in parent_guard_lines or (fp_name, line_no) in parent_guard_lines


def _collect_tdra_overlay(git_root: Path, full_hash: str) -> tuple[dict, set, set]:
    current_nodes: dict[tuple[str, int], list[dict]] = {}
    parent_guard_lines: set[tuple[str, int]] = set()
    new_path_node_ids: set[str] = set()

    try:
        from backend.routers.tdra import _ANALYSIS_CACHE
        from backend.services.differential_engine import DifferentialEngine

        commit_analysis = None
        for (cached_root, _), (_, results) in _ANALYSIS_CACHE.items():
            if str(cached_root) == str(git_root):
                for r in results:
                    if r.get("commit_hash", "").lower() == full_hash.lower():
                        commit_analysis = r
                        break
            if commit_analysis:
                break

        parent_hash = None
        engine = None
        try:
            engine = DifferentialEngine(str(git_root))
            commit_obj = engine.repo.commit(full_hash)
            parent_hash = commit_obj.parents[0].hexsha if commit_obj.parents else None
        except Exception:
            pass

        if not commit_analysis and engine is not None and parent_hash is not None:
            try:
                commit_analysis = engine.analyze_commit(parent_hash, full_hash)
            except Exception:
                pass

        if commit_analysis:
            for path in commit_analysis.get("new_paths_detail", []):
                for nid in path:
                    new_path_node_ids.add(str(nid))

        if engine is not None and parent_hash is not None:
            try:
                changed_files = engine.get_diff_changed_files(parent_hash, full_hash)
                if changed_files:
                    import tempfile
                    import shutil
                    from backend.services.differential_engine import extract_files_at_commit
                    from backend.services.code_security_graph import build_graph_for_path
                    from backend.services.java_graph_builder import build_java_graph

                    def _build_partial(tmp_dir):
                        jf = list(Path(tmp_dir).rglob("*.java"))
                        return build_java_graph(tmp_dir) if jf else build_graph_for_path(tmp_dir)

                    curr_tmp = tempfile.mkdtemp(prefix="tdra_diff_curr_")
                    try:
                        extract_files_at_commit(str(git_root), full_hash, changed_files, curr_tmp)
                        g_curr = _build_partial(curr_tmp)
                        for nid, d in g_curr.nodes(data=True):
                            f = d.get("file", "")
                            try:
                                rel = Path(f).relative_to(curr_tmp).as_posix().lower()
                            except Exception:
                                rel = Path(f).name.lower()
                            line = d.get("line") or d.get("lineno")
                            if line is not None:
                                current_nodes.setdefault((rel, int(line)), []).append({
                                    "id": str(nid),
                                    "type": d.get("type", ""),
                                })
                    finally:
                        shutil.rmtree(curr_tmp, ignore_errors=True)

                    parent_tmp = tempfile.mkdtemp(prefix="tdra_diff_parent_")
                    try:
                        extract_files_at_commit(str(git_root), parent_hash, changed_files, parent_tmp)
                        g_prev = _build_partial(parent_tmp)
                        for nid, d in g_prev.nodes(data=True):
                            if d.get("type") in ("guard", "sanitizer"):
                                f = d.get("file", "")
                                try:
                                    rel = Path(f).relative_to(parent_tmp).as_posix().lower()
                                except Exception:
                                    rel = Path(f).name.lower()
                                line = d.get("line") or d.get("lineno")
                                if line is not None:
                                    parent_guard_lines.add((rel, int(line)))
                    finally:
                        shutil.rmtree(parent_tmp, ignore_errors=True)
            except Exception:
                pass

        # Also blend in nodes from current graph if available
        try:
            from backend.services.code_security_graph import get_current_graph
            cg = get_current_graph()
            if cg and cg.get("nodes"):
                for n in cg["nodes"]:
                    f = n.get("file", "")
                    rel = Path(f).name.lower()
                    line = n.get("line") or n.get("lineno")
                    if line is not None:
                        current_nodes.setdefault((rel, int(line)), []).append({
                            "id": str(n.get("id", "")),
                            "type": n.get("type", ""),
                        })
        except Exception:
            pass

    except Exception:
        pass

    return current_nodes, parent_guard_lines, new_path_node_ids


@router.get("/blame")
def git_blame(project_path: str = Query(...)):
    allowed_p = resolve_allowed_repo(project_path)
    try:
        git_root = find_git_root(str(allowed_p))
        return {"git_root": git_root, "status": "ok" if git_root else "no_git"}
    except Exception as e:
        return {"git_root": None, "status": "no_git", "detail": str(e)}


@router.get("/timeline")
def git_timeline(project_path: str = Query(...), limit: int = Query(20)):
    allowed_p = resolve_allowed_repo(project_path)
    try:
        import git
        repo = git.Repo(str(allowed_p), search_parent_directories=True)
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


@router.get("/commit-diff")
def get_commit_diff(repo_path: str = Query(...), commit: str = Query(...)):
    if not commit or not re.match(r"^[0-9a-fA-F]{7,40}$", commit):
        raise HTTPException(status_code=400, detail="Invalid commit hash format")

    p = resolve_allowed_repo(repo_path)

    git_root = p if (p / ".git").exists() else (Path(find_git_root(str(p))) if find_git_root(str(p)) else None)
    if not git_root or not (git_root / ".git").exists():
        curr = p
        for _ in range(4):
            if (curr / ".git").exists():
                git_root = curr
                break
            curr = curr.parent
    if not git_root or not (git_root / ".git").exists():
        raise HTTPException(status_code=404, detail="No .git repository found in repository path")

    rev_res = subprocess.run(
        ["git", "-C", str(git_root), "rev-parse", commit],
        capture_output=True, text=True, errors="replace"
    )
    if rev_res.returncode != 0:
        raise HTTPException(status_code=404, detail=f"Commit '{commit}' not found in repository")
    full_hash = rev_res.stdout.strip()

    show_res = subprocess.run(
        ["git", "-C", str(git_root), "show", "--format=", "--unified=3", "--no-color", full_hash],
        capture_output=True, text=True, errors="replace"
    )
    if show_res.returncode != 0:
        raise HTTPException(status_code=404, detail=f"git show failed: {show_res.stderr.strip()}")

    diff_text = show_res.stdout

    current_nodes, parent_guard_lines, new_path_node_ids = _collect_tdra_overlay(git_root, full_hash)

    max_lines = 2000
    total_lines = 0
    truncated = False

    files = []
    cur_file = None
    cur_hunk = None
    old_p = ""
    new_p = ""

    hunk_re = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

    for line in diff_text.splitlines():
        if total_lines >= max_lines:
            truncated = True
            break

        if line.startswith("diff --git"):
            parts = line.split()
            old_p = parts[2][2:] if len(parts) >= 4 and parts[2].startswith("a/") else ""
            new_p = parts[3][2:] if len(parts) >= 4 and parts[3].startswith("b/") else ""
            cur_file = {
                "path": new_p or old_p or "unknown",
                "status": "modified",
                "additions": 0,
                "deletions": 0,
                "hunks": []
            }
            files.append(cur_file)
            cur_hunk = None
        elif cur_file is not None and line.startswith("new file mode"):
            cur_file["status"] = "added"
        elif cur_file is not None and line.startswith("deleted file mode"):
            cur_file["status"] = "deleted"
            if old_p:
                cur_file["path"] = old_p
        elif cur_file is not None and (line.startswith("rename from") or line.startswith("similarity index")):
            cur_file["status"] = "renamed"
        elif cur_file is not None and (line.startswith("Binary files") or "GIT binary patch" in line):
            cur_file["status"] = "binary"
        elif line.startswith("@@ "):
            m = hunk_re.match(line)
            if m and cur_file is not None and cur_file["status"] != "binary":
                old_start = int(m.group(1))
                new_start = int(m.group(3))
                header = line.split(" @@")[0] + " @@" if " @@" in line else line
                cur_hunk = {
                    "header": header,
                    "lines": [],
                    "_old": old_start,
                    "_new": new_start,
                }
                cur_file["hunks"].append(cur_hunk)
        elif cur_hunk is not None and cur_file is not None and cur_file["status"] != "binary":
            if line.startswith("+") and not line.startswith("+++"):
                if total_lines >= max_lines:
                    truncated = True
                    break
                text = line[1:]
                new_no = cur_hunk["_new"]
                cur_hunk["_new"] += 1
                cur_file["additions"] += 1
                total_lines += 1

                marks = []
                matching_nodes = _find_nodes_for_file_line(current_nodes, cur_file["path"], new_no)
                for node in matching_nodes:
                    t = node.get("type", "")
                    nid = node.get("id", "")
                    if t in ("source", "entry") and "entry" not in marks:
                        marks.append("entry")
                    if t == "sink" and "sink" not in marks:
                        marks.append("sink")
                    if t in ("sanitizer", "guard") and "guard" not in marks:
                        marks.append("guard")
                    if nid in new_path_node_ids and "new_path" not in marks:
                        marks.append("new_path")

                if "new_path" not in marks and new_path_node_ids:
                    cur_file_name = Path(cur_file["path"]).name.lower()
                    for np_id in new_path_node_ids:
                        if cur_file_name in np_id.lower():
                            symbol = np_id.split("::")[-1]
                            if symbol and symbol in text and any(k in text for k in ("(", "def ", "class ", "public ", "void ", "String ")):
                                marks.append("new_path")
                                break

                cur_hunk["lines"].append({
                    "type": "add",
                    "old_no": None,
                    "new_no": new_no,
                    "text": text,
                    "marks": marks
                })

            elif line.startswith("-") and not line.startswith("---"):
                if total_lines >= max_lines:
                    truncated = True
                    break
                text = line[1:]
                old_no = cur_hunk["_old"]
                cur_hunk["_old"] += 1
                cur_file["deletions"] += 1
                total_lines += 1

                marks = []
                is_guard_removed = _has_parent_guard(parent_guard_lines, cur_file["path"], old_no)
                if not is_guard_removed:
                    for ann in GUARD_ANNOTATIONS:
                        if ann in text:
                            is_guard_removed = True
                            break
                if is_guard_removed:
                    marks.append("guard_removed")

                cur_hunk["lines"].append({
                    "type": "del",
                    "old_no": old_no,
                    "new_no": None,
                    "text": text,
                    "marks": marks
                })

            elif line.startswith(" "):
                if total_lines >= max_lines:
                    truncated = True
                    break
                text = line[1:]
                old_no = cur_hunk["_old"]
                new_no = cur_hunk["_new"]
                cur_hunk["_old"] += 1
                cur_hunk["_new"] += 1
                total_lines += 1

                marks = []
                matching_nodes = _find_nodes_for_file_line(current_nodes, cur_file["path"], new_no)
                for node in matching_nodes:
                    t = node.get("type", "")
                    nid = node.get("id", "")
                    if t in ("source", "entry") and "entry" not in marks:
                        marks.append("entry")
                    if t == "sink" and "sink" not in marks:
                        marks.append("sink")
                    if t in ("sanitizer", "guard") and "guard" not in marks:
                        marks.append("guard")
                    if nid in new_path_node_ids and "new_path" not in marks:
                        marks.append("new_path")

                cur_hunk["lines"].append({
                    "type": "context",
                    "old_no": old_no,
                    "new_no": new_no,
                    "text": text,
                    "marks": marks
                })

    for f in files:
        for h in f.get("hunks", []):
            h.pop("_old", None)
            h.pop("_new", None)

    return {
        "commit": full_hash,
        "truncated": truncated,
        "files": files
    }
