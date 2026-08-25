from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
import git
import networkx as nx

from .guard_attenuation import (
    compute_path_residual_risk,
    compute_delta_attenuation,
)


class DifferentialEngine:
    def __init__(self, repo_path: str):
        self.repo_path = str(Path(repo_path).resolve())
        self.repo = git.Repo(self.repo_path)
        self._graph_cache: dict[str, nx.DiGraph] = {}

    def get_commit_pairs(self, limit: int = 50) -> list[tuple[str, str]]:
        """Returns list of (parent_hash, commit_hash) tuples, newest first."""
        try:
            commits = list(self.repo.iter_commits(max_count=limit))
        except (git.exc.GitCommandError, ValueError):
            return []
        if len(commits) < 2:
            return []
        return [(commits[i + 1].hexsha, commits[i].hexsha) for i in range(len(commits) - 1)]

    def get_diff_changed_files(self, parent_hash: str, commit_hash: str) -> list[str]:
        """
        Uses git diff to get only the files changed between parent and commit.
        Returns list of absolute file paths that were added or modified.
        """
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", "--diff-filter=AM",
                 parent_hash, commit_hash],
                capture_output=True, text=True, cwd=self.repo_path, check=True
            )
            changed = [f.strip() for f in result.stdout.strip().splitlines() if f.strip()]
            return [str(Path(self.repo_path) / f) for f in changed]
        except subprocess.CalledProcessError:
            return []

    def get_diff_hunks(self, parent_hash: str, commit_hash: str) -> dict[str, str]:
        """
        Returns {filepath: unified_diff_text} for all changed files.
        This is the raw git diff output per file — used to identify
        which methods were added or modified in the commit.
        """
        try:
            result = subprocess.run(
                ["git", "diff", "-U3", parent_hash, commit_hash],
                capture_output=True, text=True, errors="replace", cwd=self.repo_path
            )
            diffs = {}
            current_file = None
            current_lines = []
            for line in result.stdout.splitlines():
                if line.startswith("diff --git"):
                    if current_file:
                        diffs[current_file] = "\n".join(current_lines)
                    current_file = None
                    current_lines = []
                elif line.startswith("+++ b/"):
                    current_file = line[6:].strip()
                    current_lines = []
                elif current_file:
                    current_lines.append(line)
            if current_file:
                diffs[current_file] = "\n".join(current_lines)
            return diffs
        except Exception:
            return {}

    def build_graph_scoped_to_diff(
        self, commit_hash: str, changed_files: list[str]
    ) -> nx.DiGraph:
        """
        Builds a graph for ONLY the changed files at commit_hash.
        Checks out those specific files into a temp dir, analyzes them,
        and returns a partial graph. Much faster than full clone.
        """
        if not changed_files:
            return nx.DiGraph()

        if commit_hash in self._graph_cache:
            return self._graph_cache[commit_hash]

        tmp_dir = tempfile.mkdtemp(prefix="tdra_diff_")
        try:
            for rel_path in changed_files:
                # Get the relative path from repo root
                try:
                    rel = str(Path(rel_path).relative_to(self.repo_path))
                except ValueError:
                    rel = Path(rel_path).name

                out_path = Path(tmp_dir) / rel
                out_path.parent.mkdir(parents=True, exist_ok=True)

                try:
                    res = subprocess.run(
                        ["git", "show", f"{commit_hash}:{rel}"],
                        capture_output=True,
                        cwd=self.repo_path, check=True
                    )
                    content = res.stdout.decode("utf-8", errors="replace")
                    out_path.write_text(content, encoding="utf-8", errors="replace")
                except subprocess.CalledProcessError:
                    continue  # file may not exist at this commit

            from .code_security_graph import build_graph_for_path
            from .java_graph_builder import build_java_graph

            java_files = list(Path(tmp_dir).rglob("*.java"))
            if java_files:
                G = build_java_graph(tmp_dir)
            else:
                G = build_graph_for_path(tmp_dir)

            self._graph_cache[commit_hash] = G
            return G
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def build_graph_at_commit(self, commit_hash: str) -> nx.DiGraph:
        """
        Build the graph for a given commit WITHOUT touching the caller's
        working tree. Clones the repo into a temp dir and checks out the
        commit there, so this is safe to call even if the user has
        uncommitted changes in repo_path, and safe across a loop of many
        commits (no shared mutable checkout state to corrupt).
        """
        if commit_hash in self._graph_cache:
            return self._graph_cache[commit_hash]

        tmp_dir = tempfile.mkdtemp(prefix="tdra_")
        try:
            clone = git.Repo.clone_from(self.repo_path, tmp_dir)
            clone.git.checkout(commit_hash)

            from .code_security_graph import build_graph_for_path
            from .java_graph_builder import build_java_graph

            java_files = list(Path(tmp_dir).rglob("*.java"))
            if java_files:
                G = build_java_graph(tmp_dir)
            else:
                G = build_graph_for_path(tmp_dir)

            self._graph_cache[commit_hash] = G
            return G
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def get_reachability_set(self, G: nx.DiGraph, max_paths: int = 5000) -> set[tuple]:
        """
        Returns a set of ORDERED tuples, each representing one distinct
        source->sink path.
        """
        sources = [n for n, d in G.nodes(data=True) if d.get("type") == "source"]
        sinks = [n for n, d in G.nodes(data=True) if d.get("type") == "sink"]
        paths = set()
        for src in sources:
            for sink in sinks:
                try:
                    for path in nx.all_simple_paths(G, src, sink, cutoff=15):
                        paths.add(tuple(path))
                        if len(paths) >= max_paths:
                            return paths
                except Exception:
                    continue
        return paths

    def get_guard_set(self, G: nx.DiGraph, reachability: set[tuple]) -> dict[tuple, float]:
        """
        Returns {path_tuple: effective_guard_strength}.
        """
        result = {}
        for path in reachability:
            path_nodes = list(path)
            sink_id = path_nodes[-1] if path_nodes else None
            analysis = compute_path_residual_risk(path_nodes, G, sink_id or "")
            result[path] = analysis["effective_guard_strength"]
        return result

    def analyze_commit(self, parent_hash: str, commit_hash: str) -> dict:
        """
        Core TDRA differential analysis.
        Uses git diff to scope analysis to changed files only.
        Falls back to full clone if diff is empty.
        """
        # Get changed files via git diff
        changed_files = self.get_diff_changed_files(parent_hash, commit_hash)
        diff_hunks = self.get_diff_hunks(parent_hash, commit_hash)
        
        if changed_files:
            # Fast path: build graph only for changed files at each version
            # For parent: get the PARENT version of changed files
            parent_tmp = tempfile.mkdtemp(prefix="tdra_parent_")
            curr_tmp = tempfile.mkdtemp(prefix="tdra_curr_")
            try:
                # Extract changed files at parent commit
                parent_changed = []
                curr_changed = []
                for rel_path in changed_files:
                    try:
                        rel = str(Path(rel_path).relative_to(self.repo_path))
                    except ValueError:
                        rel = Path(rel_path).name
                    
                    # Parent version
                    p_out = Path(parent_tmp) / rel
                    p_out.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        p_res = subprocess.run(
                            ["git", "show", f"{parent_hash}:{rel}"],
                            capture_output=True,
                            cwd=self.repo_path, check=True
                        )
                        p_content = p_res.stdout.decode("utf-8", errors="replace")
                        p_out.write_text(p_content, encoding="utf-8", errors="replace")
                        parent_changed.append(str(p_out))
                    except subprocess.CalledProcessError:
                        pass  # new file, doesn't exist in parent

                    # Current version
                    c_out = Path(curr_tmp) / rel
                    c_out.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        c_res = subprocess.run(
                            ["git", "show", f"{commit_hash}:{rel}"],
                            capture_output=True,
                            cwd=self.repo_path, check=True
                        )
                        c_content = c_res.stdout.decode("utf-8", errors="replace")
                        c_out.write_text(c_content, encoding="utf-8", errors="replace")
                        curr_changed.append(str(c_out))
                    except subprocess.CalledProcessError:
                        pass

                from .code_security_graph import build_graph_for_path
                from .java_graph_builder import build_java_graph

                def build(tmp):
                    jf = list(Path(tmp).rglob("*.java"))
                    return build_java_graph(tmp) if jf else build_graph_for_path(tmp)

                G_prev = build(parent_tmp) if parent_changed else nx.DiGraph()
                G_curr = build(curr_tmp) if curr_changed else nx.DiGraph()
            finally:
                shutil.rmtree(parent_tmp, ignore_errors=True)
                shutil.rmtree(curr_tmp, ignore_errors=True)
        else:
            # Fallback to original full-clone approach
            G_prev = self.build_graph_at_commit(parent_hash)
            G_curr = self.build_graph_at_commit(commit_hash)

        R_prev = self.get_reachability_set(G_prev)
        R_curr = self.get_reachability_set(G_curr)
        guards_prev = self.get_guard_set(G_prev, R_prev)
        guards_curr = self.get_guard_set(G_curr, R_curr)

        new_paths = R_curr - R_prev
        shared_paths = R_prev & R_curr
        
        guard_weakening = []
        total_attenuation_drop = 0.0

        for path in shared_paths:
            A_prev = guards_prev.get(path, 0.0)
            A_curr = guards_curr.get(path, 0.0)
            drop = A_prev - A_curr
            if drop > 0.05:  # threshold: >5% effective guard strength lost
                guard_weakening.append(path)
                total_attenuation_drop += drop

        alpha, beta = 0.6, 0.4
        p_before = max(len(R_prev), 1)
        
        path_expansion_score = len(new_paths) / p_before
        
        # Guard component: weighted by magnitude of attenuation drop
        # If no prior guards, attenuation drop is 0
        total_prior_attenuation = max(sum(guards_prev.values()), 0.01)
        guard_regression_score = total_attenuation_drop / total_prior_attenuation

        RF = round(
            alpha * min(path_expansion_score, 1.0) +
            beta  * min(guard_regression_score, 1.0),
            4
        )
        RF = min(RF, 1.0)

        if RF < 0.2: severity = "Low"
        elif RF < 0.45: severity = "Medium"
        elif RF < 0.7: severity = "High"
        else: severity = "Critical"

        commit_obj = self.repo.commit(commit_hash)
        return {
            "commit_hash": commit_hash,
            "parent_hash": parent_hash,
            "author": commit_obj.author.name,
            "date": commit_obj.authored_datetime.isoformat(),
            "message": commit_obj.message.strip(),
            "changed_files": [Path(f).name for f in changed_files],
            "diff_lines_changed": sum(
                len([l for l in d.splitlines() if l.startswith(("+", "-")) 
                     and not l.startswith(("---", "+++"))])
                for d in diff_hunks.values()
            ),
            "new_attack_paths": len(new_paths),
            "guard_weakening_events": len(guard_weakening),
            "total_attenuation_drop": round(total_attenuation_drop, 4),
            "guard_regression_score": round(guard_regression_score, 4),
            "path_expansion_score": round(path_expansion_score, 4),
            "paths_before": len(R_prev),
            "paths_after": len(R_curr),
            "rf_score": RF,
            "severity": severity,
            "new_paths_detail": [list(p)[:8] for p in list(new_paths)[:5]],
            "analysis_method": "git_diff_scoped" if changed_files else "full_clone",
        }
