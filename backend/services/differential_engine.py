from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
import git
import networkx as nx


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

    def get_guard_set(self, G: nx.DiGraph, reachability: set[tuple]) -> dict[tuple, int]:
        """Returns {path_tuple: guard_count} for all paths."""
        result = {}
        for path in reachability:
            node_set = set(path)
            guards = sum(1 for n in node_set if G.nodes.get(n, {}).get("type") == "sanitizer")
            result[path] = guards
        return result

    def analyze_commit(self, parent_hash: str, commit_hash: str) -> dict:
        """Core TDRA differential analysis for one commit."""
        G_prev = self.build_graph_at_commit(parent_hash)
        G_curr = self.build_graph_at_commit(commit_hash)

        R_prev = self.get_reachability_set(G_prev)
        R_curr = self.get_reachability_set(G_curr)
        guards_prev = self.get_guard_set(G_prev, R_prev)
        guards_curr = self.get_guard_set(G_curr, R_curr)

        # New attack paths introduced by this commit
        new_paths = R_curr - R_prev

        # Guard weakening: paths in both versions with fewer guards in curr
        shared_paths = R_prev & R_curr
        guard_weakening = [p for p in shared_paths if guards_curr.get(p, 0) < guards_prev.get(p, 0)]

        # RF formula: alpha=0.6, beta=0.4
        alpha, beta = 0.6, 0.4
        p_before = max(len(R_prev), 1)
        g_before = max(sum(guards_prev.values()), 1)
        delta_paths = len(new_paths)
        delta_guards = len(guard_weakening)

        RF = round(
            alpha * (delta_paths / p_before) +
            beta * (delta_guards / g_before),
            4
        )
        RF = min(RF, 1.0)  # clamp to [0,1]

        # Severity classification
        if RF < 0.2:
            severity = "Low"
        elif RF < 0.45:
            severity = "Medium"
        elif RF < 0.7:
            severity = "High"
        else:
            severity = "Critical"

        commit_obj = self.repo.commit(commit_hash)

        return {
            "commit_hash": commit_hash,
            "parent_hash": parent_hash,
            "author": commit_obj.author.name,
            "date": commit_obj.authored_datetime.isoformat(),
            "message": commit_obj.message.strip(),
            "new_attack_paths": delta_paths,
            "guard_weakening_events": delta_guards,
            "paths_before": len(R_prev),
            "paths_after": len(R_curr),
            "risk_factor": RF,
            "severity": severity,
            "new_paths_detail": [list(p)[:8] for p in list(new_paths)[:5]],
        }
