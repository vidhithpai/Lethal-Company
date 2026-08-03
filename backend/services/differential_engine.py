import git
import networkx as nx
from pathlib import Path

class DifferentialEngine:
    
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.repo = git.Repo(repo_path)  # use gitpython
    
    def get_commit_pairs(self, limit: int = 50) -> list[tuple]:
        """Returns list of (parent_hash, commit_hash) tuples, newest first"""
        commits = list(self.repo.iter_commits(max_count=limit))
        return [(commits[i+1].hexsha, commits[i].hexsha) 
                for i in range(len(commits)-1)]
    
    def build_graph_at_commit(self, commit_hash: str) -> nx.DiGraph:
        """Checkout commit, build graph, restore HEAD"""
        original = self.repo.head.commit.hexsha
        try:
            self.repo.git.stash()
            self.repo.git.checkout(commit_hash)
            # detect language and build appropriate graph
            from .code_security_graph import build_graph_for_path
            from .java_graph_builder import build_java_graph
            java_files = list(Path(self.repo_path).rglob("*.java"))
            if java_files:
                G = build_java_graph(self.repo_path)
            else:
                G = build_graph_for_path(self.repo_path)
            return G
        finally:
            self.repo.git.checkout(original)
            try: self.repo.git.stash('pop')
            except: pass
    
    def get_reachability_set(self, G: nx.DiGraph) -> set[frozenset]:
        """Returns set of frozensets, each representing one E->S path"""
        sources = [n for n,d in G.nodes(data=True) if d.get('type')=='source']
        sinks = [n for n,d in G.nodes(data=True) if d.get('type')=='sink']
        paths = set()
        for src in sources:
            for sink in sinks:
                try:
                    for path in nx.all_simple_paths(G, src, sink, cutoff=15):
                        paths.add(frozenset(path))
                except: continue
        return paths
    
    def get_guard_set(self, G: nx.DiGraph, 
                      reachability: set) -> dict[frozenset, int]:
        """Returns {path_frozenset: guard_count} for all paths"""
        result = {}
        for path_fs in reachability:
            guards = sum(1 for n in path_fs 
                        if G.nodes.get(n, {}).get('type') == 'sanitizer')
            result[path_fs] = guards
        return result
    
    def analyze_commit(self, parent_hash: str, 
                       commit_hash: str) -> dict:
        """Core TDRA differential analysis for one commit"""
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
        guard_weakening = [p for p in shared_paths 
                          if guards_curr.get(p, 0) < guards_prev.get(p, 0)]
        
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
            "new_attack_paths": delta_paths,
            "guard_weakening_events": delta_guards,
            "paths_before": len(R_prev),
            "paths_after": len(R_curr),
            "risk_factor": RF,
            "severity": severity,
            "new_paths_detail": [list(p)[:8] for p in list(new_paths)[:5]]
        }
