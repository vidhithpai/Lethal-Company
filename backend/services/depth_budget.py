"""
Adaptive depth budgeting for TDRA reachability analysis.
Borrowed from CodeGraph's adaptive exploration sizing concept.
"""

import math
from dataclasses import dataclass
import networkx as nx


@dataclass
class DepthBudget:
    max_depth: int           # max hops per path
    max_paths_per_entry: int # max paths to enumerate per ENTRY node
    max_total_paths: int     # hard cap across all ENTRY nodes
    strategy: str            # 'full' | 'bounded' | 'sampled' | 'entry_local'
    reason: str              # human-readable explanation for the paper


def compute_depth_budget(G: nx.DiGraph,
                          time_budget_seconds: float = 30.0) -> DepthBudget:
    """
    Compute safe depth and path limits for this graph.
    
    Strategy selection:
    - tiny   (<50 nodes):   full analysis, depth=15
    - small  (<500 nodes):  bounded, depth=12
    - medium (<2000 nodes): bounded, depth=10, cap paths
    - large  (<10000 nodes): entry-local, depth=8, strict cap
    - xlarge (>=10000 nodes): sampled, depth=6, very strict cap
    """
    n_nodes  = G.number_of_nodes()
    n_edges  = G.number_of_edges()
    n_entry  = len([n for n,d in G.nodes(data=True) 
                    if d.get('type') == 'source'])
    n_sink   = len([n for n,d in G.nodes(data=True)
                    if d.get('type') == 'sink'])
    
    # Avg branching factor estimate
    avg_branch = n_edges / max(n_nodes, 1)
    avg_branch = max(1.0, min(avg_branch, 8.0))  # clamp to [1,8]
    
    if n_nodes < 50:
        return DepthBudget(
            max_depth=15,
            max_paths_per_entry=1000,
            max_total_paths=10000,
            strategy='full',
            reason=f'Tiny graph ({n_nodes} nodes): full analysis, d=15'
        )
    
    elif n_nodes < 500:
        return DepthBudget(
            max_depth=12,
            max_paths_per_entry=500,
            max_total_paths=5000,
            strategy='bounded',
            reason=f'Small graph ({n_nodes} nodes): bounded, d=12'
        )
    
    elif n_nodes < 2000:
        # Estimate: n_entry × b^10 should fit in time budget
        estimated_paths = n_entry * (avg_branch ** 10)
        if estimated_paths > 50000:
            depth = max(6, int(math.log(50000 / max(n_entry,1), avg_branch)))
        else:
            depth = 10
        return DepthBudget(
            max_depth=depth,
            max_paths_per_entry=200,
            max_total_paths=2000,
            strategy='bounded',
            reason=f'Medium graph ({n_nodes} nodes, {n_entry} entries): d={depth}'
        )
    
    elif n_nodes < 10000:
        depth = 8
        return DepthBudget(
            max_depth=depth,
            max_paths_per_entry=50,
            max_total_paths=500,
            strategy='entry_local',
            reason=f'Large graph ({n_nodes} nodes): entry-local analysis, d={depth}'
        )
    
    else:
        return DepthBudget(
            max_depth=6,
            max_paths_per_entry=20,
            max_total_paths=200,
            strategy='sampled',
            reason=f'XL graph ({n_nodes} nodes): sampled reachability, d=6'
        )
