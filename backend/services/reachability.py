from typing import List, Dict, Any, Tuple
import networkx as nx
from backend.services.dependency_parser import Dependency
import logging

logger = logging.getLogger(__name__)

def perform_reachability_analysis(g: nx.DiGraph, dependencies: List[Dependency]) -> List[Dict[str, Any]]:
    results = []
    
    # Pre-compute all application entry points and sources
    sources = [n for n, d in g.nodes(data=True) if d.get('type') == 'source' or 'input' in d.get('label', '').lower()]
    if not sources:
        sources = [n for n, d in g.in_degree() if d == 0]

    for dep in dependencies:
        if not dep.cves:
            continue
            
        reachable = False
        confidence = 0.0
        entry_points = []
        call_chain = []
        affected_files = set()
        
        # 1. Find nodes related to the package
        imported_nodes = []
        for n, data in g.nodes(data=True):
            file_path = data.get('file', '')
            label = data.get('label', '')
            node_type = data.get('type', '')
            
            # Check for import nodes or usage in labels
            if dep.package in label or dep.package in file_path or (node_type == 'import' and dep.package in label):
                imported_nodes.append(n)
                if file_path:
                    affected_files.add(file_path)
                
        if imported_nodes:
            confidence = 0.5
            
            # 2. Path finding from sources to imported nodes
            for src in sources:
                for imp_node in imported_nodes:
                    try:
                        if nx.has_path(g, src, imp_node):
                            reachable = True
                            confidence = 0.95
                            if src not in entry_points:
                                entry_points.append(src)
                            
                            path = nx.shortest_path(g, src, imp_node)
                            if not call_chain or len(path) < len(call_chain):
                                call_chain = path # Keep shortest path
                    except nx.NetworkXNoPath:
                        continue
                    except Exception as e:
                        logger.error(f"Error checking path: {e}")
        
        # 3. Calculate Risk Score based on CVSS and Reachability
        max_cvss = max([c.get('cvss', 0.0) for c in dep.cves] + [0.0])
        base_score = max_cvss * 10
        
        overall_score = base_score
        
        if reachable:
            overall_score *= 1.2
            # Add small penalty/bonus based on number of attack paths
            if len(entry_points) > 1:
                overall_score += len(entry_points) * 0.5
        else:
            overall_score *= 0.6
            
        overall_score = min(100.0, overall_score)
        
        if overall_score >= 90:
            priority = "Critical"
        elif overall_score >= 70:
            priority = "High"
        elif overall_score >= 40:
            priority = "Medium"
        else:
            priority = "Low"
            
        results.append({
            "package": dep.package,
            "version": dep.version,
            "reachable": reachable,
            "confidence": confidence,
            "entry_points": entry_points,
            "affected_files": list(affected_files),
            "call_chain": call_chain,
            "risk_score": {
                "overall_score": int(overall_score),
                "priority": priority
            },
            "cves": dep.cves
        })
        
    return results

def inject_cves_into_graph(g: nx.DiGraph, reachability_results: List[Dict[str, Any]]) -> None:
    for res in reachability_results:
        pkg_id = f"pkg:{res['package']}@{res['version']}"
        g.add_node(pkg_id, type="package", label=f"{res['package']}@{res['version']}", reachable=res['reachable'])
        
        for affected in res['affected_files']:
            file_nodes = [n for n, d in g.nodes(data=True) if d.get('file') == affected]
            if file_nodes:
                g.add_edge(file_nodes[0], pkg_id, type="depends_on")
                
        for cve in res['cves']:
            cve_id = cve['id']
            g.add_node(cve_id, type="cve", label=cve_id, severity=cve['severity'], cvss=cve['cvss'])
            g.add_edge(pkg_id, cve_id, type="has_vulnerability")
