from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

from backend.services.dependency_parser import discover_dependencies
from backend.services.cve_lookup import fetch_cves_for_dependencies
from backend.services.reachability import perform_reachability_analysis, inject_cves_into_graph
from backend.services.code_security_graph import get_current_graph_nodes, _current_graph
from backend.services.cve_explainer import explain_cve

import networkx as nx

router = APIRouter(prefix="/api/cve", tags=["cve"])

# In-memory store for the latest scan results
_latest_cve_results = []
_latest_dependencies = []

class ScanRequest(BaseModel):
    project_path: str

class ExplainRequest(BaseModel):
    cve_id: str
    package: str

@router.post("/scan")
async def cve_scan(req: ScanRequest):
    global _latest_cve_results, _latest_dependencies
    
    # 1. Discover Dependencies
    deps = discover_dependencies(req.project_path)
    _latest_dependencies = [d.to_dict() for d in deps]
    
    # 2. Fetch CVEs
    await fetch_cves_for_dependencies(deps)
    
    # 3. Reconstruct Graph from current state
    g = nx.DiGraph()
    for node in _current_graph.get("nodes", []):
        if "id" in node:
            g.add_node(node["id"], **node)
    
    # 4. Reachability & Integration
    reach_results = perform_reachability_analysis(g, deps)
    _latest_cve_results = reach_results
    
    inject_cves_into_graph(g, reach_results)
    
    # Update current graph nodes with new injected nodes/edges
    _current_graph["nodes"] = [dict(data, id=n) for n, data in g.nodes(data=True)]
    
    cves_found = sum(len(r['cves']) for r in reach_results)
    
    return {
        "message": "CVE Scan complete",
        "dependencies_found": len(deps),
        "cves_found": cves_found,
        "results": reach_results
    }

@router.get("/list")
def list_cves(severity: Optional[str] = None, package: Optional[str] = None, search: Optional[str] = None, page: int = 1, limit: int = 50):
    results = _latest_cve_results
    
    if package:
        results = [r for r in results if r.get('package', '').lower() == package.lower()]
        
    if severity:
        results = [r for r in results if any(c.get('severity') == severity for c in r.get('cves', []))]
        
    if search:
        search = search.lower()
        results = [r for r in results if search in r.get('package', '').lower() or any(search in c.get('id', '').lower() or search in c.get('summary', '').lower() for c in r.get('cves', []))]
        
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    
    return {
        "total": len(results),
        "page": page,
        "limit": limit,
        "results": results[start_idx:end_idx]
    }

@router.get("/{cve_id}")
def get_cve(cve_id: str):
    for res in _latest_cve_results:
        for cve in res.get('cves', []):
            if cve.get('id') == cve_id:
                return {"cve": cve, "reachability": res}
    raise HTTPException(status_code=404, detail="CVE not found")

@router.post("/explain")
def explain_cve_endpoint(req: ExplainRequest):
    for res in _latest_cve_results:
        if res.get('package') == req.package:
            for cve in res.get('cves', []):
                if cve.get('id') == req.cve_id:
                    explanation = explain_cve(cve, res)
                    return {"explanation": explanation}
    raise HTTPException(status_code=404, detail="CVE or Package not found")

@router.post("/reachable")
def is_reachable(req: ExplainRequest):
    for res in _latest_cve_results:
        if res.get('package') == req.package:
            return {"reachable": res.get("reachable"), "confidence": res.get("confidence")}
    raise HTTPException(status_code=404, detail="Package not found")
