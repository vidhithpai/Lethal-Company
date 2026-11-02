import asyncio
import httpx
from typing import List, Dict, Any, Optional
import logging
from backend.services.dependency_parser import Dependency

logger = logging.getLogger(__name__)

# Basic caches
_osv_cache: Dict[str, List[Dict[str, Any]]] = {}
_nvd_cache: Dict[str, Dict[str, Any]] = {}

class VulnerabilityProvider:
    async def fetch_vulnerabilities(self, dependencies: List[Dependency]) -> None:
        raise NotImplementedError

class OSVProvider(VulnerabilityProvider):
    OSV_API_URL = "https://api.osv.dev/v1/querybatch"

    async def fetch_vulnerabilities(self, dependencies: List[Dependency]) -> None:
        async with httpx.AsyncClient() as client:
            queries = []
            deps_to_query = []
            
            # Use cache and prepare batch query
            for dep in dependencies:
                if dep.version == "unknown":
                    continue
                cache_key = f"{dep.ecosystem}:{dep.package}:{dep.version}"
                if cache_key in _osv_cache:
                    dep.cves = _osv_cache[cache_key]
                else:
                    queries.append({
                        "version": dep.version,
                        "package": {
                            "name": dep.package,
                            "ecosystem": dep.ecosystem
                        }
                    })
                    deps_to_query.append(dep)
            
            if not queries:
                return

            payload = {"queries": queries}
            try:
                response = await client.post(self.OSV_API_URL, json=payload, timeout=20.0)
                if response.status_code == 200:
                    data = response.json()
                    results = data.get("results", [])
                    
                    for dep, result in zip(deps_to_query, results):
                        vulns = result.get("vulns", []) if result else []
                        cves = self._parse_osv_vulns(vulns, dep.package, dep.version)
                        
                        cache_key = f"{dep.ecosystem}:{dep.package}:{dep.version}"
                        _osv_cache[cache_key] = cves
                        dep.cves = cves
                else:
                    logger.error(f"OSV batch query failed with status {response.status_code}")
            except Exception as e:
                logger.error(f"Error querying OSV batch API: {e}")

    def _parse_osv_vulns(self, vulns: List[Dict[str, Any]], package: str, version: str) -> List[Dict[str, Any]]:
        cves = []
        for vuln in vulns:
            aliases = vuln.get("aliases", [])
            cve_id = next((alias for alias in aliases if alias.startswith("CVE-")), vuln.get("id"))
            
            severity = "UNKNOWN"
            cvss_score = 0.0
            
            for sev in vuln.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    score_vector = sev.get("score", "")
                    # Simple heuristic mapping since we don't have a CVSS parser
                    severity = "CRITICAL" if "CRITICAL" in score_vector or "C" in score_vector else "HIGH" if "HIGH" in score_vector else severity
                    cvss_score = 9.8 if severity == "CRITICAL" else 7.5 if severity == "HIGH" else 5.0 
            
            cve_obj = {
                "id": cve_id,
                "package": package,
                "installed_version": version,
                "fixed_version": "unknown", 
                "severity": severity,
                "cvss": cvss_score,
                "published": vuln.get("published", ""),
                "summary": vuln.get("summary", vuln.get("details", "")[:200] if vuln.get("details") else ""),
                "references": [ref.get("url") for ref in vuln.get("references", [])],
                "cwe": [a for a in aliases if a.startswith("CWE-")]
            }
            cves.append(cve_obj)
        return cves

class NVDProvider:
    # NVD API Enrichment (Secondary)
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    async def enrich_cves(self, dependencies: List[Dependency]) -> None:
        async with httpx.AsyncClient() as client:
            tasks = []
            cve_refs = []
            
            for dep in dependencies:
                for cve in dep.cves:
                    cve_id = cve.get("id")
                    if cve_id and cve_id.startswith("CVE-"):
                        if cve_id in _nvd_cache:
                            self._apply_nvd_enrichment(cve, _nvd_cache[cve_id])
                        else:
                            tasks.append(self._query_nvd(client, cve_id))
                            cve_refs.append(cve)
            
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for cve, result in zip(cve_refs, results):
                    if isinstance(result, dict) and result:
                        cve_id = cve.get("id")
                        if cve_id:
                            _nvd_cache[cve_id] = result
                        self._apply_nvd_enrichment(cve, result)

    async def _query_nvd(self, client: httpx.AsyncClient, cve_id: str) -> Dict[str, Any]:
        # Respect NVD rate limits (without API key it is 5 requests / 30 seconds rolling window)
        # We will do a best effort with a timeout, if it fails we just skip
        try:
            response = await client.get(f"{self.NVD_API_URL}?cveId={cve_id}", timeout=5.0)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                if vulnerabilities:
                    return vulnerabilities[0].get("cve", {})
        except Exception as e:
            logger.debug(f"NVD query failed for {cve_id}: {e}")
        return {}

    def _apply_nvd_enrichment(self, cve: Dict[str, Any], nvd_data: Dict[str, Any]) -> None:
        metrics = nvd_data.get("metrics", {})
        cvss_data = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
        if cvss_data:
            base_score = cvss_data[0].get("cvssData", {}).get("baseScore", cve.get("cvss"))
            base_severity = cvss_data[0].get("cvssData", {}).get("baseSeverity", cve.get("severity"))
            cve["cvss"] = float(base_score)
            cve["severity"] = base_severity
            
        cwes = nvd_data.get("weaknesses", [])
        if cwes:
            extracted_cwes = [desc.get("value") for weak in cwes for desc in weak.get("description", []) if desc.get("value", "").startswith("CWE-")]
            cve["cwe"] = list(set(cve.get("cwe", []) + extracted_cwes))

async def fetch_cves_for_dependencies(dependencies: List[Dependency]) -> None:
    # 1. Primary source
    osv = OSVProvider()
    await osv.fetch_vulnerabilities(dependencies)
    
    # 2. Secondary enrichment
    nvd = NVDProvider()
    await nvd.enrich_cves(dependencies)
