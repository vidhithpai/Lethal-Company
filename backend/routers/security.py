from __future__ import annotations

from pathlib import Path
from fastapi import APIRouter, HTTPException, Query
import networkx as nx

from backend.services.code_security_graph import (
    compute_attack_paths,
    compute_attack_surface,
    compute_high_risk_paths,
    get_security_graph,
    invalidate_security_graph_cache,
    patch_security_node,
    resolve_node_ref,
    shortest_path_to_target,
    detect_security_communities,
    COMMUNITY_COLORS,
    compute_patch_impact,
)
from backend.services.path_guard import is_safe_file_path

router = APIRouter(tags=["security"])


@router.get("/api/graph")
def read_graph():
    built = get_security_graph()
    g = built["graph"]
    communities = detect_security_communities(g)
    paths = compute_attack_paths(limit=500, max_depth=14)
    meta = {
        "total_nodes": len(g.nodes),
        "total_sources": len([n for _, n in g.nodes(data=True) if n.get("type") == "source"]),
        "total_sinks": len([n for _, n in g.nodes(data=True) if n.get("type") == "sink"]),
        "total_paths": len(paths),
        "communities_detected": len(set(communities.values())),
        "scanned_project": "Project",
        "scan_time_ms": 150
    }
    
    # Extract live nodes from graph (since git blame is injected post-build)
    live_nodes = [dict(data, id=n) for n, data in g.nodes(data=True)]
    
    return {"nodes": live_nodes, "links": built["edges"], "path": [], "meta": meta}


@router.get("/api/attack-surface")
def read_attack_surface():
    surface = compute_attack_surface()
    return {"nodes": surface, "edges": [], "path": []}


@router.get("/api/attack-paths")
def read_attack_paths(
    limit: int = Query(50, ge=1, le=500),
    max_depth: int = Query(12, ge=1, le=50),
):
    paths = compute_attack_paths(limit=limit, max_depth=max_depth)
    return {"paths": paths}


@router.get("/api/high-risk-paths")
def read_high_risk_paths(limit: int = Query(20, ge=1, le=200)):
    paths = compute_high_risk_paths(limit=limit)
    return {"paths": paths}


@router.get("/api/graph/path")
def read_graph_path(target: str):
    # `target` should be a node id (sink). Returns path array of node ids.
    return {"path": shortest_path_to_target(target)}


@router.post("/api/graph/patch/{node_id:path}")
def patch_graph_node(node_id: str):
    built_before = get_security_graph()
    all_paths = compute_attack_paths(limit=500, max_depth=14)
    impact = compute_patch_impact(built_before["graph"], node_id, all_paths)

    patch_security_node(node_id)
    invalidate_security_graph_cache()
    built = get_security_graph()
    live_nodes = [dict(data, id=n) for n, data in built["graph"].nodes(data=True)]
    return {"nodes": live_nodes, "links": built["edges"], "path": [], "patch_impact": impact.get("patch_impact")}

@router.get("/api/communities")
def read_communities():
    built = get_security_graph()
    g = built["graph"]
    communities = detect_security_communities(g)
    
    groups = {}
    for node_id, comm in communities.items():
        if comm not in groups:
            groups[comm] = {"nodes": [], "count": 0, "color": COMMUNITY_COLORS.get(comm, "#6B7280")}
        groups[comm]["nodes"].append(node_id)
        groups[comm]["count"] += 1
        
    return {
        "communities": groups,
        "summary": f"{len(groups)} communities detected."
    }

CWE_CATALOG: dict[str, dict[str, str]] = {
    "CWE-78": {
        "name": "OS Command Injection",
        "severity": "CRITICAL",
        "description": "Executes operating system commands constructed from external input without proper sanitization.",
        "attack_surface": "Attacker-controlled input reaches a system shell or process execution sink.",
        "recommendation": "Use argument arrays rather than command strings (e.g. subprocess.run(['cmd', arg], shell=False)). Do not invoke system shell directly."
    },
    "CWE-89": {
        "name": "SQL Injection",
        "severity": "CRITICAL",
        "description": "Constructs database queries using dynamic concatenation of untrusted input, permitting query manipulation.",
        "attack_surface": "Data flows into database execution APIs without parameterization.",
        "recommendation": "Use parameterized queries or prepared statements (e.g. cursor.execute('SELECT * FROM t WHERE id=?', (val,)))."
    },
    "CWE-95": {
        "name": "Code Injection ('Eval Injection')",
        "severity": "CRITICAL",
        "description": "Passes dynamic code strings into a language interpreter (eval/exec) executed in the application context.",
        "attack_surface": "Unvalidated input is evaluated directly as code.",
        "recommendation": "Eliminate eval() and exec(). Use ast.literal_eval() or JSON parsing for structured data representations."
    },
    "CWE-94": {
        "name": "Improper Control of Generation of Code ('Code Injection')",
        "severity": "CRITICAL",
        "description": "External input influences dynamically synthesized code or logic blocks.",
        "attack_surface": "Input controls code compilation or script generation.",
        "recommendation": "Refactor away from dynamic code generation. Use static mappings and strict whitelists."
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "severity": "CRITICAL",
        "description": "Deserializes untrusted byte streams without verification, permitting arbitrary object creation and remote code execution.",
        "attack_surface": "Untrusted serialized data is passed to unverified deserializers (pickle, ObjectInputStream, unsafe yaml).",
        "recommendation": "Do not deserialize untrusted data with pickle or ObjectInputStream. Use safe interchange formats like JSON."
    },
    "CWE-22": {
        "name": "Path Traversal / Unsafe File Access",
        "severity": "HIGH",
        "description": "Uses external input to construct file paths without verifying they remain within intended directory boundaries.",
        "attack_surface": "File system operations receive user-supplied filenames or relative path segments (e.g. ../).",
        "recommendation": "Canonicalize paths using os.path.realpath() and verify that the target path begins with the allowed base directory."
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "severity": "HIGH",
        "description": "Initiates network requests to destinations derived from untrusted input, potentially exposing internal services or cloud metadata.",
        "attack_surface": "HTTP or network client requests URLs controlled or influenced by external callers.",
        "recommendation": "Validate request URLs against a strict domain whitelist and reject private IP ranges (127.0.0.1, 10.0.0.0/8, 169.254.169.254)."
    },
    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "description": "Outputs untrusted data to browser contexts without contextual sanitization or encoding.",
        "attack_surface": "User data flows into HTTP responses or dynamic HTML rendering without encoding.",
        "recommendation": "Contextually encode all user-supplied data (HTML, JavaScript, attribute encoding) before writing to response streams."
    },
    "CWE-611": {
        "name": "XML External Entity (XXE) Injection",
        "severity": "HIGH",
        "description": "Parses untrusted XML documents with external entity resolution enabled.",
        "attack_surface": "XML parsing pipelines process attacker-supplied schemas or entity definitions.",
        "recommendation": "Disable external entity resolution (DTD resolution) in XML parsers or use defusedxml."
    },
    "CWE-1336": {
        "name": "Server-Side Template Injection (SSTI)",
        "severity": "CRITICAL",
        "description": "Renders user input directly as template code rather than template data.",
        "attack_surface": "Template engine evaluates expressions contained inside attacker-supplied strings.",
        "recommendation": "Pass user values strictly as context variables to templates; do not render format strings directly."
    },
    "CWE-470": {
        "name": "Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')",
        "severity": "HIGH",
        "description": "Dynamically instantiates classes or invokes methods using untrusted class names or method identifiers.",
        "attack_surface": "Reflection calls (Class.forName, Method.invoke) resolve targets directly from inputs.",
        "recommendation": "Use a closed whitelist map to look up permitted classes and methods."
    },
    "CWE-20": {
        "name": "Improper Input Validation (Generic - unmapped)",
        "severity": "MEDIUM",
        "description": "Operation receives input without verifying conformance against expected formats, types, or boundary limits.",
        "attack_surface": "Data is processed without formal schema or pattern validation.",
        "recommendation": "Implement strict input validation schemas, type checking, and sanitization boundaries."
    }
}


def infer_node_cwe(node_data: dict) -> tuple[str, str]:
    cwe = node_data.get("cwe")
    cwe_name = node_data.get("cwe_name")
    if cwe and cwe in CWE_CATALOG:
        return cwe, cwe_name or CWE_CATALOG[cwe]["name"]

    sink_kind = node_data.get("sink_kind")
    if sink_kind:
        kind_map = {
            "cmd_execution": ("CWE-78", "OS Command Injection"),
            "eval_exec": ("CWE-95", "Code Injection ('Eval Injection')"),
            "sql_execution": ("CWE-89", "SQL Injection"),
            "deserialization": ("CWE-502", "Deserialization of Untrusted Data"),
            "file_write": ("CWE-22", "Path Traversal / Unsafe File Write"),
            "ssrf": ("CWE-918", "Server-Side Request Forgery (SSRF)"),
            "ssti": ("CWE-1336", "Server-Side Template Injection (SSTI)"),
        }
        if sink_kind in kind_map:
            return kind_map[sink_kind]

    label = (node_data.get("label") or node_data.get("id") or "").lower()
    if any(k in label for k in ("subprocess", "os.system", "popen", "processbuilder", "runtime.exec", "system(")):
        if "eval(" not in label and "exec(" not in label:
            return "CWE-78", "OS Command Injection"
    if any(k in label for k in ("eval(", "exec(", "eval_exec", "eval")):
        return "CWE-95", "Code Injection ('Eval Injection')"
    if any(k in label for k in ("execute(", "executequery", "executeupdate", "createquery", "createnativequery", "sql")):
        return "CWE-89", "SQL Injection"
    if any(k in label for k in ("pickle", "yaml.load", "objectinputstream", "readobject", "deserialize")):
        return "CWE-502", "Deserialization of Untrusted Data"
    if any(k in label for k in ("open(", "write_text", "write_bytes", "filewriter", "files.write", "rmtree", "path")):
        return "CWE-22", "Path Traversal / Unsafe File Write"
    if any(k in label for k in ("requests.", "httpx.", "urlopen", "ssrf")):
        return "CWE-918", "Server-Side Request Forgery (SSRF)"
    if any(k in label for k in ("render_template_string", "ssti")):
        return "CWE-1336", "Server-Side Template Injection (SSTI)"
    if any(k in label for k in ("response.getwriter", "xss")):
        return "CWE-79", "Cross-Site Scripting (XSS)"
    if any(k in label for k in ("forname", "method.invoke", "reflection")):
        return "CWE-470", "Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')"

    if node_data.get("type") == "sink":
        return "CWE-20", "Improper Input Validation (Unclassified Sink)"

    return "", ""


def build_node_analysis(
    node_id: str,
    node_data: dict,
    g: nx.DiGraph,
    upstream_sources: list[dict],
    downstream_sinks: list[dict],
    paths_through: list[dict]
) -> dict:
    node_type = str(node_data.get("type", "normal")).lower()
    filepath = node_data.get("file", "")
    fname = Path(filepath).name if filepath else "unknown"
    line = node_data.get("line", 1)
    label = node_data.get("label") or node_id

    # SINK NODE
    if node_type == "sink":
        primary_cwe, primary_name = infer_node_cwe(node_data)
        catalog_entry = CWE_CATALOG.get(primary_cwe, CWE_CATALOG["CWE-20"])
        cwes = [{"cwe": primary_cwe, "name": primary_name, "role": "sink"}]
        severity = catalog_entry.get("severity", "HIGH")
        what_it_does = f"Dangerous execution sink '{label}' at {fname}:{line}. {catalog_entry['description']}"

        path_sample = ""
        if paths_through:
            sample_p = paths_through[0].get("path", [])
            labels = [g.nodes[x].get("label", x) for x in sample_p if x in g]
            if labels:
                path_sample = " → ".join(labels[:4])
                if len(labels) > 4:
                    path_sample += f" → ... → {labels[-1]}"

        if path_sample:
            root_cause = f"Reachable along attack corridor: {path_sample}. Taint flows into this sink without required sanitization."
        elif upstream_sources:
            src_names = ", ".join(s["label"] for s in upstream_sources[:3])
            root_cause = f"Reachable from user-controlled input source(s): {src_names}."
        else:
            root_cause = catalog_entry["attack_surface"]

        fix = catalog_entry["recommendation"]

    # SOURCE NODE (e.g. os.getenv, request.args)
    elif node_type == "source":
        sink_cwes = []
        seen_cwes = set()
        for s in downstream_sinks:
            sid = s["id"]
            sdata = g.nodes.get(sid, {})
            scwe, sname = infer_node_cwe(sdata)
            if scwe and scwe not in seen_cwes:
                seen_cwes.add(scwe)
                sink_cwes.append({
                    "cwe": scwe,
                    "name": sname,
                    "sink": s.get("label", sid),
                    "role": "downstream_sink",
                    "severity": CWE_CATALOG.get(scwe, {}).get("severity", "HIGH")
                })

        if sink_cwes:
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            sink_cwes.sort(key=lambda x: sev_order.get(x["severity"], 99))
            primary_cwe = sink_cwes[0]["cwe"]
            primary_name = sink_cwes[0]["name"]
            severity = sink_cwes[0]["severity"]
            cwe_list_str = ", ".join(f"{c['cwe']} ({c['name']})" for c in sink_cwes)

            what_it_does = f"Untrusted input origin '{label}' at {fname}:{line}. This node introduces external user-controlled data into the application."

            path_sample = ""
            if paths_through:
                sample_p = paths_through[0].get("path", [])
                labels = [g.nodes[x].get("label", x) for x in sample_p if x in g]
                if labels:
                    path_sample = " → ".join(labels[:4])
                    if len(labels) > 4:
                        path_sample += f" → ... → {labels[-1]}"

            if path_sample:
                root_cause = f"Taint origin propagates along attack corridor: {path_sample}. Reaches downstream sink(s) vulnerable to {cwe_list_str}."
            else:
                sink_names = ", ".join(f"{s['label']}" for s in downstream_sinks[:3])
                root_cause = f"Taint flows from this input into downstream sink(s): {sink_names}. Threat exposure includes {cwe_list_str}."

            fix = f"Validate and sanitize all data received from '{label}' at this entry point before propagation. Enforce strict boundaries for downstream {primary_cwe} sinks."
            cwes = sink_cwes
        else:
            # Check if source or its outgoing variable names indicate target vulnerability class
            target_cwes = []
            try:
                for succ in g.successors(node_id):
                    succ_label = (g.nodes[succ].get("label") or succ).lower()
                    if any(k in succ_label for k in ("database", "db", "sql", "query")):
                        target_cwes.append(("CWE-89", "SQL Injection (Database Configuration)"))
                    elif any(k in succ_label for k in ("cmd", "command", "shell", "exec")):
                        target_cwes.append(("CWE-78", "OS Command Injection"))
                    elif any(k in succ_label for k in ("path", "file", "filename", "dir")):
                        target_cwes.append(("CWE-22", "Path Traversal / Unsafe File Access"))
                    elif any(k in succ_label for k in ("url", "host", "endpoint")):
                        target_cwes.append(("CWE-918", "Server-Side Request Forgery (SSRF)"))
            except Exception:
                pass

            if target_cwes:
                primary_cwe, primary_name = target_cwes[0]
                severity = CWE_CATALOG.get(primary_cwe, {}).get("severity", "HIGH")
                what_it_does = f"External input origin '{label}' at {fname}:{line}. Introduces external environment data into {primary_name.lower()} operations."
                root_cause = f"Taint flows from this source into downstream variable(s) configuring {primary_name}."
                fix = f"Validate and strictly sanitize all values received from '{label}' before propagation into {primary_cwe} sinks."
                cwes = [{"cwe": primary_cwe, "name": primary_name, "role": "source", "severity": severity}]
            else:
                primary_cwe = ""
                primary_name = "External Input Origin (Unlinked)"
                severity = "LOW"
                what_it_does = f"External input origin '{label}' at {fname}:{line}. Introduces external environment data into the runtime."
                root_cause = "Entry source detected. Currently no complete taint path reaches a classified execution sink in this module."
                fix = f"Ensure strict schema validation and type constraints on data returned by '{label}'."
                cwes = []

    # SANITIZER / GUARD NODE
    elif node_type in ("sanitizer", "guard"):
        sink_cwes = []
        seen_cwes = set()
        for s in downstream_sinks:
            sid = s["id"]
            sdata = g.nodes.get(sid, {})
            scwe, sname = infer_node_cwe(sdata)
            if scwe and scwe not in seen_cwes:
                seen_cwes.add(scwe)
                sink_cwes.append({
                    "cwe": scwe,
                    "name": sname,
                    "sink": s.get("label", sid),
                    "role": "protected_sink",
                    "severity": CWE_CATALOG.get(scwe, {}).get("severity", "HIGH")
                })

        if sink_cwes:
            primary_cwe = sink_cwes[0]["cwe"]
            primary_name = sink_cwes[0]["name"]
            cwe_list_str = ", ".join(f"{c['cwe']} ({c['name']})" for c in sink_cwes)
            what_it_does = f"Security guard / sanitizer '{label}' at {fname}:{line}. Mitigates taint flow toward downstream execution sinks."
            root_cause = f"Positioned along taint corridor protecting against {cwe_list_str}."
            fix = f"Verify that validation logic in '{label}' comprehensively covers all canonicalization, encoding, and delimiter bypasses for {primary_cwe}."
            cwes = sink_cwes
            severity = "LOW"
        else:
            primary_cwe = ""
            primary_name = "Defensive Security Guard"
            what_it_does = f"Security guard / sanitizer routine '{label}' at {fname}:{line}."
            root_cause = "Sanitization point detected along execution path. No exposed attack corridor currently reaches unmitigated sinks."
            fix = "Ensure validation regex or checks reject non-conforming characters and edge cases."
            cwes = []
            severity = "LOW"

    # INTERMEDIATE / FUNCTION / NORMAL
    else:
        sink_cwes = []
        seen_cwes = set()
        for s in downstream_sinks:
            sid = s["id"]
            sdata = g.nodes.get(sid, {})
            scwe, sname = infer_node_cwe(sdata)
            if scwe and scwe not in seen_cwes:
                seen_cwes.add(scwe)
                sink_cwes.append({
                    "cwe": scwe,
                    "name": sname,
                    "sink": s.get("label", sid),
                    "role": "downstream_sink",
                    "severity": CWE_CATALOG.get(scwe, {}).get("severity", "MEDIUM")
                })

        if sink_cwes:
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            sink_cwes.sort(key=lambda x: sev_order.get(x["severity"], 99))
            primary_cwe = sink_cwes[0]["cwe"]
            primary_name = sink_cwes[0]["name"]
            severity = sink_cwes[0]["severity"]
            cwe_list_str = ", ".join(f"{c['cwe']} ({c['name']})" for c in sink_cwes)

            what_it_does = f"Intermediate data-flow node '{label}' at {fname}:{line}. Propagates tainted variables or calls between functions."

            path_sample = ""
            if paths_through:
                sample_p = paths_through[0].get("path", [])
                labels = [g.nodes[x].get("label", x) for x in sample_p if x in g]
                if labels:
                    path_sample = " → ".join(labels[:4])
                    if len(labels) > 4:
                        path_sample += f" → ... → {labels[-1]}"

            if path_sample:
                root_cause = f"Part of taint propagation path: {path_sample}. Propagates data toward {cwe_list_str}."
            else:
                root_cause = f"Transfers tainted state toward downstream sink(s) exposed to {cwe_list_str}."

            fix = f"Apply defensive input sanitization prior to this step or ensure valid sanitizers intervene before reaching downstream {primary_cwe} sinks."
            cwes = sink_cwes
        else:
            primary_cwe = ""
            primary_name = "Benign / No Direct Attack Path"
            severity = "LOW"
            what_it_does = f"Application execution node '{label}' at {fname}:{line}."
            root_cause = "Internal logic node without active attack corridor to a classified execution sink."
            fix = "No immediate vulnerability remediation required. Standard coding hygiene applies."
            cwes = []

    vuln_title = f"{primary_cwe}: {primary_name}" if primary_cwe else primary_name
    return {
        "cwe": primary_cwe or "",
        "cwe_name": primary_name,
        "vuln_type": vuln_title,
        "cwes": cwes,
        "what_it_does": what_it_does,
        "root_cause": root_cause,
        "fix": fix,
        "severity": severity,
        "role": node_type
    }


@router.get("/api/node/context")
def read_node_context(node_id: str):
    built = get_security_graph()
    g = built["graph"]
    target_id = None

    if node_id in g:
        target_id = node_id
    else:
        # Normalize slashes and attempt fuzzy node lookup
        norm_req = node_id.replace("\\", "/").strip()
        for n in g.nodes:
            norm_n = str(n).replace("\\", "/").strip()
            if norm_n == norm_req or norm_n.endswith(norm_req) or norm_req.endswith(norm_n):
                target_id = n
                break

    if not target_id:
        # Second attempt: match by label or file base
        for n, d in g.nodes(data=True):
            if d.get("label") == node_id or d.get("id") == node_id:
                target_id = n
                break

    if not target_id:
        raise HTTPException(status_code=404, detail=f"Node {node_id} not found")

    node_id = target_id
    node_data = dict(g.nodes[node_id])
    filepath = node_data.get("file")
    line = node_data.get("line", 1)
    context_code = ""

    if filepath and Path(filepath).exists():
        try:
            lines = Path(filepath).read_text(errors="replace").splitlines()
            start = max(0, line - 15)
            end = min(len(lines), line + 15)
            context_code = "\n".join(lines[start:end])
        except Exception:
            context_code = ""

    try:
        upstream_nodes = nx.ancestors(g, node_id)
        upstream_sources = [{"id": n, "label": g.nodes[n].get("label", n)} for n in upstream_nodes if g.nodes[n].get("type") == "source"]
    except Exception:
        upstream_sources = []

    try:
        downstream_nodes = nx.descendants(g, node_id)
        downstream_sinks = [{"id": n, "label": g.nodes[n].get("label", n), "risk": g.nodes[n].get("risk", "LOW")} for n in downstream_nodes if g.nodes[n].get("type") == "sink"]
    except Exception:
        downstream_sinks = []

    all_paths = compute_attack_paths(limit=500, max_depth=14)
    paths_through = [p for p in all_paths if node_id in p.get("path", [])]

    # Include any sinks identified at the end of matching attack paths
    seen_sink_ids = {s["id"] for s in downstream_sinks}
    for p in paths_through:
        p_nodes = p.get("path", [])
        if p_nodes:
            last_n = p_nodes[-1]
            if last_n in g and last_n not in seen_sink_ids:
                seen_sink_ids.add(last_n)
                downstream_sinks.append({
                    "id": last_n,
                    "label": g.nodes[last_n].get("label", last_n),
                    "risk": g.nodes[last_n].get("risk", "HIGH"),
                    "cwe": p.get("cwe")
                })

    blast_radius = node_data.get("blast_radius", {})
    if not isinstance(blast_radius, dict) and "files_in_commit" not in blast_radius:
        blist = node_data.get("blast_radius", [])
        if isinstance(blist, list):
            blast_radius = {
                "files_in_commit": blist,
                "count": len(blist),
                "description": f"Introduced in commit that touched {len(blist)} files"
            }
        else:
            blast_radius = {"files_in_commit": [], "count": 0, "description": "No git blame data"}

    analysis = build_node_analysis(node_id, node_data, g, upstream_sources, downstream_sinks, paths_through)

    return {
        "node_id": node_id,
        "type": node_data.get("type"),
        "file": filepath,
        "line": line,
        "context_code": context_code,
        "node": node_data,
        "upstream": {
            "sources": upstream_sources,
            "description": f"{len(upstream_sources)} inputs can taint this node"
        },
        "downstream": {
            "sinks": downstream_sinks,
            "description": f"This node can reach {len(downstream_sinks)} sinks"
        },
        "attack_paths_through": paths_through,
        "sanitizers_on_path": [],
        "blast_radius": blast_radius,
        "analysis": analysis
    }

@router.get("/api/node/patch-impact")
def read_patch_impact(node_id: str):
    built = get_security_graph()
    g = built["graph"]
    if node_id not in g:
        raise HTTPException(status_code=404, detail="Node not found")
        
    all_paths = compute_attack_paths(limit=500, max_depth=14)
    return compute_patch_impact(g, node_id, all_paths)


@router.get("/api/path")
def get_path(source: str, sink: str, max_depth: int = Query(20, ge=1, le=200), limit: int = Query(50, ge=1, le=500)):
    """
    Required endpoint: /api/path?source=...&sink=...
    Accepts either internal node ids or human labels like 'input()' / 'os.system()'.
    Returns paths as arrays of internal node ids (so the frontend can highlight).
    """
    built = get_security_graph()
    g = built["graph"]

    src_id = resolve_node_ref(source, node_type="source") or resolve_node_ref(source, node_type=None)
    sink_id = resolve_node_ref(sink, node_type="sink") or resolve_node_ref(sink, node_type=None)
    if not src_id or not sink_id:
        raise HTTPException(status_code=404, detail="Source or sink not found in graph")

    paths = []
    try:
        for p in nx.all_simple_paths(g, src_id, sink_id, cutoff=max_depth):
            paths.append(p)
            if len(paths) >= limit:
                break
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        pass

    return {"paths": paths}


@router.get("/api/debug/edges")
def debug_edges(limit: int = Query(500, ge=1, le=5000)):
    built = get_security_graph()
    g = built["graph"]
    edges = []
    for u, v, data in g.edges(data=True):
        edges.append({"source": u, "target": v, "type": data.get("type", ""), "reason": data.get("reason", "")})
        if len(edges) >= limit:
            break
    return {"edges": edges}


@router.get("/api/file/source")
def get_file_source(filepath: str = Query(...)):
    """
    Return the source code of a file that was scanned.
    Only serves files that exist on the server filesystem.
    """
    import tempfile
    from pathlib import Path
    from backend.services.git_history import _resolve_candidate_paths

    raw_path = (filepath or "").strip()
    if not raw_path:
        raise HTTPException(status_code=400, detail="filepath is required")

    # Find the actual file on disk
    target_file: Path | None = None

    # 1. Check direct resolution and candidate paths
    candidates = _resolve_candidate_paths(raw_path)
    for cand in candidates:
        if cand.exists() and cand.is_file():
            target_file = cand
            break

    # 2. Check under /tmp/vulngraph_uploads or tempdir
    if not target_file:
        norm = raw_path.replace("\\", "/")
        uploads_root = Path("/tmp/vulngraph_uploads").resolve()
        if "vulngraph_uploads/" in norm:
            sub = norm.split("vulngraph_uploads/", 1)[1]
            cand = uploads_root / sub
            if cand.exists() and cand.is_file():
                target_file = cand
            else:
                # Check for redundant duplicate subfolder e.g. timetable_management/timetable_management
                parts = [pt for pt in sub.split("/") if pt]
                if len(parts) > 1 and parts[0] == parts[1]:
                    cand_dedup = uploads_root / Path(*parts[1:])
                    if cand_dedup.exists() and cand_dedup.is_file():
                        target_file = cand_dedup
                if not target_file and len(parts) > 0:
                    cand_dup = uploads_root / parts[0] / sub
                    if cand_dup.exists() and cand_dup.is_file():
                        target_file = cand_dup

    # 3. Check filename match under uploads or CWD
    if not target_file:
        fname = Path(raw_path).name
        search_dirs = [
            Path("/tmp/vulngraph_uploads").resolve(),
            Path(tempfile.gettempdir()) / "vulngraph_uploads",
            Path.cwd(),
        ]
        for sdir in search_dirs:
            if sdir.exists():
                for match in sdir.rglob(fname):
                    if match.is_file():
                        target_file = match.resolve()
                        break
            if target_file:
                break

    if not target_file or not target_file.exists() or not target_file.is_file():
        raise HTTPException(status_code=404, detail=f"File not found: {raw_path}")

    # Security: check if file is within safe directories
    if not is_safe_file_path(target_file):
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        content = target_file.read_text(encoding='utf-8', errors='replace')
        lines = content.splitlines()
        return {
            "filepath": str(target_file),
            "content": content,
            "line_count": len(lines),
            "language": target_file.suffix.lstrip('.') or 'txt',
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

