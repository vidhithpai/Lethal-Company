from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import networkx as nx

from backend.services.java_parser_bridge import parse_java_file, _collect_method_body

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build", "target"}

TYPE_MAP = {
    "entry": "source",
    "sink": "sink",
    "guard": "sanitizer",
    "normal": "normal",
}

RISK_SCORES = {
    "source": 2.0,
    "sink": 9.0,
    "sanitizer": 3.0,
    "normal": 1.0,
}


def _rel_path_str(filepath: str, root: Path | str | None = None) -> str:
    p = Path(filepath)
    if root:
        try:
            p = p.relative_to(Path(root))
        except ValueError:
            pass
    return str(p).replace("\\", "/")


def _node_id(filepath: str, line: int, node_type: str, name: str, root: Path | str | None = None) -> str:
    rel = _rel_path_str(filepath, root)
    return f"{rel}::{name}"


def _read_file_methods(filepath: str) -> dict[str, str]:
    try:
        content = Path(filepath).read_text(encoding="utf-8")
    except OSError:
        return {}

    methods: dict[str, str] = {}
    lines = content.splitlines()
    i = 0

    while i < len(lines):
        line = lines[i]
        match = re.match(
            r"^\s*(?:(?:public|private|protected|static|final)\s+)*"
            r"[\w<>\[\],\s.?]+\s+(\w+)\s*\(",
            line,
        )
        if match and ";" not in line.split("//")[0]:
            name = match.group(1)
            if name in {"if", "for", "while", "switch", "catch", "return", "new", "throw"}:
                i += 1
                continue

            body, next_i = _collect_method_body(lines, i)
            methods[name] = body
            i = next_i
            continue
        i += 1

    return methods

def build_symbol_table(project_path: str) -> dict:
    """
    Builds a scope-aware symbol table.
    Returns {
      "by_class": {"ClassName.methodName": node_id, ...},
      "by_name":  {"methodName": [node_id, ...], ...},  # list — may be ambiguous
      "class_files": {"ClassName": filepath, ...}        # for receiver typing
    }
    """
    by_class: dict[str, str] = {}
    by_name:  dict[str, list] = {}
    class_files: dict[str, str] = {}

    java_files = list(Path(project_path).rglob("*.java"))
    for jf in java_files:
        try:
            source = jf.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        class_match = re.search(
            r'\b(?:public\s+)?(?:class|interface|enum)\s+(\w+)', source
        )
        class_name = class_match.group(1) if class_match else jf.stem
        class_files[class_name] = str(jf)

        method_pattern = re.compile(
            r'(?:public|protected|private|static|\s)+[\w<>\[\]]+\s+'
            r'(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{',
            re.MULTILINE
        )
        for m in method_pattern.finditer(source):
            method_name = m.group(1)
            if method_name in ('if','for','while','switch','catch','try',
                               'else','new','return','class','interface'):
                continue

            line_no = source[:m.start()].count('\n') + 1
            node_type = _classify_java_method_type(method_name, source,
                                                    m.start(), class_name)
            node_id = f"{jf.name}:{line_no}:{node_type}:{method_name}"

            # Unambiguous: ClassName.methodName
            full_key = f"{class_name}.{method_name}"
            by_class[full_key] = node_id

            # Potentially ambiguous: methodName alone
            if method_name not in by_name:
                by_name[method_name] = []
            by_name[method_name].append(node_id)

    return {"by_class": by_class, "by_name": by_name, "class_files": class_files}


def _classify_java_method_type(method_name: str, source: str,
                                pos: int, class_name: str) -> str:
    """Classify a Java method into TDRA node type."""
    before = source[max(0, pos - 400): pos]
    ENTRY_ANN = {'@RequestMapping','@GetMapping','@PostMapping','@PutMapping',
                 '@DeleteMapping','@PatchMapping','@KafkaListener',
                 '@RabbitListener','@MessageMapping'}
    SINK_PAT  = {'execute','executequery','executeupdate','exec','invoke',
                 'write','send','serialize','forname','getwriter'}
    GUARD_ANN = {'@Valid','@Validated','@NotNull','@NotBlank','@Pattern',
                 '@Size','@PreAuthorize','@Secured','@RolesAllowed'}
    GUARD_NAM = {'validate','sanitize','check','escape','filter',
                 'authorize','authenticate','ispermitted','hasrole',
                 'canonicalize','allowlist'}

    if any(a in before for a in ENTRY_ANN): return 'source'
    if any(a in before for a in GUARD_ANN): return 'sanitizer'
    mn_lower = method_name.lower()
    if any(mn_lower.startswith(g) for g in GUARD_NAM): return 'sanitizer'
    if any(s in mn_lower for s in SINK_PAT): return 'sink'
    return 'normal'


from backend.services.graph_manifest import (
    load_manifest, save_manifest, get_changed_files,
    update_manifest_after_scan, MANIFEST_FILENAME
)

# Add cached graph store at module level
_graph_cache: dict[str, nx.DiGraph] = {}  # project_path -> graph


def build_java_graph(project_path: str, 
                     incremental: bool = True,
                     progress_callback=None) -> nx.DiGraph:
    """
    Build (or incrementally update) the program graph for a Java project.
    Uses manifest.json to detect and skip unchanged files.
    """
    if not incremental:
        return _build_java_graph_full(project_path, progress_callback=progress_callback)
    
    manifest = load_manifest(project_path)
    changed  = get_changed_files(project_path, manifest)
    
    total_changed = len(changed["new"]) + len(changed["changed"])
    
    # Full scan: no cached graph or >30% of files changed
    total_files = total_changed + len(changed["unchanged"])
    if (project_path not in _graph_cache 
            or total_files == 0
            or total_changed / max(total_files, 1) > 0.30):
        G = _build_java_graph_full(project_path, progress_callback=progress_callback)
        _graph_cache[project_path] = G
        manifest = update_manifest_after_scan(manifest, changed)
        save_manifest(project_path, manifest, G)
        return G
    
    # Incremental: rebuild only changed files, merge into cached graph
    G = _graph_cache[project_path].copy()
    
    # Remove nodes from deleted/changed files
    files_to_remove = set(changed["deleted"] + changed["changed"])
    nodes_to_remove = [n for n, d in G.nodes(data=True)
                       if d.get("file", "") in files_to_remove]
    G.remove_nodes_from(nodes_to_remove)
    
    # Analyze new/changed files only
    files_to_analyze = changed["new"] + changed["changed"]
    if files_to_analyze:
        # Build partial graph for only the changed files
        partial_tmp = _build_java_graph_for_files(
            files_to_analyze, project_path, progress_callback=progress_callback
        )
        # Merge partial graph into main graph
        G = nx.compose(G, partial_tmp)
    
    _graph_cache[project_path] = G
    manifest = update_manifest_after_scan(manifest, changed)
    save_manifest(project_path, manifest, G)
    
    return G


import time

_last_java_builder_timings = {
    "file_discovery": 0.0,
    "symbol_table": 0.0,
    "file_parsing": 0.0,
    "edge_resolution": 0.0,
    "discovered_files_count": 0,
}

def get_last_java_timings() -> dict:
    return dict(_last_java_builder_timings)


def _build_java_graph_full(project_path: str, progress_callback=None) -> nx.DiGraph:
    global _last_java_builder_timings
    g = nx.DiGraph()
    root = Path(project_path).resolve()
    
    t0 = time.perf_counter()
    java_files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            if filename.endswith(".java"):
                java_files.append(str((Path(dirpath) / filename).resolve()))
    _last_java_builder_timings["file_discovery"] = time.perf_counter() - t0
    _last_java_builder_timings["discovered_files_count"] = len(java_files)

    if not java_files:
        return g

    total_files = len(java_files)
    if progress_callback:
        progress_callback(0, total_files, "")
    
    # === PHASE 1: Build global symbol table ===
    t0 = time.perf_counter()
    sym = build_symbol_table(project_path)
    _last_java_builder_timings["symbol_table"] = time.perf_counter() - t0
    by_class   = sym["by_class"]
    by_name    = sym["by_name"]
    class_files = sym["class_files"]
    
    file_methods: dict[str, dict[str, str]] = {}
    parsed_by_file: dict[str, dict[str, list[dict[str, Any]]]] = {}

    t0 = time.perf_counter()
    for idx, filepath in enumerate(java_files):
        try:
            source_text = Path(filepath).read_text(encoding="utf-8", errors="replace")
        except Exception:
            source_text = ""

        parsed = parse_java_file(filepath)
        parsed_by_file[filepath] = parsed
        file_methods[filepath] = _read_file_methods(filepath)

        for category, items in parsed.items():
            node_type = TYPE_MAP[category]
            node_type = str(node_type).lower()
            for item in items:
                name = item["name"]
                line = int(item["line"])
                nid = _node_id(filepath, line, node_type, name, root=root)
                if nid in g:
                    continue
                attrs = {
                    "id": nid,
                    "type": node_type,
                    "file": filepath,
                    "line": line,
                    "label": f"{name}()",
                    "risk_score": RISK_SCORES.get(node_type, 1.0),
                    "risk": "high" if node_type == "sink" else "low",
                    "patched": False,
                }
                if node_type == "sink":
                    attrs["cwe"] = item.get("cwe")
                    attrs["cwe_name"] = item.get("cwe_name")
                    attrs["sink_kind"] = item.get("sink_kind")
                    attrs["severity"] = item.get("severity", 8.0)
                    attrs["taint_confirmed"] = False  # Static regex match in Java pipeline

                if node_type in ("sanitizer", "guard"):
                    lines = source_text.splitlines()
                    start_idx = max(0, line - 6)
                    before_text = "\n".join(lines[start_idx:line])
                    GUARD_ANNOTATIONS = {"@Valid","@Validated","@NotNull","@NotBlank",
                                         "@Pattern","@Size","@Min","@Max","@Positive",
                                         "@PreAuthorize","@Secured","@RolesAllowed"}
                    detected_annotations = [a for a in GUARD_ANNOTATIONS if a in before_text]
                    has_annotation = len(detected_annotations) > 0
                    attrs["guard_basis"] = "annotation" if has_annotation else "name"
                    attrs["annotations"] = detected_annotations

                g.add_node(nid, **attrs)

        if progress_callback:
            progress_callback(idx + 1, total_files, Path(filepath).name)

    _last_java_builder_timings["file_parsing"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    for filepath, methods in file_methods.items():
        method_names = list(methods.keys())
        for caller, body in methods.items():
            caller_nodes = [
                nid for nid, data in g.nodes(data=True)
                if data.get("file") == filepath and data.get("label") == f"{caller}()"
            ]
            if not caller_nodes:
                continue
            caller_id = caller_nodes[0]

            for callee in method_names:
                if callee == caller:
                    continue
                if re.search(rf"\b{re.escape(callee)}\s*\(", body):
                    callee_nodes = [
                        nid for nid, data in g.nodes(data=True)
                        if data.get("file") == filepath and data.get("label") == f"{callee}()"
                    ]
                    for callee_id in callee_nodes:
                        if not g.has_edge(caller_id, callee_id):
                            g.add_edge(
                                caller_id,
                                callee_id,
                                type="call",
                                reason="calls",
                                weight=1.0,
                            )

    # === PHASE 3: Add cross-file edges ===
    # For each node in the graph, scan its source file for 
    # method calls and resolve them against the symbol table
    
    for jf in java_files:
        try:
            source = jf.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        
        # Find all method calls: patterns like  
        # variableName.methodName( or ClassName.methodName(
        call_pattern = re.compile(r'(\w+)\.(\w+)\s*\(')
        
        # Find which nodes belong to this file
        file_nodes = [n for n in g.nodes() 
                      if g.nodes[n].get('file','').endswith(jf.name)]
        
        for match in call_pattern.finditer(source):
            obj_name = match.group(1)      # e.g. "userService"
            called_method = match.group(2)  # e.g. "save"
            call_line = source[:match.start()].count('\n') + 1
            
            # Find the caller node (the method that contains this call)
            caller_node = None
            best_line_dist = float('inf')
            for fn in file_nodes:
                node_line = g.nodes[fn].get('line', 0)
                if node_line <= call_line:
                    dist = call_line - node_line
                    if dist < best_line_dist:
                        best_line_dist = dist
                        caller_node = fn
            
            if caller_node is None:
                continue
            
            target_node = None
            confidence = "INFERRED"

            # Step 1 — try receiver type inference (most precise, GitNexus pattern)
            field_pattern = re.compile(
                rf'(\w+)\s+{re.escape(obj_name)}\s*[;=,)\n]'
            )
            field_match = field_pattern.search(source)
            if field_match:
                inferred_class = field_match.group(1)
                full_key = f"{inferred_class}.{called_method}"
                if full_key in by_class:
                    target_node = by_class[full_key]
                    confidence = "EXTRACTED"  # receiver type found in source

            # Step 2 — fall back to unambiguous name match
            if target_node is None and called_method in by_name:
                candidates = by_name[called_method]
                if len(candidates) == 1:
                    target_node = candidates[0]
                    confidence = "INFERRED"   # name matched, class not confirmed
                else:
                    # Ambiguous — multiple classes have this method name
                    # Pick the one whose file is most similar to current file
                    target_node = candidates[0]  # best guess
                    confidence = "AMBIGUOUS"

            if target_node and target_node != caller_node:
                if not g.has_edge(caller_node, target_node):
                    g.add_edge(caller_node, target_node,
                               type='cross_file_call',
                               edge_type='cross_file_call',
                               confidence=confidence,
                               call_line=call_line)

    _last_java_builder_timings["edge_resolution"] = time.perf_counter() - t0
    return g


def _build_java_graph_for_files(files: list[str], 
                                 project_path: str) -> nx.DiGraph:
    g = nx.DiGraph()
    root = Path(project_path).resolve()
    target_files = {str(Path(f).resolve()) for f in files}
    if not target_files:
        return g

    sym = build_symbol_table(project_path)
    by_class   = sym["by_class"]
    by_name    = sym["by_name"]

    file_methods: dict[str, dict[str, str]] = {}
    parsed_by_file: dict[str, dict[str, list[dict[str, Any]]]] = {}

    for filepath in target_files:
        if not Path(filepath).exists():
            continue
        try:
            source_text = Path(filepath).read_text(encoding="utf-8", errors="replace")
        except Exception:
            source_text = ""

        parsed = parse_java_file(filepath)
        parsed_by_file[filepath] = parsed
        file_methods[filepath] = _read_file_methods(filepath)

        for category, items in parsed.items():
            node_type = TYPE_MAP[category]
            node_type = str(node_type).lower()
            for item in items:
                name = item["name"]
                line = int(item["line"])
                nid = _node_id(filepath, line, node_type, name, root=root)
                if nid in g:
                    continue
                attrs = {
                    "id": nid,
                    "type": node_type,
                    "file": filepath,
                    "line": line,
                    "label": f"{name}()",
                    "risk_score": RISK_SCORES.get(node_type, 1.0),
                    "risk": "high" if node_type == "sink" else "low",
                    "patched": False,
                }
                if node_type == "sink":
                    attrs["cwe"] = item.get("cwe")
                    attrs["cwe_name"] = item.get("cwe_name")
                    attrs["sink_kind"] = item.get("sink_kind")
                    attrs["severity"] = item.get("severity", 8.0)
                    attrs["taint_confirmed"] = False

                if node_type in ("sanitizer", "guard"):
                    lines = source_text.splitlines()
                    start_idx = max(0, line - 6)
                    before_text = "\n".join(lines[start_idx:line])
                    GUARD_ANNOTATIONS = {"@Valid","@Validated","@NotNull","@NotBlank",
                                         "@Pattern","@Size","@Min","@Max","@Positive",
                                         "@PreAuthorize","@Secured","@RolesAllowed"}
                    detected_annotations = [a for a in GUARD_ANNOTATIONS if a in before_text]
                    has_annotation = len(detected_annotations) > 0
                    attrs["guard_basis"] = "annotation" if has_annotation else "name"
                    attrs["annotations"] = detected_annotations

                g.add_node(nid, **attrs)

    for filepath, methods in file_methods.items():
        method_names = list(methods.keys())
        for caller, body in methods.items():
            caller_nodes = [
                nid for nid, data in g.nodes(data=True)
                if data.get("file") == filepath and data.get("label") == f"{caller}()"
            ]
            if not caller_nodes:
                continue
            caller_id = caller_nodes[0]

            for callee in method_names:
                if callee == caller:
                    continue
                if re.search(rf"\b{re.escape(callee)}\s*\(", body):
                    callee_nodes = [
                        nid for nid, data in g.nodes(data=True)
                        if data.get("file") == filepath and data.get("label") == f"{callee}()"
                    ]
                    for callee_id in callee_nodes:
                        if not g.has_edge(caller_id, callee_id):
                            g.add_edge(
                                caller_id,
                                callee_id,
                                type="call",
                                reason="calls",
                                weight=1.0,
                            )

    for filepath in target_files:
        jf = Path(filepath)
        if not jf.exists():
            continue
        try:
            source = jf.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        call_pattern = re.compile(r'(\w+)\.(\w+)\s*\(')
        file_nodes = [n for n in g.nodes() 
                      if g.nodes[n].get('file','').endswith(jf.name)]

        for match in call_pattern.finditer(source):
            obj_name = match.group(1)
            called_method = match.group(2)
            call_line = source[:match.start()].count('\n') + 1

            caller_node = None
            best_line_dist = float('inf')
            for fn in file_nodes:
                node_line = g.nodes[fn].get('line', 0)
                if node_line <= call_line:
                    dist = call_line - node_line
                    if dist < best_line_dist:
                        best_line_dist = dist
                        caller_node = fn

            if caller_node is None:
                continue

            target_node = None
            confidence = "INFERRED"

            field_pattern = re.compile(
                rf'(\w+)\s+{re.escape(obj_name)}\s*[;=,)\n]'
            )
            field_match = field_pattern.search(source)
            if field_match:
                inferred_class = field_match.group(1)
                full_key = f"{inferred_class}.{called_method}"
                if full_key in by_class:
                    target_node = by_class[full_key]
                    confidence = "EXTRACTED"

            if target_node is None and called_method in by_name:
                candidates = by_name[called_method]
                if len(candidates) == 1:
                    target_node = candidates[0]
                    confidence = "INFERRED"
                else:
                    target_node = candidates[0]
                    confidence = "AMBIGUOUS"

            if target_node and target_node != caller_node:
                if not g.has_edge(caller_node, target_node):
                    g.add_edge(caller_node, target_node,
                               type='cross_file_call',
                               edge_type='cross_file_call',
                               confidence=confidence,
                               call_line=call_line)

    return g


def java_graph_to_built(g: nx.DiGraph) -> dict[str, Any]:
    nodes = [dict(data) for _, data in g.nodes(data=True)]
    edges = []
    sources: list[str] = []
    sinks: list[str] = []
    sanitizers: list[str] = []

    for u, v, data in g.edges(data=True):
        edges.append({
            "source": u,
            "target": v,
            "type": data.get("type", "call"),
            "reason": data.get("reason", "calls"),
            "weight": float(data.get("weight", 1.0)),
            "confidence": 0.85,
            "on_attack_path": False,
        })

    for nid, data in g.nodes(data=True):
        node_type = data.get("type")
        if node_type == "source":
            sources.append(nid)
        elif node_type == "sink":
            sinks.append(nid)
        elif node_type == "sanitizer":
            sanitizers.append(nid)

    return {
        "graph": g,
        "nodes": nodes,
        "edges": edges,
        "sources": sources,
        "sinks": sinks,
        "sanitizers": sanitizers,
    }


def store_java_graph(project_path: str, built: dict[str, Any]) -> None:
    import backend.services.code_security_graph as csg

    p = str(Path(project_path).resolve())
    with csg._lock:
        csg._ROOT_OVERRIDE = Path(project_path).resolve()
        csg._cache["graph"] = built
        csg._cache["root"] = p
        csg._security_graph = built["graph"]


def detect_project_language(project_path: str) -> str:
    root = Path(project_path).resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            if filename.endswith(".java"):
                return "java"
    return "python"


def analyze_java_codebase(project_path: str, progress_callback=None) -> dict[str, Any]:
    import backend.services.code_security_graph as csg

    g = build_java_graph(project_path, progress_callback=progress_callback)
    built = java_graph_to_built(g)
    store_java_graph(project_path, built)

    node_list_data = [dict(data, id=n) for n, data in g.nodes(data=True)]
    attack_paths = csg.compute_high_risk_paths(limit=10)
    csg._current_graph = {
        "nodes": node_list_data,
        "links": built["edges"],
        "meta": {"scanned_project": Path(project_path).name, "language": "java"},
    }
    csg._current_paths = attack_paths
    csg._current_high_risk = attack_paths
    return built
