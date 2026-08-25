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

def build_symbol_table(project_path: str) -> dict[str, str]:
    """
    Scans all .java files in project_path and builds a global map of:
    {method_name: node_id, ClassName.methodName: node_id}
    
    This allows cross-file call resolution — when file A calls 
    userService.save(), we can find the node id of UserService.save()
    in another file and add the edge.
    
    Returns: {symbol: node_id} where symbol is:
      - "ClassName.methodName" (preferred, unambiguous)
      - "methodName" (fallback, may have collisions)
    """
    symbol_table = {}
    java_files = list(Path(project_path).rglob("*.java"))
    
    for jf in java_files:
        try:
            source = jf.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        
        # Extract class name from file
        class_match = re.search(
            r'\b(?:public\s+)?(?:class|interface|enum)\s+(\w+)', source
        )
        class_name = class_match.group(1) if class_match else jf.stem
        
        # Extract all method definitions
        method_pattern = re.compile(
            r'(?:public|protected|private|static|\s)+[\w<>\[\]]+\s+'
            r'(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{',
            re.MULTILINE
        )
        for m in method_pattern.finditer(source):
            method_name = m.group(1)
            if method_name in ('if', 'for', 'while', 'switch', 'catch'):
                continue
            
            # Determine node type for this method
            node_type = _classify_java_method(method_name, source, 
                                               m.start(), class_name)
            
            # Build node_id same format as build_java_graph uses
            line_no = source[:m.start()].count('\n') + 1
            node_id = _node_id(str(jf), line_no, node_type, method_name, root=project_path)
            
            # Register under multiple lookup keys
            symbol_table[f"{class_name}.{method_name}"] = node_id
            symbol_table[method_name] = node_id  # fallback
            
    return symbol_table


def _classify_java_method(method_name: str, source: str, 
                           pos: int, class_name: str) -> str:
    """Classify a method as source/sink/sanitizer/normal."""
    # Check annotations on the 3 lines before the method
    before = source[max(0, pos-300):pos]
    
    ENTRY_ANNOTATIONS = {'@RequestMapping','@GetMapping','@PostMapping',
                         '@PutMapping','@DeleteMapping','@PatchMapping',
                         '@MessageMapping','@KafkaListener','@RabbitListener'}
    SINK_PATTERNS = {'execute','executeQuery','executeUpdate','exec',
                     'invoke','write','send','publish','serialize',
                     'createQuery','nativeQuery'}
    GUARD_ANNOTATIONS = {'@Valid','@Validated','@NotNull','@NotBlank',
                         '@Pattern','@Size','@Min','@Max'}
    GUARD_NAMES = {'validate','sanitize','check','verify','escape',
                   'filter','authorize','authenticate','isValid','hasPermission'}
    
    if any(ann in before for ann in ENTRY_ANNOTATIONS):
        return 'source'
    if any(ann in before for ann in GUARD_ANNOTATIONS):
        return 'sanitizer'
    if any(method_name.lower().startswith(g) for g in GUARD_NAMES):
        return 'sanitizer'
    if any(s in method_name.lower() for s in SINK_PATTERNS):
        return 'sink'
    return 'normal'




def build_java_graph(project_path: str) -> nx.DiGraph:
    g = nx.DiGraph()
    root = Path(project_path).resolve()
    java_files = list(Path(project_path).rglob("*.java"))
    if not java_files:
        return g
    
    # === PHASE 1: Build global symbol table ===
    symbol_table = build_symbol_table(project_path)
    
    file_methods: dict[str, dict[str, str]] = {}
    parsed_by_file: dict[str, dict[str, list[dict[str, Any]]]] = {}

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            if not filename.endswith(".java"):
                continue
            filepath = str((Path(dirpath) / filename).resolve())
            
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
            
            # Try to resolve the called method across all files
            # Try "ClassName.method" first (check known class names)
            target_node = None
            
            # Strategy 1: direct name match (e.g. save -> UserRepository.save)
            if called_method in symbol_table:
                target_node = symbol_table[called_method]
            
            # Strategy 2: look for ClassName.method where ClassName 
            # matches the variable type (from field declarations)
            # e.g. "private UserService userService" -> UserService.save
            field_pattern = re.compile(
                rf'(\w+)\s+{re.escape(obj_name)}\s*[;=,)]'
            )
            field_match = field_pattern.search(source)
            if field_match:
                inferred_class = field_match.group(1)
                key = f"{inferred_class}.{called_method}"
                if key in symbol_table:
                    target_node = symbol_table[key]
            
            # Add cross-file edge if resolved and not self-loop
            if target_node and target_node != caller_node:
                if not g.has_edge(caller_node, target_node):
                    g.add_edge(caller_node, target_node, 
                               type='cross_file_call',
                               reason='calls',
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


def analyze_java_codebase(project_path: str) -> dict[str, Any]:
    import backend.services.code_security_graph as csg

    g = build_java_graph(project_path)
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
