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


def build_java_graph(project_path: str) -> nx.DiGraph:
    g = nx.DiGraph()
    root = Path(project_path).resolve()
    file_methods: dict[str, dict[str, str]] = {}
    parsed_by_file: dict[str, dict[str, list[dict[str, Any]]]] = {}

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            if not filename.endswith(".java"):
                continue
            filepath = str((Path(dirpath) / filename).resolve())
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
                    g.add_node(
                        nid,
                        id=nid,
                        type=node_type,
                        file=filepath,
                        line=line,
                        label=f"{name}()",
                        risk_score=RISK_SCORES.get(node_type, 1.0),
                        risk="high" if node_type == "sink" else "low",
                        patched=False,
                    )

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
