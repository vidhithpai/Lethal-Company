from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Iterable

import networkx as nx


@dataclass(frozen=True)
class SecurityGraphConfig:
    root_dir: Path
    max_files: int = 5000


_lock = RLock()
_cache: dict[str, Any] = {"graph": None, "root": None}
_security_graph: nx.DiGraph | None = None

COMMUNITY_COLORS = {
    "authentication_surface": "#F59E0B",   # amber
    "data_input_surface":     "#10B981",   # green
    "persistence_layer":      "#EF4444",   # red
    "execution_surface":      "#DC2626",   # dark red
    "sanitization_zone":      "#6366F1",   # indigo
    "application_logic":      "#6B7280",   # gray
}

def compute_edge_confidence(edge_type: str, source_type: str, target_type: str,
                             has_direct_assignment: bool, cross_function: bool) -> float:
    base = 1.0
    if has_direct_assignment and not cross_function:
        base = 0.95
    elif not cross_function:
        base = 0.85
    elif cross_function:
        base = 0.65

    sink_multipliers = {
        "sql_execution": 1.0,
        "cmd_execution": 1.0,
        "file_write": 0.9,
        "deserialization": 0.95,
        "eval_exec": 1.0,
    }
    base *= sink_multipliers.get(target_type, 0.8)

    source_multipliers = {
        "http_input": 1.0,
        "env_input": 0.85,
        "file_input": 0.80,
        "cli_input": 0.75,
    }
    base *= source_multipliers.get(source_type, 0.8)
    return round(min(base, 1.0), 2)

def detect_security_communities(G: nx.DiGraph) -> dict[str, str]:
    communities = {}
    for node_id, attrs in G.nodes(data=True):
        label = attrs.get("label", "").lower()
        node_type = attrs.get("type", "")
        sink_kind = attrs.get("sink_kind", "")
        source_kind = attrs.get("source_kind", "")

        if "auth" in label or "login" in label or "password" in label or "token" in label:
            communities[node_id] = "authentication_surface"
        elif node_type == "source" and source_kind in ("http_input", "form_input"):
            communities[node_id] = "data_input_surface"
        elif sink_kind in ("sql_execution",):
            communities[node_id] = "persistence_layer"
        elif sink_kind in ("cmd_execution", "eval_exec"):
            communities[node_id] = "execution_surface"
        elif node_type == "sanitizer":
            communities[node_id] = "sanitization_zone"
        elif node_type == "source":
            communities[node_id] = "data_input_surface"
        else:
            communities[node_id] = "application_logic"
    return communities

def compute_patch_impact(G: nx.DiGraph, node_id: str, all_paths: list[dict]) -> dict:
    eliminated = []
    mitigated = []
    unaffected = []
    for path_info in all_paths:
        path_nodes = path_info.get("path", [])
        if node_id in path_nodes:
            if path_nodes[0] == node_id or path_nodes[-1] == node_id:
                eliminated.append(path_info)
            else:
                mitigated.append(path_info)
        else:
            unaffected.append(path_info)

    high_risk_eliminated = [p for p in eliminated if p.get("classification") == "HIGH" or p.get("risk") == "HIGH"]

    return {
        "node_id": node_id,
        "patch_impact": {
            "eliminated_paths": len(eliminated),
            "mitigated_paths": len(mitigated),
            "unaffected_paths": len(unaffected),
            "high_risk_eliminated": len(high_risk_eliminated),
            "impact_score": round((len(eliminated) * 2 + len(mitigated)) / max(len(all_paths), 1) * 10, 1),
            "recommendation": _patch_recommendation(len(eliminated), len(high_risk_eliminated), len(all_paths))
        }
    }

def _patch_recommendation(eliminated: int, high_risk: int, total: int) -> str:
    if high_risk > 0:
        return f"CRITICAL FIX — eliminates {high_risk} HIGH-risk path(s)"
    elif eliminated > total * 0.5:
        return f"HIGH PRIORITY — eliminates {eliminated}/{total} attack paths"
    elif eliminated > 0:
        return f"MEDIUM PRIORITY — eliminates {eliminated} path(s)"
    else:
        return "LOW PRIORITY — patching this node has limited impact"

PATCHED_SECURITY_NODES: dict[str, bool] = {}
PATCHED_NODES = PATCHED_SECURITY_NODES
_ROOT_OVERRIDE: Path | None = None

_current_graph = {"nodes": [], "links": [], "meta": {}}
_current_paths = []
_current_high_risk = []

def get_current_graph(): return _current_graph
def get_current_attack_paths(): return _current_paths
def get_current_high_risk_paths(): return _current_high_risk


def invalidate_security_graph_cache() -> None:
    global _security_graph
    with _lock:
        _cache["graph"] = None
        _cache["root"] = None
        _security_graph = None


def use_mock_graph() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    PATCHED_SECURITY_NODES.clear()
    set_security_root(repo_root / "sample_project" / "src")
    invalidate_security_graph_cache()
    get_security_graph()


def patch_security_node(node_id: str) -> bool:
    PATCHED_SECURITY_NODES[node_id] = True
    invalidate_security_graph_cache()
    return True


def set_security_root(root: Path | None) -> None:
    global _ROOT_OVERRIDE
    _ROOT_OVERRIDE = root
    invalidate_security_graph_cache()


def get_security_root() -> Path | None:
    return _ROOT_OVERRIDE


def get_current_graph_nodes() -> list[dict]:
    """Return all nodes from the last built graph as list of dicts."""
    with _lock:
        if _cache["graph"] is not None:
            return list(_cache["graph"]["nodes"])
    return []


def _iter_python_files(root: Path, *, max_files: int) -> Iterable[Path]:
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}
        ]
        for name in filenames:
            if not name.endswith(".py"):
                continue
            count += 1
            if count > max_files:
                return
            yield Path(dirpath) / name


def _qualname(expr: ast.AST) -> str | None:
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        base = _qualname(expr.value)
        if base:
            return f"{base}.{expr.attr}"
    return None


def _is_write_mode_call(call: ast.Call) -> bool:
    if not isinstance(call.func, ast.Name) or call.func.id != "open":
        return False
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant) and isinstance(call.args[1].value, str):
        return "w" in call.args[1].value or "a" in call.args[1].value
    for kw in call.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return "w" in kw.value.value or "a" in kw.value.value
    return False


_REQUEST_ATTR_SOURCES = {
    "request.args", "request.form", "request.json", "request.data",
    "request.headers", "request.cookies", "request.files",
    "request.values", "request.get_json",
}
_FASTAPI_SOURCES = {"Body", "Query", "Path", "Form", "Header", "Cookie", "File"}
_OS_SYS_SOURCES = {"os.environ", "os.getenv", "sys.argv"}
_SANITIZER_KEYWORDS = {
    "sanitize", "escape", "encode", "clean", "validate",
    "parameterize", "quote", "bleach", "html_escape", "urlencode", "safe",
}


def _is_source_expr(node: ast.AST) -> tuple[bool, str]:
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id == "input":
            return True, "input()"
        if node.func.id in _FASTAPI_SOURCES:
            return True, f"{node.func.id}()"

    if isinstance(node, ast.Subscript):
        qn = _qualname(node.value)
        if qn in {"os.environ"}:
            return True, "os.environ[...]"

    qn = _qualname(node)
    if qn in _OS_SYS_SOURCES:
        return True, qn

    if isinstance(node, ast.Attribute):
        full = _qualname(node)
        if full in _REQUEST_ATTR_SOURCES:
            return True, full

    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        qn2 = _qualname(node.func)
        if qn2 and any(qn2.startswith(src) for src in _REQUEST_ATTR_SOURCES):
            return True, f"{qn2}()"
        if qn2 == "os.getenv":
            return True, "os.getenv()"
        if qn2 and qn2.endswith(".read_text"):
            return True, "Path.read_text()"
        if qn2 and qn2.endswith(".read_bytes"):
            return True, "Path.read_bytes()"

    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
        return True, "open(...)"

    return False, ""


def _is_sink_call(call: ast.Call) -> tuple[bool, str, float]:
    qn = _qualname(call.func)

    if isinstance(call.func, ast.Name) and call.func.id in {"eval", "exec"}:
        return True, f"{call.func.id}(...)", 10.0

    if qn in {"pickle.loads", "pickle.load"}:
        return True, f"{qn}(...)", 9.5

    if qn in {"yaml.load"}:
        return True, "yaml.load(...)", 8.5

    if qn in {"os.system"}:
        return True, "os.system(...)", 9.0

    if qn and qn.startswith("subprocess.") and qn.split(".", 1)[1] in {
        "run", "Popen", "call", "check_call", "check_output",
    }:
        return True, f"{qn}(...)", 9.0

    if qn in {"shutil.rmtree", "shutil.move"}:
        return True, f"{qn}(...)", 7.5

    if qn and qn.endswith(".execute"):
        if len(call.args) >= 2:
            return True, f"{qn}(...) [parameterized]", 3.0
        return True, f"{qn}(...)", 8.0

    if _is_write_mode_call(call):
        return True, "open(..., 'w')", 6.0

    if qn in {"pathlib.Path.write_text", "pathlib.Path.write_bytes"}:
        return True, f"{qn}(...)", 6.0

    return False, "", 0.0


def _is_sanitizer_call(call: ast.Call) -> bool:
    qn = _qualname(call.func) or ""
    return any(kw in qn.lower() for kw in _SANITIZER_KEYWORDS)


def _severity_to_weight(sev: float) -> float:
    if sev >= 9.0:
        return 0.1
    elif sev >= 7.0:
        return 0.3
    elif sev >= 4.0:
        return 0.6
    return 1.0


def _classify_risk(score: float) -> str:
    if score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _node_id(path: Path, lineno: int, col: int, kind: str, name: str) -> str:
    return f"{str(path)}:{lineno}:{col}:{kind}:{name}"


def _var_id(path: Path, name: str) -> str:
    return f"{str(path)}:var:{name}"


class _TaintVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, g: nx.DiGraph) -> None:
        self.file_path = file_path
        self.g = g
        self.tainted: set[str] = set()
        self.sources: set[str] = set()
        self.sinks: set[str] = set()
        self.sanitizers: set[str] = set()
        self.current_function: str | None = None

    def _function_id(self, name: str) -> str:
        return f"{str(self.file_path)}:func:{name}"

    def _ensure_function_node(self, name: str, *, lineno: int, col: int) -> str:
        nid = self._function_id(name)
        self._add_node(nid, ntype="function", label=f"{name}()", lineno=lineno, col=col)
        return nid

    def _add_node(self, node_id: str, *, ntype: str, label: str, lineno: int, col: int, kind: str = "") -> None:
        if node_id in self.g:
            return
        attrs = {
            "id": node_id,
            "type": ntype,
            "label": label,
            "file": str(self.file_path),
            "line": lineno,
            "col": col,
        }
        if kind and ntype == "source":
            attrs["source_kind"] = kind
        elif kind and ntype == "sink":
            attrs["sink_kind"] = kind
        self.g.add_node(node_id, **attrs)

    def _expr_to_node(self, expr: ast.AST, *, fallback_label: str, ntype: str) -> str:
        lineno = getattr(expr, "lineno", 1)
        col = getattr(expr, "col_offset", 0)
        label = _qualname(expr) or fallback_label
        nid = _node_id(self.file_path, lineno, col, ntype, label)
        
        kind = ""
        if ntype == "source":
            lbl = label.lower()
            if any(x in lbl for x in ["request", "body", "query", "path", "form", "header", "cookie"]):
                kind = "http_input"
            elif "os.environ" in lbl or "os.getenv" in lbl:
                kind = "env_input"
            elif "read" in lbl or "open" in lbl:
                kind = "file_input"
            else:
                kind = "cli_input"
        elif ntype == "sink":
            lbl = label.lower()
            if "execute" in lbl:
                kind = "sql_execution"
            elif "subprocess" in lbl or "os.system" in lbl:
                kind = "cmd_execution"
            elif "write" in lbl or "open" in lbl or "rmtree" in lbl or "move" in lbl:
                kind = "file_write"
            elif "pickle" in lbl or "yaml" in lbl:
                kind = "deserialization"
            elif "eval" in lbl or "exec" in lbl:
                kind = "eval_exec"

        self._add_node(nid, ntype=ntype, label=label, lineno=lineno, col=col, kind=kind)
        return nid

    def _var_to_node(self, name: str, *, lineno: int, col: int) -> str:
        nid = _var_id(self.file_path, name)
        self._add_node(nid, ntype="intermediate", label=name, lineno=lineno, col=col)
        return nid

    def _taint_of_expr(self, expr: ast.AST) -> tuple[bool, list[str]]:
        src_nodes: list[str] = []

        is_source, label = _is_source_expr(expr)
        if is_source:
            nid = self._expr_to_node(expr, fallback_label=label, ntype="source")
            self.sources.add(nid)
            if self.current_function:
                fn = self._ensure_function_node(
                    self.current_function,
                    lineno=getattr(expr, "lineno", 1),
                    col=getattr(expr, "col_offset", 0),
                )
                self.g.add_edge(nid, fn, type="dependency", reason="source_in_function")
            return True, [nid]

        if isinstance(expr, ast.Call) and _is_sanitizer_call(expr):
            san_nid = self._expr_to_node(expr, fallback_label="sanitizer()", ntype="sanitizer")
            self.sanitizers.add(san_nid)
            inner_tainted = False
            for arg in expr.args:
                t, _ = self._taint_of_expr(arg)
                inner_tainted = inner_tainted or t
            return inner_tainted, [san_nid]

        for sub in ast.walk(expr):
            if isinstance(sub, ast.Name):
                var_nid = self._var_to_node(sub.id, lineno=getattr(sub, "lineno", 1), col=getattr(sub, "col_offset", 0))
                if var_nid in self.tainted:
                    src_nodes.append(var_nid)

        return (len(src_nodes) > 0), src_nodes

    def visit_Assign(self, node: ast.Assign) -> Any:
        tainted, origins = self._taint_of_expr(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                tid = self._var_to_node(target.id, lineno=getattr(target, "lineno", 1), col=getattr(target, "col_offset", 0))
                for o in origins:
                    self.g.add_edge(o, tid, type="dataflow", reason="assigned")
                if tainted:
                    self.tainted.add(tid)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        prev = self.current_function
        self.current_function = node.name
        self._ensure_function_node(node.name, lineno=getattr(node, "lineno", 1), col=getattr(node, "col_offset", 0))
        self.generic_visit(node)
        self.current_function = prev

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is None:
            return
        tainted, origins = self._taint_of_expr(node.value)
        if isinstance(node.target, ast.Name):
            tid = self._var_to_node(node.target.id, lineno=getattr(node.target, "lineno", 1), col=getattr(node.target, "col_offset", 0))
            for o in origins:
                self.g.add_edge(o, tid, type="dataflow", reason="assigned")
            if tainted:
                self.tainted.add(tid)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        is_sink, label, sev = _is_sink_call(node)
        if is_sink:
            sink_id = self._expr_to_node(node, fallback_label=label, ntype="sink")
            weight = _severity_to_weight(sev)
            self.g.nodes[sink_id]["severity"] = sev
            self.g.nodes[sink_id]["weight"] = weight
            if sev >= 9.0:
                self.g.nodes[sink_id]["risk"] = "critical"
            elif sev >= 7.0:
                self.g.nodes[sink_id]["risk"] = "high"
            elif sev >= 4.0:
                self.g.nodes[sink_id]["risk"] = "medium"
            else:
                self.g.nodes[sink_id]["risk"] = "low"
            self.sinks.add(sink_id)

            if self.current_function:
                fn = self._ensure_function_node(
                    self.current_function,
                    lineno=getattr(node, "lineno", 1),
                    col=getattr(node, "col_offset", 0),
                )
                self.g.add_edge(fn, sink_id, type="call", reason="sink_in_function", weight=weight)

            for arg in node.args:
                t, origins = self._taint_of_expr(arg)
                if t:
                    for o in origins:
                        self.g.add_edge(o, sink_id, type="dataflow", reason="tainted_arg", weight=weight)

        if _is_sanitizer_call(node):
            san_id = self._expr_to_node(node, fallback_label="sanitizer()", ntype="sanitizer")
            self.sanitizers.add(san_id)
            if self.current_function:
                fn = self._ensure_function_node(
                    self.current_function,
                    lineno=getattr(node, "lineno", 1),
                    col=getattr(node, "col_offset", 0),
                )
                self.g.add_edge(fn, san_id, type="call", reason="sanitizer_in_function", weight=3.0)

        if self.current_function and isinstance(node.func, ast.Name):
            caller = self._ensure_function_node(
                self.current_function,
                lineno=getattr(node, "lineno", 1),
                col=getattr(node, "col_offset", 0),
            )
            callee = self._ensure_function_node(
                node.func.id,
                lineno=getattr(node, "lineno", 1),
                col=getattr(node, "col_offset", 0),
            )
            self.g.add_edge(caller, callee, type="call", reason="calls", weight=1.0)

        any_tainted = False
        origins: list[str] = []
        for arg in node.args:
            t, o = self._taint_of_expr(arg)
            any_tainted = any_tainted or t
            origins.extend(o)

        if any_tainted and not is_sink:
            call_res = self._expr_to_node(node, fallback_label=_qualname(node.func) or "call()", ntype="intermediate")
            self.tainted.add(call_res)
            for o in origins:
                self.g.add_edge(o, call_res, type="dataflow", reason="flows_into_call", weight=1.0)

        self.generic_visit(node)


def build_security_graph(config: SecurityGraphConfig) -> dict[str, Any]:
    g = nx.DiGraph()
    sources: list[str] = []
    sinks: list[str] = []
    sanitizers: list[str] = []

    for py_file in _iter_python_files(config.root_dir, max_files=config.max_files):
        try:
            text = py_file.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=str(py_file))
        except Exception:
            continue

        vis = _TaintVisitor(py_file, g)
        vis.visit(tree)
        sources.extend(list(vis.sources))
        sinks.extend(list(vis.sinks))
        sanitizers.extend(list(vis.sanitizers))

    for nid, is_patched in list(PATCHED_SECURITY_NODES.items()):
        if is_patched and nid in g:
            g.remove_node(nid)

    communities = detect_security_communities(g)
    for nid in list(g.nodes):
        g.nodes[nid]["patched"] = bool(PATCHED_SECURITY_NODES.get(nid, False))
        if "id" not in g.nodes[nid]:
            g.nodes[nid]["id"] = nid
        comm = communities.get(nid, "application_logic")
        g.nodes[nid]["community"] = comm
        g.nodes[nid]["community_color"] = COMMUNITY_COLORS.get(comm, "#6B7280")

    nodes = [dict(data) for _, data in g.nodes(data=True)]
    edges = []
    for u, v, data in g.edges(data=True):
        u_node = g.nodes[u]
        v_node = g.nodes[v]
        edge_type = data.get("type", "dataflow")
        source_kind = u_node.get("source_kind", "")
        sink_kind = v_node.get("sink_kind", "")
        reason = data.get("reason", "")
        has_direct_assignment = (reason == "assigned")
        cross_function = (edge_type == "call" or reason == "calls")

        conf = compute_edge_confidence(edge_type, source_kind, sink_kind, has_direct_assignment, cross_function)
        data["confidence"] = conf

        edges.append({
            "source": u,
            "target": v,
            "type": edge_type,
            "reason": reason,
            "weight": float(data.get("weight", 1.0)),
            "confidence": conf,
            "on_attack_path": False
        })

    return {"graph": g, "nodes": nodes, "edges": edges, "sources": sources, "sinks": sinks, "sanitizers": sanitizers}


def get_security_graph(root: Path | None = None) -> dict[str, Any]:
    repo_root = Path(__file__).resolve().parents[2]
    default_root = repo_root / "sample_project" / "src"
    root_dir = (root or _ROOT_OVERRIDE or default_root)
    if not root_dir.exists():
        root_dir = repo_root

    global _security_graph
    with _lock:
        if _cache["graph"] is None or _cache["root"] != str(root_dir):
            from backend.services.java_graph_builder import (
                build_java_graph,
                detect_project_language,
                java_graph_to_built,
            )
            if detect_project_language(str(root_dir)) == "java":
                built = java_graph_to_built(build_java_graph(str(root_dir)))
            else:
                built = build_security_graph(SecurityGraphConfig(root_dir=root_dir))
            _cache["graph"] = built
            _cache["root"] = str(root_dir)
            _security_graph = built["graph"]
        return _cache["graph"]


def analyze_codebase(project_path: str) -> dict[str, Any]:
    global _current_graph, _current_paths, _current_high_risk
    p = Path(project_path).resolve()
    set_security_root(p)
    
    res = get_security_graph(p)
    _current_graph = {
        "nodes": res.get("nodes", []),
        "links": res.get("edges", []),
        "meta": {"scanned_project": p.name}
    }
    _current_paths = compute_attack_paths()
    _current_high_risk = compute_high_risk_paths()
    
    return res


def compute_attack_surface() -> list[dict[str, Any]]:
    built = get_security_graph()
    g: nx.DiGraph = built["graph"]
    return [dict(data) for nid, data in g.nodes(data=True) if data.get("type") == "source"]


def find_attack_paths(G, sources, sinks, max_depth=15):
    paths = []
    for src in sources:
        for sink in sinks:
            try:
                for path in nx.all_simple_paths(G, src, sink, cutoff=max_depth):
                    guards = [n for n in path
                              if G.nodes[n].get('type') in ('sanitizer', 'guard')]
                    guard_density = len(guards) / max(len(path), 1)
                    risk = round(1 - guard_density, 4)

                    sink_scores = [
                        float(G.nodes[n].get("risk_score", 9.0))
                        for n in path if G.nodes[n].get("type") == "sink"
                    ]
                    edge_weights = []
                    for i in range(len(path) - 1):
                        edge_data = G.get_edge_data(path[i], path[i + 1]) or {}
                        edge_weights.append(float(edge_data.get("weight", 1.0)))
                    rf_contribution = round(
                        (
                            (sum(sink_scores) if sink_scores else risk * 10.0) * 0.55
                            + (sum(edge_weights) if edge_weights else 1.0) * 0.45
                        )
                        / max(len(path), 1)
                        / 10.0,
                        4,
                    )

                    paths.append({
                        "path": path,
                        "guards": guards,
                        "guard_density": guard_density,
                        "risk": risk,
                        "rf_contribution": rf_contribution,
                    })
            except nx.NetworkXNoPath:
                continue
    return sorted(paths, key=lambda x: x["risk"], reverse=True)


def compute_attack_paths(limit: int = 50, max_depth: int = 8) -> list[dict[str, Any]]:
    built = get_security_graph()
    g: nx.DiGraph = built["graph"]
    sources = [n for n, d in g.nodes(data=True) if d.get("type") == "source"]
    sinks = [n for n, d in g.nodes(data=True) if d.get("type") == "sink"]
    paths = find_attack_paths(g, sources, sinks, max_depth=max_depth)
    return paths[:limit]


def compute_high_risk_paths(limit: int = 20) -> list[dict[str, Any]]:
    paths = compute_attack_paths(limit=500, max_depth=14)
    return paths[:limit]


def shortest_path_to_target(target_node_id: str) -> list[str]:
    built = get_security_graph()
    g: nx.DiGraph = built["graph"]
    if target_node_id not in g:
        return []

    sources = [n for n, d in g.nodes(data=True) if d.get("type") == "source"]
    paths = find_attack_paths(g, sources, [target_node_id], max_depth=15)
    return paths[0]["path"] if paths else []


def resolve_node_ref(ref: str, *, node_type: str | None = None) -> str | None:
    built = get_security_graph()
    g: nx.DiGraph = built["graph"]

    if ref in g:
        if node_type is None or g.nodes[ref].get("type") == node_type:
            return ref

    needle = (ref or "").strip().lower()
    if not needle:
        return None

    def norm(label: str) -> str:
        return (label or "").strip().lower().replace("(...)", "()")

    for nid, data in g.nodes(data=True):
        if node_type is not None and data.get("type") != node_type:
            continue
        label = str(data.get("label", ""))
        if label.strip().lower() == needle or norm(label) == needle:
            return nid

    for nid, data in g.nodes(data=True):
        if node_type is not None and data.get("type") != node_type:
            continue
        label = str(data.get("label", "")).lower()
        if needle in label or needle in norm(label):
            return nid

    return None
