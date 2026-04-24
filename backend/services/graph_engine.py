from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any

import networkx as nx


@dataclass(frozen=True)
class GraphPaths:
    data_path: Path


PATCHED_NODES: dict[str, bool] = {}


class GraphEngine:
    def __init__(self, config: GraphPaths) -> None:
        self._config = config
        self._lock = RLock()
        self._g = nx.DiGraph()
        self._node_attrs: dict[str, dict[str, Any]] = {}
        self._edge_attrs: dict[tuple[str, str], dict[str, Any]] = {}
        self._load_from_json()

    def _load_from_json(self) -> None:
        raw_content = self._config.data_path.read_text(encoding="utf-8")
        payload = json.loads(raw_content)

        if "dependencies" in payload:
            from .mapper import map_owasp_report_to_graph
            payload = map_owasp_report_to_graph(self._config.data_path)

        nodes = payload.get("nodes", [])
        edges = payload.get("edges", [])

        g = nx.DiGraph()
        node_attrs: dict[str, dict[str, Any]] = {}
        edge_attrs: dict[tuple[str, str], dict[str, Any]] = {}

        for n in nodes:
            node_id = str(n["id"])
            patched = bool(PATCHED_NODES.get(node_id, bool(n.get("patched", False))))
            PATCHED_NODES.setdefault(node_id, patched)
            node_attrs[node_id] = {
                "id": node_id,
                "label": str(n.get("label", "")),
                "type": str(n.get("type", "")),
                "patched": patched,
            }
            g.add_node(node_id)

        for e in edges:
            s = str(e["source"])
            t = str(e["target"])
            edge_data = {
                "source": s,
                "target": t,
                "cve": str(e.get("cve", "")),
                "weight": float(e.get("weight", 1)),
                "severity": str(e.get("severity", "")),
            }
            if s not in node_attrs or t not in node_attrs:
                continue
            if node_attrs[s]["patched"] or node_attrs[t]["patched"]:
                continue
            g.add_edge(s, t, weight=edge_data["weight"])
            edge_attrs[(s, t)] = edge_data

        with self._lock:
            self._g = g
            self._node_attrs = node_attrs
            self._edge_attrs = edge_attrs

    def get_graph(self) -> dict[str, Any]:
        with self._lock:
            nodes = []
            for node_id, attrs in self._node_attrs.items():
                patched = bool(PATCHED_NODES.get(node_id, attrs.get("patched", False)))
                PATCHED_NODES[node_id] = patched
                node_copy = dict(attrs)
                node_copy["patched"] = patched
                nodes.append(node_copy)
            edges = list(self._edge_attrs.values())
        return {"nodes": nodes, "edges": edges}

    def get_attack_path(self, source: str, target: str) -> list[str]:
        with self._lock:
            if source not in self._g or target not in self._g:
                return []
            try:
                return nx.dijkstra_path(self._g, source, target, weight="weight")
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                return []

    def patch_node(self, node_id: str) -> bool:
        with self._lock:
            if node_id not in self._node_attrs or node_id not in self._g:
                return False

            self._node_attrs[node_id]["patched"] = True
            PATCHED_NODES[node_id] = True

            to_remove: list[tuple[str, str]] = []
            for (s, t) in list(self._edge_attrs.keys()):
                if s == node_id or t == node_id:
                    to_remove.append((s, t))

            for (s, t) in to_remove:
                if self._g.has_edge(s, t):
                    self._g.remove_edge(s, t)
                self._edge_attrs.pop((s, t), None)

            return True


_engine: GraphEngine | None = None
_engine_lock = RLock()
_backend_dir = Path(__file__).resolve().parents[1]  # backend/
MOCK_GRAPH_PATH = _backend_dir / "data" / "seed_graph.json"
GENERATED_GRAPH_PATH = _backend_dir / "data" / "generated_graph.json"
_active_graph_path: Path = MOCK_GRAPH_PATH


def get_engine() -> GraphEngine:
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = GraphEngine(GraphPaths(data_path=_active_graph_path))
        return _engine


def set_active_graph_path(data_path: Path) -> None:
    global _engine, _active_graph_path
    with _engine_lock:
        _active_graph_path = data_path
        PATCHED_NODES.clear()
        _engine = GraphEngine(GraphPaths(data_path=data_path))


def use_mock_graph() -> None:
    set_active_graph_path(MOCK_GRAPH_PATH)


def use_generated_graph() -> None:
    if not GENERATED_GRAPH_PATH.exists():
        raise FileNotFoundError("Generated graph not found.")
    set_active_graph_path(GENERATED_GRAPH_PATH)

