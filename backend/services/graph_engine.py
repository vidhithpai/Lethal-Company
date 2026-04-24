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


class GraphEngine:
    def __init__(self, config: GraphPaths) -> None:
        self._config = config
        self._lock = RLock()
        self._g = nx.DiGraph()
        self._node_attrs: dict[str, dict[str, Any]] = {}
        self._edge_attrs: dict[tuple[str, str], dict[str, Any]] = {}
        self._load_from_json()

    def _load_from_json(self) -> None:
        payload = json.loads(self._config.data_path.read_text(encoding="utf-8"))

        nodes = payload.get("nodes", [])
        edges = payload.get("edges", [])

        g = nx.DiGraph()
        node_attrs: dict[str, dict[str, Any]] = {}
        edge_attrs: dict[tuple[str, str], dict[str, Any]] = {}

        for n in nodes:
            node_id = str(n["id"])
            node_attrs[node_id] = {
                "id": node_id,
                "label": str(n.get("label", "")),
                "type": str(n.get("type", "")),
                "patched": bool(n.get("patched", False)),
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
            }
            if s not in node_attrs or t not in node_attrs:
                continue
            g.add_edge(s, t, weight=edge_data["weight"])
            edge_attrs[(s, t)] = edge_data

        with self._lock:
            self._g = g
            self._node_attrs = node_attrs
            self._edge_attrs = edge_attrs

    def get_graph(self) -> dict[str, Any]:
        with self._lock:
            nodes = list(self._node_attrs.values())
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


def get_engine() -> GraphEngine:
    global _engine
    with _engine_lock:
        if _engine is None:
            backend_dir = Path(__file__).resolve().parents[1]  # backend/
            data_path = backend_dir / "data" / "seed_graph.json"
            _engine = GraphEngine(GraphPaths(data_path=data_path))
        return _engine

