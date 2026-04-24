import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph3D from "react-force-graph-3d";
import SpriteText from "three-spritetext";
import * as THREE from "three";
import useStore from "../store/useStore";

// ─── Node color map (identical to previous 2D version) ───────────────────────
const NODE_COLORS = {
  source:       "#22c55e",
  sink:         "#ef4444",
  intermediate: "#f59e0b",
  function:     "#3b82f6",
  sanitizer:    "#a78bfa",
  default:      "#6b7280",
};

// Risk ring / glow tint colours for sink nodes
const RISK_COLORS = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22c55e",
};

const nodeColorByType = (type) => NODE_COLORS[type] || NODE_COLORS.default;

const LEGEND = [
  { label: "Source",    color: NODE_COLORS.source },
  { label: "Sink",      color: NODE_COLORS.sink },
  { label: "Taint",     color: NODE_COLORS.intermediate },
  { label: "Function",  color: NODE_COLORS.function },
  { label: "Sanitizer", color: NODE_COLORS.sanitizer },
];

// ─── Custom Three.js object per node ─────────────────────────────────────────
// Returns a group containing a sphere + floating label sprite.
function buildNodeObject(node, isOnPath) {
  const group = new THREE.Group();
  const radius = isOnPath ? 5 : node.patched ? 4 : 3.5;
  const color  = node.patched ? "#4a5568" : nodeColorByType(node.type);

  // Sphere
  const geometry = new THREE.SphereGeometry(radius, 16, 16);
  const material = new THREE.MeshLambertMaterial({
    color,
    transparent: true,
    opacity: node.patched ? 0.5 : 1.0,
  });
  group.add(new THREE.Mesh(geometry, material));

  // Risk ring shell for sinks (emissive shell slightly larger)
  if (node.type === "sink" && node.risk && RISK_COLORS[node.risk]) {
    const ringGeo = new THREE.SphereGeometry(radius + 1.5, 16, 16);
    const ringMat = new THREE.MeshLambertMaterial({
      color: RISK_COLORS[node.risk],
      transparent: true,
      opacity: 0.18,
      wireframe: false,
    });
    group.add(new THREE.Mesh(ringGeo, ringMat));
  }

  // Glow ring for path nodes
  if (isOnPath && !node.patched) {
    const glowGeo = new THREE.SphereGeometry(radius + 2.5, 16, 16);
    const glowMat = new THREE.MeshLambertMaterial({
      color,
      transparent: true,
      opacity: 0.12,
    });
    group.add(new THREE.Mesh(glowGeo, glowMat));
  }

  // Floating text label
  const rawLabel = node.label || (node.id ? node.id.split(":").pop() : "?");
  const label    = rawLabel.length > 24 ? rawLabel.slice(0, 24) + "…" : rawLabel;
  const sprite   = new SpriteText(label);
  sprite.color        = isOnPath ? "#ffffff" : "#c8d4e8";
  sprite.textHeight   = isOnPath ? 3.2 : 2.4;
  sprite.fontFace     = "JetBrains Mono, monospace";
  sprite.position.set(0, radius + 5, 0);
  group.add(sprite);

  return group;
}

// ─── GraphCanvas (3D) ─────────────────────────────────────────────────────────
const GraphCanvas = ({ onNodeClick }) => {
  const graph        = useStore((state) => state.graph);
  const path         = useStore((state) => state.path);
  const containerRef = useRef(null);
  const graphRef     = useRef(null);
  const [size, setSize] = useState({ width: 800, height: 600 });

  // Track container dimensions
  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry) return;
      setSize({
        width:  Math.max(320, Math.floor(entry.contentRect.width)),
        height: Math.max(320, Math.floor(entry.contentRect.height)),
      });
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  // Sets of node/edge IDs on the current highlighted attack path
  const pathNodeSet = useMemo(() => new Set(path), [path]);
  const pathEdgeSet = useMemo(() => {
    const s = new Set();
    for (let i = 0; i < path.length - 1; i++) {
      s.add(`${path[i]}->${path[i + 1]}`);
    }
    return s;
  }, [path]);

  // One-time zoom after initial graph load
  useEffect(() => {
    if (graphRef.current) {
      setTimeout(() => graphRef.current.zoomToFit(600, 80), 1400);
    }
  }, [graph]);

  // Per-path zoom: fires whenever bumpZoom() is called from QueryBar
  const zoomTrigger = useStore((state) => state.zoomTrigger);
  useEffect(() => {
    if (!zoomTrigger || !graphRef.current || !path.length) return;

    // Force-graph mutates x/y/z directly on the node objects in the store,
    // so we can read positions straight from the Zustand graph nodes.
    const storeNodes = useStore.getState().graph.nodes;
    const pathNodes  = path
      .map((id) => storeNodes.find((n) => n.id === id))
      .filter((n) => n && n.x != null);

    if (!pathNodes.length) {
      graphRef.current.zoomToFit(600, 60);
      return;
    }

    const avg = (arr) => arr.reduce((s, v) => s + v, 0) / arr.length;
    const cx  = avg(pathNodes.map((n) => n.x));
    const cy  = avg(pathNodes.map((n) => n.y ?? 0));
    const cz  = avg(pathNodes.map((n) => n.z ?? 0));

    // Fly camera to look at the centroid from a slight angle
    graphRef.current.cameraPosition(
      { x: cx, y: cy - 40, z: cz + 180 },  // camera eye
      { x: cx, y: cy,      z: cz },         // look-at target
      700                                    // transition ms
    );
  }, [zoomTrigger, path]);

  return (
    <div
      className="graph-canvas"
      ref={containerRef}
      style={{ position: "relative", width: "100%", height: "100%" }}
    >
      <ForceGraph3D
        ref={graphRef}
        width={size.width}
        height={size.height}
        graphData={graph}

        // ── Node rendering ──────────────────────────────────────────────────
        nodeLabel={(node) =>
          `${node.label || node.id} · ${node.type || "node"} · line ${node.line || "?"}`
        }
        nodeThreeObject={(node) =>
          buildNodeObject(node, pathNodeSet.has(node.id))
        }
        nodeThreeObjectExtend={false}  // our group IS the whole object
        onNodeClick={(node) => onNodeClick(node)}

        // ── Node size (used by force engine for collision) ──────────────────
        nodeVal={(node) => (pathNodeSet.has(node.id) ? 5 : node.patched ? 4 : 3.5)}

        // ── Edge rendering ──────────────────────────────────────────────────
        linkWidth={(link) => {
          const s = link.source?.id || link.source;
          const t = link.target?.id || link.target;
          return pathEdgeSet.has(`${s}->${t}`) ? 3.5 : 1;
        }}
        linkColor={(link) => {
          const s = link.source?.id || link.source;
          const t = link.target?.id || link.target;
          if (pathEdgeSet.has(`${s}->${t}`)) return "#ef4444";
          if (link.type === "call")       return "#3b82f666";
          if (link.type === "dependency") return "#06b6d466";
          return "#1e3a5f";
        }}
        linkOpacity={0.7}

        // ── Directional particles (attack path animation) ───────────────────
        linkDirectionalParticles={(link) => {
          const s = link.source?.id || link.source;
          const t = link.target?.id || link.target;
          return pathEdgeSet.has(`${s}->${t}`) ? 5 : 0;
        }}
        linkDirectionalParticleWidth={2.5}
        linkDirectionalParticleColor={() => "#ef4444"}
        linkDirectionalArrowLength={4}
        linkDirectionalArrowRelPos={1}

        // ── Scene ───────────────────────────────────────────────────────────
        backgroundColor="#080c14"
        showNavInfo={false}
        cooldownTicks={120}
      />

      {/* Legend overlay — CSS-only, unchanged from 2D version */}
      <div className="graph-legend">
        {LEGEND.map(({ label, color }) => (
          <div key={label} className="legend-item">
            <div className="legend-dot" style={{ background: color }} />
            <span>{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default GraphCanvas;
