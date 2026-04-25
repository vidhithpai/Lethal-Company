import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph3D from "react-force-graph-3d";
import SpriteText from "three-spritetext";
import * as THREE from "three";
import useStore from "../store/useStore";

const RISK_COLORS = {
  critical: "#EF4444",
  high: "#F97316",
  medium: "#F59E0B",
  low: "#10B981"
};
const getNodeColor = (node) => {
  if (node.patched) return '#4B5563';
  const typeColors = {
    source: '#10B981',
    sink: '#EF4444',
    intermediate: '#F59E0B',
    sanitizer: '#6366F1',
    function: '#3B82F6',
  };

  // Only use community color if it's a specific community, otherwise prefer type color
  if (node.community && node.community !== "application_logic" && node.community_color) {
    return node.community_color;
  }

  return typeColors[node.type] || '#6B7280';
};

const getNodeSize = (node) => {
  const base = 6;
  const riskMultiplier = { CRITICAL: 2.5, HIGH: 2.0, MEDIUM: 1.5, LOW: 1.0, critical: 2.5, high: 2.0, medium: 1.5, low: 1.0 };
  const risk = node.risk || 'LOW';
  const confidence = node.confidence || 0.5;
  return base * (riskMultiplier[risk] || 1.0) * (0.5 + confidence * 0.5);
};

const getEdgeColor = (link, isOnPath) => {
  if (link.patched) return '#374151';
  if (isOnPath || link.on_attack_path) {
    const conf = link.confidence || 0.7;
    return `rgba(239, 68, 68, ${0.4 + conf * 0.6})`;
  }
  const conf = link.confidence || 0.7;
  return `rgba(107, 114, 128, ${0.3 + conf * 0.4})`;
};

const GraphLegend = () => (
  <div style={{
    position: 'absolute', bottom: 16, left: 16,
    background: 'rgba(17,24,39,0.92)',
    border: '1px solid #374151',
    borderRadius: 8, padding: '10px 14px',
    fontSize: 11, color: '#D1D5DB', zIndex: 10
  }}>
    <div style={{fontWeight:600, marginBottom:6, color:'#F9FAFB'}}>
      Graph legend
    </div>
    {[
      {color:'#10B981', label:'Source (entry point)'},
      {color:'#EF4444', label:'Sink (dangerous op)'},
      {color:'#F59E0B', label:'Intermediate / tainted'},
      {color:'#6366F1', label:'Sanitizer (reduces risk)'},
      {color:'#4B5563', label:'Patched node'},
    ].map(({color, label}) => (
      <div key={label} style={{display:'flex',alignItems:'center',gap:6,marginBottom:3}}>
        <div style={{width:10,height:10,borderRadius:'50%',background:color,flexShrink:0}}/>
        <span>{label}</span>
      </div>
    ))}
    <div style={{marginTop:6,paddingTop:6,borderTop:'1px solid #374151',color:'#9CA3AF'}}>
      Edge opacity = confidence score
    </div>
  </div>
);

// ─── Custom Three.js object per node ─────────────────────────────────────────
function buildNodeObject(node, isOnPath) {
  const group = new THREE.Group();
  const radius = getNodeSize(node) / 2;
  const color  = getNodeColor(node);

  // Sphere
  const geometry = new THREE.SphereGeometry(radius, 16, 16);
  const material = new THREE.MeshLambertMaterial({
    color,
    transparent: true,
    opacity: node.patched ? 0.5 : 1.0,
  });
  group.add(new THREE.Mesh(geometry, material));

  // Risk ring shell for sinks (emissive shell slightly larger)
  if (node.type === "sink" && node.risk) {
    const riskCol = RISK_COLORS[node.risk.toLowerCase()] || "#ef4444";
    const ringGeo = new THREE.SphereGeometry(radius + 1.5, 16, 16);
    const ringMat = new THREE.MeshLambertMaterial({
      color: riskCol,
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
        nodeVal={(node) => getNodeSize(node) / 2}

        // ── Edge rendering ──────────────────────────────────────────────────
        linkWidth={(link) => {
          const s = link.source?.id || link.source;
          const t = link.target?.id || link.target;
          return pathEdgeSet.has(`${s}->${t}`) ? 3.5 : 1;
        }}
        linkColor={(link) => {
          const s = link.source?.id || link.source;
          const t = link.target?.id || link.target;
          return getEdgeColor(link, pathEdgeSet.has(`${s}->${t}`));
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

      <GraphLegend />
    </div>
  );
};

export default GraphCanvas;
