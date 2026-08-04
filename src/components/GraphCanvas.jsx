import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph3D from "react-force-graph-3d";
import SpriteText from "three-spritetext";
import * as THREE from "three";
import { forceY } from "d3-force-3d";
import useStore from "../store/useStore";

const RISK_COLORS = {
  critical: "#EF4444",
  high: "#F97316",
  medium: "#F59E0B",
  low: "#10B981"
};

// ─── Shape-Based Geometries per Node Type (Modification 2) ───
const GEOMETRIES = {
  source: (radius) => new THREE.SphereGeometry(radius, 20, 20),
  sink: (radius) => new THREE.IcosahedronGeometry(radius, 0), // Icosahedron (Dangerous Octahedron-like)
  sanitizer: (radius) => new THREE.CylinderGeometry(radius, radius, radius * 1.5, 6), // Hexagon cylinder
  function: (radius) => new THREE.BoxGeometry(radius * 1.6, radius * 1.6, radius * 1.6), // Cube
  intermediate: (radius) => new THREE.OctahedronGeometry(radius, 0), // Diamond
  normal: (radius) => new THREE.SphereGeometry(radius, 16, 16)
};

const getNodeColor = (node, diffMode) => {
  if (node.patched) return '#4B5563'; // Neutral grey
  
  // Differential Version View Mode (Modification 7)
  if (diffMode) {
    if (node.diff_status === "added" || node.id.includes("new")) {
      return '#10B981'; // Green glow for new code
    }
    if (node.diff_status === "removed" || node.id.includes("old") || node.label?.includes("legacy")) {
      return '#EF4444'; // Red for removed code
    }
    if (node.type === "sanitizer" && node.patched) {
      return '#F59E0B'; // Faded guard yellow
    }
  }

  const nodeType = String(node.type || '').toLowerCase();
  const typeColors = {
    source: '#10B981',      // Emerald Green
    sink: '#EF4444',        // Bright Red
    intermediate: '#F59E0B',// Amber
    sanitizer: '#8B5CF6',   // Electric Violet (Guard node)
    function: '#3B82F6',    // Blue
    normal: '#9CA3AF',      // Slate grey
  };

  if (node.community && node.community !== "application_logic" && node.community_color) {
    return node.community_color;
  }

  return typeColors[nodeType] || '#6B7280';
};

// Meaningful Node Sizes (Modification 1)
const getNodeSize = (node) => {
  const nodeType = String(node.type || '').toLowerCase();
  
  // Base size hierarchy: Sink > Guard (Sanitizer) > Entry (Source) > Intermediate > Normal
  let base = 4;
  if (nodeType === 'sink') base = 9;
  else if (nodeType === 'sanitizer') base = 7;
  else if (nodeType === 'source') base = 6;
  else if (nodeType === 'function') base = 5;
  else if (nodeType === 'intermediate') base = 4.5;
  else base = 3.5;

  // Multiplier based on risk score / level
  const riskMultiplier = {
    CRITICAL: 1.8,
    HIGH: 1.5,
    MEDIUM: 1.25,
    LOW: 1.0,
    critical: 1.8,
    high: 1.5,
    medium: 1.25,
    low: 1.0
  };
  const risk = node.risk || 'LOW';
  
  // Size increase for patched/modified nodes
  const modificationBonus = node.patched ? 1.2 : 1.0;

  return base * (riskMultiplier[risk] || 1.0) * modificationBonus;
};

// Reachability visualization edge colors (Modification 4)
const getEdgeColor = (link, isOnPath, activeLayer) => {
  if (link.patched) return 'rgba(75, 85, 99, 0.15)'; // Inactive patched edge
  
  // If we are visualizing reachability layer
  if (isOnPath || link.on_attack_path) {
    return 'rgba(239, 68, 68, 0.85)'; // Intense red for active vulnerable paths
  }
  
  if (activeLayer === "reachability") {
    return 'rgba(59, 130, 246, 0.25)'; // Highlight normal reachable connections in cool blue
  }

  // Normal edges: thin and low opacity
  return 'rgba(107, 114, 128, 0.2)';
};

// Custom Three.js object builder per node
function buildNodeObject(node, isOnPath, hoveredNodeId, diffMode, blastNodeId) {
  const group = new THREE.Group();
  const nodeType = String(node.type || '').toLowerCase();
  
  // Scale node based on hover or selection blast ripple
  let radius = getNodeSize(node) / 2;
  
  // Hover & selection microinteractions (Modification 17)
  const isHovered = hoveredNodeId === node.id;
  const isBlastCenter = blastNodeId === node.id;
  
  if (isHovered) {
    radius *= 1.25;
  }
  if (isBlastCenter) {
    radius *= 1.4;
  }

  const color = getNodeColor(node, diffMode);
  const geomFn = GEOMETRIES[nodeType] || GEOMETRIES.normal;
  const geometry = geomFn(radius);
  
  // Custom futuristic materials
  const material = new THREE.MeshPhongMaterial({
    color,
    emissive: color,
    emissiveIntensity: isHovered ? 0.8 : (nodeType === 'sink' || nodeType === 'source' ? 0.4 : 0.15),
    transparent: true,
    opacity: node.patched ? 0.35 : 0.95,
    shininess: 90
  });

  const mesh = new THREE.Mesh(geometry, material);
  group.add(mesh);

  // ─── Guard Node Barriers (Modification 13) ───
  if (nodeType === "sanitizer") {
    // Faint green/cyan shielding halo for guards
    const shieldGeo = new THREE.CylinderGeometry(radius * 1.5, radius * 1.5, radius * 0.2, 8, 1, true);
    const shieldMat = new THREE.MeshBasicMaterial({
      color: node.patched ? "#EF4444" : "#10B981", // Red if guard failed/dissolved, Green if guard safe
      transparent: true,
      opacity: node.patched ? 0.15 : 0.35,
      wireframe: true,
      side: THREE.DoubleSide
    });
    const shieldMesh = new THREE.Mesh(shieldGeo, shieldMat);
    shieldMesh.rotation.x = Math.PI / 2;
    group.add(shieldMesh);
  }

  // ─── Concentric Risk Rings / Halos (Modification 6) ───
  if (!node.patched && (nodeType === "sink" || node.risk)) {
    const risk = String(node.risk || '').toUpperCase();
    let ringCount = 1;
    if (risk === "MEDIUM") ringCount = 2;
    else if (risk === "HIGH") ringCount = 3;
    else if (risk === "CRITICAL") ringCount = 4;

    for (let r = 1; r <= ringCount; r++) {
      const ringGeo = new THREE.RingGeometry(radius + (r * 1.8), radius + (r * 1.8) + 0.3, 16);
      const ringMat = new THREE.MeshBasicMaterial({
        color: RISK_COLORS[risk.toLowerCase()] || color,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.25 - (r * 0.05), // Fades out
        blending: THREE.AdditiveBlending
      });
      const ringMesh = new THREE.Mesh(ringGeo, ringMat);
      
      // Face camera
      ringMesh.lookAt(new THREE.Vector3(0, 0, 1));
      group.add(ringMesh);
    }
  }

  // Floating label in mono font
  const rawLabel = node.label || (node.id ? node.id.split(":").pop() : "?");
  const label = rawLabel.length > 24 ? rawLabel.slice(0, 24) + "…" : rawLabel;
  const sprite = new SpriteText(label);
  sprite.color = node.patched ? "#64748b" : (isOnPath ? "#ffffff" : "#e2e8f5");
  sprite.textHeight = isOnPath ? 3.5 : (isHovered ? 2.8 : 2.2);
  sprite.fontFace = "JetBrains Mono, monospace";
  sprite.fontWeight = "600";
  sprite.position.set(0, radius + 4.5, 0);
  
  group.add(sprite);

  return group;
}

const GraphCanvas = ({ onNodeClick }) => {
  const graph = useStore((state) => state.graph);
  const path = useStore((state) => state.path);
  const activeLayer = useStore((state) => state.activeLayer);
  const diffMode = useStore((state) => state.diffMode);
  const hoveredNodeId = useStore((state) => state.hoveredNodeId);
  const setHoveredNodeId = useStore((state) => state.setHoveredNodeId);
  const blastNodeId = useStore((state) => state.blastNodeId);
  const setBlastNodeId = useStore((state) => state.setBlastNodeId);
  
  const containerRef = useRef(null);
  const graphRef = useRef(null);
  const [size, setSize] = useState({ width: 800, height: 600 });

  // Track container dimensions
  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry) return;
      setSize({
        width: Math.max(320, Math.floor(entry.contentRect.width)),
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

  // Apply layered force layout (Modification 3)
  useEffect(() => {
    if (!graphRef.current) return;
    
    // Add vertical layer positioning force
    const fg = graphRef.current;
    
    fg.d3Force('y', forceY().y((node) => {
      const type = String(node.type || '').toLowerCase();
      // Level 1: external inputs -> Level 2: functions -> Level 3: sanitizers -> Level 4: sinks
      if (type === 'source') return -120; // Top
      if (type === 'function') return -30;
      if (type === 'sanitizer') return 30;
      if (type === 'sink') return 120; // Bottom
      return 0;
    }).strength(0.08));
    
    // Adjust charge force strength
    fg.d3Force('charge').strength(-150);
  }, [graph]);

  // Zoom to fit on load
  useEffect(() => {
    if (graphRef.current && graph?.nodes?.length > 0) {
      setTimeout(() => graphRef.current.zoomToFit(800, 80), 1000);
    }
  }, [graph]);

  // Center camera on zoom triggers
  const zoomTrigger = useStore((state) => state.zoomTrigger);
  useEffect(() => {
    if (!zoomTrigger || !graphRef.current || !path.length) return;

    const storeNodes = useStore.getState().graph.nodes;
    const pathNodes = path
      .map((id) => storeNodes.find((n) => n.id === id))
      .filter((n) => n && n.x != null);

    if (!pathNodes.length) {
      graphRef.current.zoomToFit(600, 60);
      return;
    }

    const avg = (arr) => arr.reduce((s, v) => s + v, 0) / arr.length;
    const cx = avg(pathNodes.map((n) => n.x));
    const cy = avg(pathNodes.map((n) => n.y ?? 0));
    const cz = avg(pathNodes.map((n) => n.z ?? 0));

    graphRef.current.cameraPosition(
      { x: cx, y: cy - 40, z: cz + 200 }, // camera position
      { x: cx, y: cy, z: cz },           // look-at
      800                                // duration ms
    );
  }, [zoomTrigger, path]);

  // Blast radius animation trigger (Modification 9)
  useEffect(() => {
    if (blastNodeId && graphRef.current) {
      // Find the node coordinate
      const node = graph?.nodes?.find(n => n.id === blastNodeId);
      if (node && node.x != null) {
        // Smoothly zoom camera to blast zone
        graphRef.current.cameraPosition(
          { x: node.x, y: node.y - 20, z: node.z + 130 },
          { x: node.x, y: node.y, z: node.z },
          800
        );

        // Reset blast ripple state after 1.5s
        const t = setTimeout(() => {
          setBlastNodeId(null);
        }, 1500);
        return () => clearTimeout(t);
      }
    }
  }, [blastNodeId, graph, setBlastNodeId]);

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

        // ── Node rendering ──
        nodeLabel={(node) =>
          `${node.label || node.id} · ${node.type || "node"} · line ${node.line || "?"}`
        }
        nodeThreeObject={(node) =>
          buildNodeObject(
            node, 
            pathNodeSet.has(node.id), 
            hoveredNodeId, 
            diffMode,
            blastNodeId
          )
        }
        nodeThreeObjectExtend={false}
        onNodeClick={(node) => {
          // Camera focus (Modification 17)
          if (graphRef.current && node.x != null) {
            graphRef.current.cameraPosition(
              { x: node.x, y: node.y - 30, z: node.z + 140 },
              { x: node.x, y: node.y, z: node.z },
              600
            );
          }
          // Blast radius ripple trigger when clicking node (Modification 9)
          setBlastNodeId(node.id);
          onNodeClick(node);
        }}
        onNodeHover={(node) => {
          setHoveredNodeId(node ? node.id : null);
        }}
        nodeVal={(node) => getNodeSize(node) / 2}

        // ── Edge rendering ──
        linkWidth={(link) => {
          const s = link.source?.id || link.source;
          const t = link.target?.id || link.target;
          return pathEdgeSet.has(`${s}->${t}`) ? 3.5 : 0.8;
        }}
        linkColor={(link) => {
          const s = link.source?.id || link.source;
          const t = link.target?.id || link.target;
          return getEdgeColor(link, pathEdgeSet.has(`${s}->${t}`), activeLayer);
        }}
        linkOpacity={0.8}

        // ── Directional Flow Particles (Modification 5) ──
        linkDirectionalParticles={(link) => {
          const s = link.source?.id || link.source;
          const t = link.target?.id || link.target;
          const isOnPath = pathEdgeSet.has(`${s}->${t}`);
          
          if (isOnPath) return 6; // Active particle flow on attack path
          if (activeLayer === "reachability" && link.on_attack_path) return 2; // Normal flow
          return 0;
        }}
        linkDirectionalParticleWidth={2.8}
        linkDirectionalParticleColor={(link) => {
          // Different particle colors: Blue (Normal), Green (Sanitized/Safe), Yellow (Blocked), Red (Malicious)
          const s = link.source?.id || link.source;
          const t = link.target?.id || link.target;
          const isOnPath = pathEdgeSet.has(`${s}->${t}`);
          
          if (isOnPath) {
            return "#EF4444"; // Malicious (Red)
          }
          if (link.type === "sanitized" || link.patched) {
            return "#10B981"; // Validated/Blocked (Green/Yellow)
          }
          return "#60A5FA"; // Normal Data (Blue)
        }}
        linkDirectionalParticleSpeed={(link) => {
          const s = link.source?.id || link.source;
          const t = link.target?.id || link.target;
          const isOnPath = pathEdgeSet.has(`${s}->${t}`);
          
          // Malicious flow moves faster indicating execution intensity
          return isOnPath ? 0.015 : 0.005;
        }}
        linkDirectionalArrowLength={4}
        linkDirectionalArrowRelPos={1}

        // ── Scene ──
        backgroundColor="#060913"
        showNavInfo={false}
        cooldownTicks={150}
      />

      {/* Modern Sci-Fi Legend overlay */}
      <div className="graph-legend">
        <div className="legend-title">Graph Taxonomy</div>
        <div className="legend-item">
          <div className="legend-dot" style={{ background: '#10B981' }} />
          <span>Entry / Source (Input)</span>
        </div>
        <div className="legend-item">
          <div className="legend-dot" style={{ background: '#EF4444' }} />
          <span>Sensitive Sink (Op)</span>
        </div>
        <div className="legend-item">
          <div className="legend-dot" style={{ background: '#8B5CF6' }} />
          <span>Security Guard (Filter)</span>
        </div>
        <div className="legend-item">
          <div className="legend-dot" style={{ background: '#3B82F6' }} />
          <span>Application Logic</span>
        </div>
        <div className="legend-item">
          <div className="legend-dot" style={{ background: '#4B5563' }} />
          <span>Patched Code</span>
        </div>
      </div>
    </div>
  );
};

export default GraphCanvas;
