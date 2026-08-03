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
  const nodeType = String(node.type || '').toLowerCase();
  const typeColors = {
    source: '#10B981',
    sink: '#EF4444',
    intermediate: '#F59E0B',
    sanitizer: '#6366F1',
    function: '#3B82F6',
    normal: '#9CA3AF',
  };

  // Only use community color if it's a specific community, otherwise prefer type color
  if (node.community && node.community !== "application_logic" && node.community_color) {
    return node.community_color;
  }

  return typeColors[nodeType] || '#6B7280';
};

const getNodeSize = (node) => {
  const nodeType = String(node.type || '').toLowerCase();
  const base = nodeType === 'normal' ? 4.5 : 6;
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
      {color:'#9CA3AF', label:'Normal (logic / getter)'},
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
function buildNodeObject(node, isOnPath, diffMode, isOnNewPath, isRemovedGuard) {
  const group = new THREE.Group();
  const nodeType = String(node.type || '').toLowerCase();
  const radius = getNodeSize(node) / 2;
  
  // Decide node color and opacity
  let color = getNodeColor(node);
  let opacity = node.patched ? 0.45 : (nodeType === 'normal' ? 0.72 : 1.0);

  if (diffMode) {
    if (isOnNewPath) {
      color = "#FF0000";
      opacity = 1.0;
    } else if (isRemovedGuard) {
      color = "#666666";
      opacity = 0.4;
    } else {
      opacity = 0.3; // faded out other nodes
    }
  }

  // Sphere
  const geometry = new THREE.SphereGeometry(radius, 16, 16);
  const material = new THREE.MeshStandardMaterial({
    color,
    transparent: true,
    opacity,
    roughness: 0.3,
    metalness: 0.1
  });
  
  // If in diffMode and on a new attack path, enable emissive color so it can pulse
  if (diffMode && isOnNewPath) {
    material.emissive = new THREE.Color(0xff0000);
    material.emissiveIntensity = 0.8;
  }
  
  group.add(new THREE.Mesh(geometry, material));

  // Risk ring shell for sinks (emissive shell slightly larger)
  if (!diffMode && nodeType === "sink" && node.risk) {
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
  if (!diffMode && isOnPath && !node.patched) {
    const glowGeo = new THREE.SphereGeometry(radius + 2.5, 16, 16);
    const glowMat = new THREE.MeshLambertMaterial({
      color,
      transparent: true,
      opacity: 0.12,
    });
    group.add(new THREE.Mesh(glowGeo, glowMat));
  }

  // Glowing ring for new path nodes using RingGeometry (Task 3: "Add a glowing ring around them using THREE.RingGeometry")
  if (diffMode && isOnNewPath) {
    const ringGeo = new THREE.RingGeometry(radius + 1.2, radius + 2.4, 32);
    const ringMat = new THREE.MeshBasicMaterial({
      color: 0xff0000,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.6
    });
    const ringMesh = new THREE.Mesh(ringGeo, ringMat);
    // Orient the ring flat (pointing upwards or towards camera)
    ringMesh.rotation.x = Math.PI / 2;
    group.add(ringMesh);
  }

  // Floating text label
  let rawLabel = node.label || (node.id ? node.id.split(":").pop() : "?");
  if (diffMode && isRemovedGuard) {
    rawLabel = "~~" + rawLabel + "~~";
  }
  const label = rawLabel.length > 24 ? rawLabel.slice(0, 24) + "…" : rawLabel;
  const sprite = new SpriteText(label);
  
  if (diffMode) {
    if (isOnNewPath) {
      sprite.color = "#FF3333";
      sprite.textHeight = 3.2;
    } else if (isRemovedGuard) {
      sprite.color = "#666666";
      sprite.textHeight = 2.0;
    } else {
      sprite.color = "#4a6080";
      sprite.textHeight = 1.6;
    }
  } else {
    sprite.color = node.patched ? "#6B7280" : (isOnPath ? "#ffffff" : "#c8d4e8");
    sprite.textHeight = isOnPath ? 3.2 : (nodeType === 'normal' ? 2.0 : 2.4);
  }
  
  sprite.fontFace = "JetBrains Mono, monospace";
  if (node.patched && !diffMode) {
    sprite.textHeight = 2.2;
    sprite.strokeWidth = 0.5;
    sprite.strokeColor = "#374151";
  }
  sprite.position.set(0, radius + 5, 0);
  group.add(sprite);

  return group;
}

// ─── GraphCanvas (3D) ─────────────────────────────────────────────────────────
const GraphCanvas = ({ onNodeClick }) => {
  const graph        = useStore((state) => state.graph);
  const path         = useStore((state) => state.path);
  const diffMode     = useStore((state) => state.diffMode);
  const setDiffMode  = useStore((state) => state.setDiffMode);
  const newPaths     = useStore((state) => state.newPaths);
  const removedGuards = useStore((state) => state.removedGuards);

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

  // Diff Mode node/edge maps
  const newPathsNodeSet = useMemo(() => {
    const s = new Set();
    if (newPaths) {
      newPaths.forEach(pathArr => {
        if (Array.isArray(pathArr)) {
          pathArr.forEach(nid => s.add(nid));
        }
      });
    }
    return s;
  }, [newPaths]);

  const newPathsEdgeSet = useMemo(() => {
    const s = new Set();
    if (newPaths) {
      newPaths.forEach(pathArr => {
        if (Array.isArray(pathArr)) {
          for (let i = 0; i < pathArr.length - 1; i++) {
            s.add(`${pathArr[i]}->${pathArr[i+1]}`);
          }
        }
      });
    }
    return s;
  }, [newPaths]);

  const removedGuardsSet = useMemo(() => {
    return new Set(Array.isArray(removedGuards) ? removedGuards : []);
  }, [removedGuards]);

  // Pulsing emissive animation loop for new paths nodes under diffMode
  useEffect(() => {
    let animFrameId;
    const pulse = () => {
      const time = Date.now() * 0.005;
      const intensity = Math.sin(time) * 0.4 + 0.6; // oscillates between 0.2 and 1.0
      
      if (diffMode && graph?.nodes) {
        graph.nodes.forEach(node => {
          if (node.__threeObj && newPathsNodeSet.has(node.id)) {
            node.__threeObj.traverse(child => {
              if (child.isMesh && child.material) {
                if (child.material.emissive) {
                  child.material.emissive.setHex(0xff0000);
                  child.material.emissiveIntensity = intensity;
                }
              }
            });
          }
        });
      }
      animFrameId = requestAnimationFrame(pulse);
    };
    pulse();
    return () => cancelAnimationFrame(animFrameId);
  }, [diffMode, graph, newPathsNodeSet]);

  // One-time zoom after initial graph load
  useEffect(() => {
    if (graphRef.current) {
      setTimeout(() => graphRef.current.zoomToFit(600, 80), 1400);
    }
  }, [graph]);

  // Per-path zoom: fires whenever bumpZoom() is called from the query panel
  const zoomTrigger = useStore((state) => state.zoomTrigger);
  useEffect(() => {
    if (!zoomTrigger || !graphRef.current || !path.length) return;

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
      {/* Diff Mode Toggle Button Overlay */}
      <button
        onClick={() => setDiffMode(!diffMode)}
        style={{
          position: "absolute",
          top: 16,
          left: 16,
          background: diffMode ? "#EF444420" : "#1F293780",
          color: diffMode ? "#EF4444" : "#9CA3AF",
          border: `1px solid ${diffMode ? "#EF444440" : "#374151"}`,
          borderRadius: 6,
          padding: "6px 12px",
          fontSize: 12,
          fontWeight: 600,
          cursor: "pointer",
          zIndex: 10,
          backdropFilter: "blur(4px)",
          transition: "all 0.2s"
        }}
      >
        {diffMode ? "🔴 DIFF MODE ON" : "⚪ DIFF MODE OFF"}
      </button>

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
          buildNodeObject(
            node,
            pathNodeSet.has(node.id),
            diffMode,
            newPathsNodeSet.has(node.id),
            removedGuardsSet.has(node.id)
          )
        }
        nodeThreeObjectExtend={false}  // our group IS the whole object
        onNodeClick={(node) => onNodeClick(node)}

        // ── Node size (used by force engine for collision) ──────────────────
        nodeVal={(node) => getNodeSize(node) / 2}

        // ── Edge rendering ──────────────────────────────────────────────────
        linkWidth={(link) => {
          const s = link.source?.id || link.source;
          const t = link.target?.id || link.target;
          if (diffMode && newPathsEdgeSet.has(`${s}->${t}`)) return 3.0; // thick red lines (width 3px)
          return pathEdgeSet.has(`${s}->${t}`) ? 3.5 : 1;
        }}
        linkColor={(link) => {
          const s = link.source?.id || link.source;
          const t = link.target?.id || link.target;
          if (diffMode && newPathsEdgeSet.has(`${s}->${t}`)) return "#FF4444"; // color #FF4444
          return getEdgeColor(link, pathEdgeSet.has(`${s}->${t}`));
        }}
        linkOpacity={0.7}

        // ── Directional particles (attack path animation) ───────────────────
        linkDirectionalParticles={(link) => {
          const s = link.source?.id || link.source;
          const t = link.target?.id || link.target;
          if (diffMode && newPathsEdgeSet.has(`${s}->${t}`)) return 5;
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
