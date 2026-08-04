import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph3D from "react-force-graph-3d";
import SpriteText from "three-spritetext";
import * as THREE from "three";
import { forceY } from "d3-force-3d";
import useStore from "../store/useStore";
import { NODE_STYLE_LOOKUP, getBaseNodeStyle, getNodeSize } from "../store/nodeStyles";

const RISK_COLORS = {
  critical: "#EF4444",
  high: "#F97316",
  medium: "#F59E0B",
  low: "#10B981"
};

// Global clock for shader animations (so we don't need a central render loop in ForceGraph)
const globalUniforms = {
  uTime: { value: 0 }
};
const animateShaders = () => {
  globalUniforms.uTime.value = performance.now() * 0.002;
  requestAnimationFrame(animateShaders);
};
animateShaders();

// Geometries are now driven by ../store/nodeStyles.js

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
  if (node.community && node.community !== "application_logic" && node.community_color) {
    return node.community_color;
  }

  const style = getBaseNodeStyle(nodeType);
  return style.color || '#6B7280';
};

// Reachability visualization edge colors (Modification 4)
const getEdgeColor = (link, isOnPath, hasSelection) => {
  if (link.patched || link.type === "sanitized") return '#10B981'; // Protected (green/static)
  if (isOnPath) return '#EF4444'; // Unsafe (red/animated)
  if (link.on_attack_path) return '#60A5FA'; // Reachable (bright/static)
  if (hasSelection && !isOnPath) return 'rgba(75, 85, 99, 0.1)'; // Inactive (grey/very low opacity)
  
  // Normal (thin/low-opacity)
  return 'rgba(107, 114, 128, 0.3)';
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
  const style = getBaseNodeStyle(nodeType);
  const geometry = style.geometry(radius);
  
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

  // Star-glow overlay for modified nodes
  if (node.modified) {
    const glowGeo = new THREE.OctahedronGeometry(radius * 1.6, 1);
    const glowMat = new THREE.MeshBasicMaterial({
      color: '#FCD34D',
      transparent: true,
      opacity: 0.4,
      wireframe: true,
      blending: THREE.AdditiveBlending
    });
    const glowMesh = new THREE.Mesh(glowGeo, glowMat);
    group.add(glowMesh);
  }

  // Pulsing animation for Sinks (static representation via scaling rings)
  if (nodeType === 'sink') {
    const pulseTime = Date.now() * 0.002;
    const pulseScale = 1 + Math.sin(pulseTime) * 0.15;
    mesh.scale.set(pulseScale, pulseScale, pulseScale);
  }

  // ─── Guard Node Barriers (Modification 13) ───
  if (nodeType === "sanitizer") {
    // Guards render as a visible barrier plane.
    // The active/removed state lives in the `node.patched` flag from useStore.
    // If a guard is patched (fixed), the barrier is active and present.
    const isBarrierActive = node.patched;
    
    if (isBarrierActive) {
      const planeGeo = new THREE.PlaneGeometry(radius * 5, radius * 5);
      
      // Base plane
      const planeMat = new THREE.MeshBasicMaterial({
        color: "#10B981", // Green for active shield
        transparent: true,
        opacity: 0.25,
        side: THREE.DoubleSide,
        depthWrite: false
      });
      const planeMesh = new THREE.Mesh(planeGeo, planeMat);
      planeMesh.rotation.x = Math.PI / 2;
      group.add(planeMesh);
      
      // Tech wireframe overlay
      const wireMat = new THREE.MeshBasicMaterial({
        color: "#10B981",
        wireframe: true,
        transparent: true,
        opacity: 0.6,
        side: THREE.DoubleSide
      });
      const wireMesh = new THREE.Mesh(planeGeo, wireMat);
      wireMesh.rotation.x = Math.PI / 2;
      group.add(wireMesh);
    }
  }

  // ─── Heatmap Glow & Risk Rings (Modification 6) ───
  if (!node.patched && (nodeType === "sink" || node.risk)) {
    const risk = String(node.risk || 'LOW').toUpperCase();
    let ringCount = 1;
    if (risk === "MEDIUM") ringCount = 2;
    else if (risk === "HIGH") ringCount = 3;
    else if (risk === "CRITICAL") ringCount = 4;

    // 1. Concentric pulsing halos (Rings)
    for (let r = 1; r <= ringCount; r++) {
      const ringGeo = new THREE.RingGeometry(radius + (r * 1.8), radius + (r * 1.8) + 0.3, 32);
      const ringMat = new THREE.ShaderMaterial({
        uniforms: {
          uColor: { value: new THREE.Color(RISK_COLORS[risk.toLowerCase()] || color) },
          uTime: globalUniforms.uTime,
          uOpacity: { value: 0.25 - (r * 0.05) },
          uOffset: { value: r * 0.5 }
        },
        vertexShader: `
          uniform float uTime;
          uniform float uOffset;
          void main() {
            // Subtle pulse animation based on time, offset per ring
            float pulse = 1.0 + sin(uTime + uOffset) * 0.04;
            gl_Position = projectionMatrix * modelViewMatrix * vec4(position * pulse, 1.0);
          }
        `,
        fragmentShader: `
          uniform vec3 uColor;
          uniform float uOpacity;
          void main() {
            gl_FragColor = vec4(uColor, uOpacity);
          }
        `,
        transparent: true,
        blending: THREE.AdditiveBlending,
        side: THREE.DoubleSide,
        depthWrite: false
      });
      const ringMesh = new THREE.Mesh(ringGeo, ringMat);
      
      // Face camera
      ringMesh.lookAt(new THREE.Vector3(0, 0, 1));
      group.add(ringMesh);
    }

    // 2. Heatmap Glow (Additive-blended Sprite)
    let glowColor = '#3B82F6'; // cool blue (safe/low)
    if (risk === 'CRITICAL') glowColor = '#991B1B'; // deep crimson
    else if (risk === 'HIGH') glowColor = '#EF4444'; // warm red
    else if (risk === 'MEDIUM') glowColor = '#F59E0B'; // warm orange

    const glowMat = new THREE.ShaderMaterial({
      uniforms: {
        uColor: { value: new THREE.Color(glowColor) }
      },
      vertexShader: `
        varying vec2 vUv;
        void main() {
          vUv = uv;
          gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
        }
      `,
      fragmentShader: `
        uniform vec3 uColor;
        varying vec2 vUv;
        void main() {
          // Calculate distance from center (0.5, 0.5)
          float d = distance(vUv, vec2(0.5));
          // Soft exponential falloff for the glow
          float alpha = smoothstep(0.5, 0.0, d);
          alpha = pow(alpha, 1.5);
          gl_FragColor = vec4(uColor, alpha * 0.55);
        }
      `,
      transparent: true,
      blending: THREE.AdditiveBlending,
      depthWrite: false
    });
    const glowSprite = new THREE.Sprite(glowMat);
    // Scale sprite to encompass the node and rings
    glowSprite.scale.set(radius * 6, radius * 6, 1);
    group.add(glowSprite);
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
      // Four vertical bands: External Inputs -> Business Logic -> Validation -> Sensitive Operations
      if (type === 'source') return -150; // External Inputs
      if (type === 'function') return -50; // Business Logic
      if (type === 'sanitizer') return 50; // Validation
      if (type === 'sink') return 150; // Sensitive Operations
      return 0;
    }).strength(0.3)); // Stronger strength to enforce bands
    
    // Adjust charge force strength
    fg.d3Force('charge').strength(-200);
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
          const isOnPath = pathEdgeSet.has(`${s}->${t}`);
          
          if (isOnPath) return 3.5;
          if (link.on_attack_path || link.patched || link.type === "sanitized") return 1.5;
          return 0.8;
        }}
        linkColor={(link) => {
          const s = link.source?.id || link.source;
          const t = link.target?.id || link.target;
          return getEdgeColor(link, pathEdgeSet.has(`${s}->${t}`), path.length > 0);
        }}
        linkOpacity={1}

        // ── Directional Flow Particles (Modification 5) ──
        linkDirectionalParticles={(link) => {
          const s = link.source?.id || link.source;
          const t = link.target?.id || link.target;
          const isOnPath = pathEdgeSet.has(`${s}->${t}`);
          
          // Animate particles for all active connections
          return 4; 
        }}
        linkDirectionalParticleWidth={2.5}
        linkDirectionalParticleColor={(link) => {
          const s = link.source?.id || link.source;
          const t = link.target?.id || link.target;
          const isOnPath = pathEdgeSet.has(`${s}->${t}`);
          
          // Particle color by data state: 
          if (isOnPath) return "#EF4444"; // Malicious (red)
          if (link.type === "sanitized") return "#10B981"; // Validated (green)
          if (link.patched) return "#FBBF24"; // Blocked (yellow)
          return "#3B82F6"; // Normal (blue)
        }}
        linkDirectionalParticleSpeed={(link) => {
          // Note: Speed must be derived from an existing intensity field. 
          // After inspecting the current data model, there is no such intensity field on paths/edges.
          // Using a fixed speed fallback instead of inventing one.
          return 0.015;
        }}
        linkDirectionalArrowLength={4}
        linkDirectionalArrowRelPos={1}
        
        // ── Scene ──
        backgroundColor="#060913"
        showNavInfo={false}
        // Removed cooldownTicks so simulation stays live (does not become a static grid)
      />

      {/* Modern Sci-Fi Legend overlay */}
      <div className="graph-legend">
        <div className="legend-title">Graph Taxonomy</div>
        {Object.values(NODE_STYLE_LOOKUP).filter(s => s.label !== 'Normal Node').map((style, idx) => (
          <div className="legend-item" key={idx}>
            <div className="legend-dot" style={{ background: style.color }} />
            <span>{style.label}</span>
          </div>
        ))}
        <div className="legend-item">
          <div className="legend-dot" style={{ background: '#4B5563' }} />
          <span>Patched Code</span>
        </div>
      </div>
    </div>
  );
};

export default GraphCanvas;
