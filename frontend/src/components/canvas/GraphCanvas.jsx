import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph3D from "react-force-graph-3d";
import SpriteText from "three-spritetext";
import * as THREE from "three";
import useStore from "../../store/useStore";
import SchematicView from "./SchematicView";
import ViewToggle from "./ViewToggle";

const getNodeColor = (node) => {
  if (node.patched) return '#64748B';
  const nodeType = String(node.type || '').toLowerCase();
  const typeColors = {
    source: '#10B981',
    sink: '#EF4444',
    intermediate: '#F59E0B',
    sanitizer: '#0EA5E9',
    function: '#3B82F6',
    normal: '#3B82F6',
  };

  if (node.community && node.community !== "application_logic" && node.community_color) {
    return node.community_color;
  }

  return typeColors[nodeType] || '#3B82F6';
};

const getNodeSize = (node) => {
  const nodeType = String(node.type || '').toLowerCase();
  const base = nodeType === 'normal' ? 4.5 : 7.0;
  const riskMultiplier = { CRITICAL: 2.2, HIGH: 1.8, MEDIUM: 1.4, LOW: 1.0, critical: 2.2, high: 1.8, medium: 1.4, low: 1.0 };
  const risk = node.risk || 'LOW';
  const confidence = node.confidence || 0.5;
  return base * (riskMultiplier[risk] || 1.0) * (0.6 + confidence * 0.4);
};

function getEdgeStyle(link) {
  const raw = (link.type || link.edge_type || '').toLowerCase();
  
  if (raw.includes('cross_file') || raw.includes('cross-file')) {
    return { color: '#06B6D4', width: 1.8, opacity: 0.7, label: 'Cross-file' };
  }
  if (raw === 'call' || raw === 'calls') {
    return { color: '#3B82F6', width: 1.5, opacity: 0.65, label: 'Calls' };
  }
  if (raw.includes('reaching_def') || raw.includes('taint')) {
    return { color: '#0EA5E9', width: 2.0, opacity: 0.85, label: 'Taint' };
  }
  if (raw === 'dataflow' || raw === 'data_flow') {
    return { color: '#06B6D4', width: 1.4, opacity: 0.55, label: 'DataFlow' };
  }
  if (raw === 'extends') {
    return { color: '#F59E0B', width: 1.6, opacity: 0.70, label: 'Extends' };
  }
  if (raw === 'implements') {
    return { color: '#EC4899', width: 1.6, opacity: 0.70, label: 'Implements' };
  }
  if (raw === 'imports') {
    return { color: '#6B7280', width: 1.0, opacity: 0.40, label: 'Imports' };
  }
  if (raw.includes('same_file')) {
    return { color: '#374151', width: 1.0, opacity: 0.40, label: 'Same-file' };
  }
  // Default: generic edge
  return { color: 'rgba(6, 182, 212, 0.35)', width: 1.2, opacity: 0.4, label: '' };
}

// ─── Top-Left HUD ─────────────────────────────────────────────────────────────
const ThreatNebulaHUD = ({ stats }) => (
  <div className="hud-panel hud-top-left">
    <div className="hud-card-title">THREAT NEBULA</div>
    <div className="hud-card-sub">3D NETWORK VIEW</div>

    <div className="hud-metrics-list">
      <div className="hud-metric-row">
        <span className="val blue">{stats.nodes}</span>
        <span style={{ color: "var(--text-muted)", fontSize: 10 }}>NODES</span>
      </div>
      <div className="hud-metric-row">
        <span className="val cyan">{stats.edges}</span>
        <span style={{ color: "var(--text-muted)", fontSize: 10 }}>DATA FLOWS</span>
      </div>
      <div className="hud-metric-row">
        <span className="val green">{stats.sources}</span>
        <span style={{ color: "var(--text-muted)", fontSize: 10 }}>SOURCES</span>
      </div>
      <div className="hud-metric-row">
        <span className="val red">{stats.sinks}</span>
        <span style={{ color: "var(--text-muted)", fontSize: 10 }}>SINKS</span>
      </div>
    </div>
  </div>
);

// ─── Bottom-Left Legend HUD ───────────────────────────────────────────────────
const LegendHUD = () => (
  <div className="hud-panel hud-bottom-left">
    <div className="hud-legend-title">LEGEND</div>
    <div className="hud-legend-grid">
      <div className="hud-legend-item">
        <span className="hud-dot source" />
        <span>Source (entry)</span>
      </div>
      <div className="hud-legend-item">
        <span className="hud-dot sink" />
        <span>Sink (dangerous)</span>
      </div>
      <div className="hud-legend-item">
        <span className="hud-dot intermediate" />
        <span>Intermediate</span>
      </div>
      <div className="hud-legend-item">
        <span className="hud-dot sanitizer" />
        <span>Sanitizer</span>
      </div>
      <div className="hud-legend-item">
        <span className="hud-dot normal" />
        <span>Normal</span>
      </div>
      <div className="hud-legend-item">
        <span className="hud-dot patched" />
        <span>Patched</span>
      </div>
    </div>

    <div style={{ borderTop:'1px solid rgba(255,255,255,0.08)', 
                  paddingTop:8, marginTop:8 }}>
      <div style={{ fontSize:10, fontWeight:600, 
                    color:'#6B7280', marginBottom:6 }}>EDGE TYPES</div>
      {[
        { color:'#3B82F6',  label:'Calls' },
        { color:'#06B6D4',  label:'Cross-file / Data flow' },
        { color:'#0EA5E9',  label:'Taint flow' },
        { color:'#F59E0B',  label:'Extends' },
        { color:'#EC4899',  label:'Implements' },
        { color:'rgba(239,68,68,0.95)', label:'Attack path' },
      ].map(e => (
        <div key={e.label} style={{ display:'flex', alignItems:'center',
                                     gap:6, marginBottom:3 }}>
          <div style={{ width:16, height:2, background:e.color,
                         borderRadius:1, flexShrink:0 }} />
          <span style={{ fontSize:9, color:'rgba(255,255,255,0.55)' }}>
            {e.label}
          </span>
        </div>
      ))}
    </div>

    <div className="hud-legend-footer">
      Opacity = Confidence
    </div>
  </div>
);

// ─── Bottom-Right Interaction Hint HUD ───────────────────────────────────────
const ControlsHintHUD = () => (
  <div className="hud-panel hud-bottom-right">
    DRAG ⟳ ROTATE &bull; SCROLL 🔍 ZOOM
  </div>
);

// ─── Animated 3D Node Object Builder ──────────────────────────────────────────
let _nodeThreeObjectCalls = 0;

function buildNodeObject(node, isOnPath, animatedObjectsRef, diffMode, isDiffNode) {
  _nodeThreeObjectCalls++;
  if (_nodeThreeObjectCalls === 1 || _nodeThreeObjectCalls % 50 === 0) {
    console.log(`[GraphCanvas] nodeThreeObject invocation #${_nodeThreeObjectCalls}: Creating new THREE.Group, Geometries (Icosahedron/Dodecahedron/Sphere), Materials, and SpriteText with NO caching/pooling.`);
  }
  const group = new THREE.Group();
  const nodeType = String(node.type || '').toLowerCase();
  const radius = getNodeSize(node) / 2;
  
  let color = getNodeColor(node);
  if (diffMode && isDiffNode) {
    color = "#FF4444";
  }

  const coreOpacity = diffMode ? (isDiffNode ? 1.0 : 0.2) : (node.patched ? 0.4 : 0.95);
  let coreMesh;

  if (nodeType === "source") {
    const geo = new THREE.IcosahedronGeometry(radius, 0);
    const mat = new THREE.MeshPhongMaterial({
      color,
      emissive: diffMode && isDiffNode ? '#FF4444' : '#059669',
      emissiveIntensity: 0.6,
      shininess: 80,
      transparent: true,
      opacity: coreOpacity,
    });
    coreMesh = new THREE.Mesh(geo, mat);

    const shellGeo = new THREE.IcosahedronGeometry(radius + 1.8, 1);
    const shellMat = new THREE.MeshBasicMaterial({
      color: diffMode && isDiffNode ? '#FF4444' : '#10B981',
      wireframe: true,
      transparent: true,
      opacity: diffMode ? (isDiffNode ? 0.5 : 0.05) : 0.35,
    });
    const shell = new THREE.Mesh(shellGeo, shellMat);
    group.add(shell);
    group.userData.shell = shell;

  } else if (nodeType === "sink") {
    const geo = new THREE.DodecahedronGeometry(radius, 0);
    const mat = new THREE.MeshPhongMaterial({
      color: diffMode && isDiffNode ? '#FF4444' : '#EF4444',
      emissive: '#DC2626',
      emissiveIntensity: 0.7,
      shininess: 100,
      transparent: true,
      opacity: coreOpacity,
    });
    coreMesh = new THREE.Mesh(geo, mat);

    const isHighRisk = (String(node.risk).toUpperCase() === 'CRITICAL' || String(node.risk).toUpperCase() === 'HIGH');
    const shellGeo = new THREE.DodecahedronGeometry(radius + (isHighRisk ? 3.0 : 1.8), 1);
    const shellMat = new THREE.MeshBasicMaterial({
      color: '#EF4444',
      wireframe: true,
      transparent: true,
      opacity: diffMode ? (isDiffNode ? 0.5 : 0.05) : (isHighRisk ? 0.45 : 0.25),
    });
    const shell = new THREE.Mesh(shellGeo, shellMat);
    group.add(shell);
    group.userData.shell = shell;

    const auraGeo = new THREE.SphereGeometry(radius + 4.0, 16, 16);
    const auraMat = new THREE.MeshLambertMaterial({
      color: '#DC2626',
      transparent: true,
      opacity: diffMode ? (isDiffNode ? 0.3 : 0.02) : (isHighRisk ? 0.22 : 0.1),
    });
    group.add(new THREE.Mesh(auraGeo, auraMat));

  } else if (nodeType === "sanitizer") {
    const geo = new THREE.OctahedronGeometry(radius, 0);
    const mat = new THREE.MeshPhongMaterial({
      color,
      emissive: '#6D28D9',
      emissiveIntensity: 0.5,
      shininess: 60,
      transparent: true,
      opacity: coreOpacity,
    });
    coreMesh = new THREE.Mesh(geo, mat);

    const shellGeo = new THREE.OctahedronGeometry(radius + 1.8, 0);
    const shellMat = new THREE.MeshBasicMaterial({
      color,
      wireframe: true,
      transparent: true,
      opacity: diffMode ? (isDiffNode ? 0.5 : 0.05) : 0.4,
    });
    const shell = new THREE.Mesh(shellGeo, shellMat);
    group.add(shell);
    group.userData.shell = shell;

  } else if (nodeType === "intermediate") {
    const geo = new THREE.OctahedronGeometry(radius, 0);
    const mat = new THREE.MeshPhongMaterial({
      color,
      emissive: '#D97706',
      emissiveIntensity: 0.4,
      transparent: true,
      opacity: coreOpacity,
    });
    coreMesh = new THREE.Mesh(geo, mat);

  } else {
    const geo = new THREE.SphereGeometry(radius, 16, 16);
    const mat = new THREE.MeshPhongMaterial({
      color,
      emissive: isOnPath ? color : '#1E293B',
      emissiveIntensity: isOnPath ? 0.6 : 0.2,
      shininess: 40,
      transparent: true,
      opacity: coreOpacity,
    });
    coreMesh = new THREE.Mesh(geo, mat);
  }

  group.add(coreMesh);
  group.userData.coreMesh = coreMesh;
  group.userData.nodeType = nodeType;
  group.userData.isOnPath = isOnPath;

  if (diffMode && isDiffNode) {
    const redGlowGeo = new THREE.SphereGeometry(radius + 3.5, 16, 16);
    const redGlowMat = new THREE.MeshBasicMaterial({
      color: '#FF4444',
      wireframe: true,
      transparent: true,
      opacity: 0.8,
    });
    const redGlow = new THREE.Mesh(redGlowGeo, redGlowMat);
    group.add(redGlow);
    group.userData.redGlow = redGlow;
  } else if (isOnPath && !node.patched) {
    const pathGlowGeo = new THREE.SphereGeometry(radius + 3.0, 16, 16);
    const pathGlowMat = new THREE.MeshBasicMaterial({
      color: nodeType === "sink" ? '#EF4444' : (nodeType === "source" ? '#10B981' : '#F59E0B'),
      wireframe: true,
      transparent: true,
      opacity: 0.45,
    });
    const pathGlow = new THREE.Mesh(pathGlowGeo, pathGlowMat);
    group.add(pathGlow);
    group.userData.pathGlow = pathGlow;
  }

  const rawLabel = node.label || (node.id ? node.id.split(":").pop() : "?");
  const displayLabel = rawLabel.length > 22 ? rawLabel.slice(0, 22) + "…" : rawLabel;
  let tagSuffix = "";
  if (nodeType === "source") tagSuffix = "\nSRC";
  else if (nodeType === "sink") tagSuffix = "\nSINK · HIGH";
  else if (nodeType === "sanitizer") tagSuffix = "\nFLT";
  else if (nodeType === "intermediate") tagSuffix = "\nINT";

  const sprite = new SpriteText(displayLabel + tagSuffix);
  if (diffMode) {
    sprite.color = isDiffNode ? "#FF4444" : "#334155";
  } else {
    sprite.color = node.patched ? "#64748B" : (isOnPath ? "#FFFFFF" : (nodeType === "sink" ? "#EF4444" : (nodeType === "source" ? "#10B981" : "#94A3B8")));
  }
  sprite.textHeight = (isOnPath || (diffMode && isDiffNode)) ? 3.4 : (nodeType === 'normal' ? 2.0 : 2.6);
  sprite.fontFace = "JetBrains Mono, monospace";
  sprite.position.set(0, radius + 4.5, 0);
  group.add(sprite);

  if (animatedObjectsRef && animatedObjectsRef.current) {
    animatedObjectsRef.current.push(group);
  }

  return group;
}

// ─── Main GraphCanvas Component ──────────────────────────────────────────────
const GraphCanvas = ({ onNodeClick }) => {
  const graph        = useStore((state) => state.graph);
  const path         = useStore((state) => state.path);
  const diffMode     = useStore((state) => state.diffMode);
  const newPaths     = useStore((state) => state.newPaths);
  const nodeVisibility = useStore((state) => state.nodeVisibility);
  const edgeVisibility = useStore((state) => state.edgeVisibility);
  const focusDepth     = useStore((state) => state.focusDepth);
  const selectedNode   = useStore((state) => state.selectedNode);
  const containerRef = useRef(null);
  const graphRef     = useRef(null);
  const [size, setSize] = useState({ width: 800, height: 600 });
  const [viewMode, setViewMode] = useState('3d');
  const animatedObjectsRef = useRef([]);

  // STEP 2 Instrumentation: Component render counting and trigger detection
  const renderCountRef = useRef(0);
  const lastGraphRef = useRef(null);
  const frameCountRef = useRef(0);
  const lastFpsTimeRef = useRef(performance.now());
  renderCountRef.current++;
  console.count('[GraphCanvas] Component Render');
  const isGraphDataNew = lastGraphRef.current !== graph;
  console.log(
    `[GraphCanvas] Render #${renderCountRef.current} | Graph data reference changed: ${isGraphDataNew} | Store state: { nodeCount: ${graph?.nodes?.length || 0}, edgeCount: ${graph?.links?.length || 0}, pathLength: ${path?.length || 0}, diffMode: ${diffMode}, selectedNode: ${selectedNode?.id || 'none'}, focusDepth: ${focusDepth} }`
  );
  lastGraphRef.current = graph;

  const filteredGraph = useMemo(() => {
    const nodes = graph?.nodes || [];
    const links = graph?.links || [];

    // 1. Node type filter
    let visibleNodes = nodes.filter(n => {
      const t = String(n.type || 'normal').toLowerCase();
      return nodeVisibility[t] !== false;
    });

    // 2. Focus depth filter (if a node is selected and depth is set)
    if (focusDepth !== null && selectedNode) {
      const neighborSet = new Set([selectedNode.id]);
      // BFS outward N hops
      let frontier = [selectedNode.id];
      for (let hop = 0; hop < focusDepth; hop++) {
        const next = [];
        for (const src of frontier) {
          links.forEach(l => {
            const s = l.source?.id || l.source;
            const t = l.target?.id || l.target;
            if (s === src && !neighborSet.has(t)) { neighborSet.add(t); next.push(t); }
            if (t === src && !neighborSet.has(s)) { neighborSet.add(s); next.push(s); }
          });
        }
        frontier = next;
      }
      visibleNodes = visibleNodes.filter(n => neighborSet.has(n.id));
    }

    const visibleNodeIds = new Set(visibleNodes.map(n => n.id));

    // 3. Edge type filter + only keep edges where both endpoints visible
    const visibleLinks = links.filter(l => {
      const s = l.source?.id || l.source;
      const t = l.target?.id || l.target;
      if (!visibleNodeIds.has(s) || !visibleNodeIds.has(t)) return false;
      const edgeType = (l.type || l.edge_type || 'dataflow').toLowerCase();
      return edgeVisibility[edgeType] !== false;
    });

    return { nodes: visibleNodes, links: visibleLinks };
  }, [graph, nodeVisibility, edgeVisibility, focusDepth, selectedNode]);

  const diffNodeSet = useMemo(() => {
    if (!diffMode || !newPaths) return new Set();
    const set = new Set();
    for (const pathArr of newPaths) {
      if (Array.isArray(pathArr)) {
        for (const id of pathArr) {
          set.add(id);
        }
      }
    }
    return set;
  }, [diffMode, newPaths]);

  const diffLinkSet = useMemo(() => {
    if (!diffMode || !newPaths) return new Set();
    const set = new Set();
    for (const pathArr of newPaths) {
      if (Array.isArray(pathArr)) {
        for (let i = 0; i < pathArr.length - 1; i++) {
          set.add(`${pathArr[i]}->${pathArr[i + 1]}`);
        }
      }
    }
    return set;
  }, [diffMode, newPaths]);

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

  useEffect(() => {
    let animId;
    let clock = 0;

    console.log(`[GraphCanvas] 3D Animation loop initialized:
- Node decoration animations (rotations, pulse scaling) run per-frame in requestAnimationFrame across ${animatedObjectsRef.current.length} objects.
- Tooltip/Raycasting: nodeLabel is invoked by ForceGraph3D only on hover/raycast collision, NOT per animation frame.`);

    const animate = () => {
      clock += 0.02;
      const objs = animatedObjectsRef.current;
      for (let i = 0; i < objs.length; i++) {
        const grp = objs[i];
        if (!grp) continue;

        if (grp.userData.coreMesh) {
          grp.userData.coreMesh.rotation.y += 0.015;
          grp.userData.coreMesh.rotation.x += 0.008;
        }

        if (grp.userData.shell) {
          grp.userData.shell.rotation.y -= 0.02;
          grp.userData.shell.rotation.z += 0.01;
          const scalePulse = 1 + Math.sin(clock * 2.5 + i) * 0.06;
          grp.userData.shell.scale.set(scalePulse, scalePulse, scalePulse);
        }

        if (grp.userData.pathGlow) {
          const glowPulse = 1 + Math.sin(clock * 3.5 + i) * 0.12;
          grp.userData.pathGlow.scale.set(glowPulse, glowPulse, glowPulse);
        }

        if (grp.userData.redGlow) {
          const glowPulse = 1 + Math.sin(clock * 4.0 + i) * 0.15;
          grp.userData.redGlow.scale.set(glowPulse, glowPulse, glowPulse);
        }
      }

      frameCountRef.current++;
      if (frameCountRef.current % 120 === 0) {
        const now = performance.now();
        const elapsed = now - lastFpsTimeRef.current;
        const fps = Math.round((120 / elapsed) * 1000);
        console.log(`[GraphCanvas] [PERF] Animation pulse loop: ~${fps} FPS | ${objs.length} node meshes being transformed per frame.`);
        lastFpsTimeRef.current = now;
      }

      animId = requestAnimationFrame(animate);
    };

    if (viewMode === '3d') {
      animate();
    }

    return () => {
      if (animId) cancelAnimationFrame(animId);
    };
  }, [viewMode, filteredGraph]);

  const pathNodeSet = useMemo(() => new Set(path), [path]);
  const pathEdgeSet = useMemo(() => {
    const s = new Set();
    for (let i = 0; i < path.length - 1; i++) {
      s.add(`${path[i]}->${path[i + 1]}`);
    }
    return s;
  }, [path]);

  const stats = useMemo(() => {
    const nodes = filteredGraph?.nodes || [];
    const links = filteredGraph?.links || [];
    const sources = nodes.filter((n) => String(n.type).toLowerCase() === 'source').length;
    const sinks = nodes.filter((n) => String(n.type).toLowerCase() === 'sink').length;
    return {
      nodes: nodes.length,
      edges: links.length,
      sources,
      sinks,
    };
  }, [filteredGraph]);

  useEffect(() => {
    if (graphRef.current) {
      setTimeout(() => {
        try {
          graphRef.current.zoomToFit(600, 80);
        } catch (_) {}
      }, 1400);
    }
  }, [graph]);

  const zoomTrigger = useStore((state) => state.zoomTrigger);
  useEffect(() => {
    if (!zoomTrigger || !graphRef.current || !path.length) return;

    const storeNodes = useStore.getState().graph.nodes;
    const pathNodes  = path
      .map((id) => storeNodes.find((n) => n.id === id))
      .filter((n) => n && n.x != null);

    if (!pathNodes.length) {
      try {
        graphRef.current.zoomToFit(600, 60);
      } catch (_) {}
      return;
    }

    const avg = (arr) => arr.reduce((s, v) => s + v, 0) / arr.length;
    const cx  = avg(pathNodes.map((n) => n.x));
    const cy  = avg(pathNodes.map((n) => n.y ?? 0));
    const cz  = avg(pathNodes.map((n) => n.z ?? 0));

    graphRef.current.cameraPosition(
      { x: cx, y: cy - 40, z: cz + 180 },
      { x: cx, y: cy,      z: cz },
      700
    );
  }, [zoomTrigger, path]);

  console.log(`[GraphCanvas] Passing to react-force-graph-3d:
- Total Nodes: ${filteredGraph?.nodes?.length || 0}
- Total Edges: ${filteredGraph?.links?.length || 0}
- ForceGraph3D props: cooldownTicks=120, warmupTicks=0 (undefined / unconfigured)
- linkThreeObject: undefined (standard Three.js line)
- nodeThreeObject: custom buildNodeObject (allocates THREE.Group, Geometries, Materials, and SpriteText on every call without caching)`);

  animatedObjectsRef.current = [];

  return (
    <div
      className="graph-canvas"
      ref={containerRef}
      style={{ position: "relative", width: "100%", height: "100%", background: "#050811" }}
    >
      {/* ── 3D VIEW ───────────────────────────────────────────────────────── */}
      {viewMode === '3d' && (
        <>
          <ThreatNebulaHUD stats={stats} />
          
          <div style={{ position: "absolute", top: 16, right: 16, zIndex: 30 }}>
            <ViewToggle mode={viewMode} onChange={setViewMode} />
          </div>

          <ForceGraph3D
            ref={graphRef}
            width={size.width}
            height={size.height}
            graphData={filteredGraph}

            nodeLabel={(node) =>
              `${node.label || node.id} · ${node.type || "node"} · line ${node.line || "?"}`
            }
            nodeThreeObject={(node) =>
              buildNodeObject(node, pathNodeSet.has(node.id), animatedObjectsRef, diffMode, diffNodeSet.has(node.id))
            }
            nodeThreeObjectExtend={false}
            onNodeClick={(node) => onNodeClick(node)}
            nodeVal={(node) => getNodeSize(node) / 2}

            linkCurvature={0.12}
            linkWidth={(link) => {
              const s = link.source?.id || link.source;
              const t = link.target?.id || link.target;
              if (diffMode && diffLinkSet.has(`${s}->${t}`)) return 3;
              if (pathEdgeSet.has(`${s}->${t}`) || link.on_attack_path) return 3.5;
              return getEdgeStyle(link).width;
            }}
            linkColor={(link) => {
              const s = link.source?.id || link.source;
              const t = link.target?.id || link.target;
              // Attack path override
              if (diffMode && diffLinkSet.has(`${s}->${t}`)) return '#FF4444';
              if (pathEdgeSet.has(`${s}->${t}`) || link.on_attack_path) return 'rgba(239, 68, 68, 0.95)';
              if (link.patched) return '#374151';
              // Edge type colour
              return getEdgeStyle(link).color;
            }}
            linkOpacity={(link) => {
              if (diffMode) {
                const s = link.source?.id || link.source;
                const t = link.target?.id || link.target;
                return diffLinkSet.has(`${s}->${t}`) ? 1.0 : 0.1;
              }
              return getEdgeStyle(link).opacity;
            }}

            linkDirectionalParticles={(link) => {
              const s = link.source?.id || link.source;
              const t = link.target?.id || link.target;
              if (diffMode) {
                return diffLinkSet.has(`${s}->${t}`) ? 6 : 0;
              }
              return pathEdgeSet.has(`${s}->${t}`) ? 6 : 0;
            }}
            linkDirectionalParticleWidth={3.0}
            linkDirectionalParticleColor={(link) => {
              if (diffMode) return "#FF4444";
              return "#F59E0B";
            }}
            linkDirectionalArrowLength={4.5}
            linkDirectionalArrowRelPos={1}

            backgroundColor="#050811"
            showNavInfo={false}
            cooldownTicks={120}
          />

          <LegendHUD />
          <ControlsHintHUD />
        </>
      )}

      {/* ── 2D SCHEMATIC VIEW ────────────────────────────────────────────── */}
      {viewMode === '2d' && (
        <SchematicView
          graph={filteredGraph}
          path={path}
          onNodeClick={onNodeClick}
          viewMode={viewMode}
          setViewMode={setViewMode}
        />
      )}
    </div>
  );
};

export default GraphCanvas;
