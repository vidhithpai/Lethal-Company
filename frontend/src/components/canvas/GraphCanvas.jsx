import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph3D from "react-force-graph-3d";
import SpriteText from "three-spritetext";
import * as THREE from "three";
import useStore from "../../store/useStore";
import { endpoints } from "../../services/api";
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
  return { color: 'rgba(6, 182, 212, 0.35)', width: 1.2, opacity: 0.4, label: '' };
}

// ─── Disposal helper to prevent memory leaks ───────────────────────────────────
function disposeThreeObject(obj) {
  if (!obj) return;
  obj.traverse((child) => {
    if (child.geometry) {
      child.geometry.dispose();
    }
    if (child.material) {
      if (Array.isArray(child.material)) {
        child.material.forEach((m) => m && m.dispose && m.dispose());
      } else {
        child.material.dispose && child.material.dispose();
      }
    }
  });
}

// ─── Diff Status Resolver with Strict Priority: weakened > added > touched ─────
function getNodeDiffStatus(node, diffStatus, diffNodeSet) {
  if (node._isGhost || node.diff_status === 'removed') return 'removed';
  const id = node.id;
  if (!diffStatus && (!diffNodeSet || !diffNodeSet.size)) return null;

  // 1. Weakened (highest priority)
  if (diffStatus?.weakened && diffStatus.weakened[id]) return 'weakened';
  if (diffStatus?.nodes && diffStatus.nodes[id] === 'weakened') return 'weakened';

  // 2. Added
  if (diffStatus?.nodes && diffStatus.nodes[id] === 'added') return 'added';
  if (diffNodeSet && diffNodeSet.has(id)) return 'added';

  // 3. Touched
  if (diffStatus?.nodes && diffStatus.nodes[id] === 'touched') return 'touched';

  return null;
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

// ─── Bottom-Left Standard Legend HUD ──────────────────────────────────────────
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

// ─── Bottom-Left Diff Mode Legend HUD ─────────────────────────────────────────
const DiffLegendHUD = ({ counts }) => (
  <div className="hud-panel hud-bottom-left" style={{ minWidth: 235 }}>
    <div className="hud-legend-title" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
      <span>DIFF MODE</span>
      <span style={{ fontSize: 9, color: '#FACC15', fontWeight: 700, padding: '2px 6px', background: 'rgba(250, 204, 21, 0.15)', borderRadius: 4, letterSpacing: 0.5 }}>
        ACTIVE
      </span>
    </div>

    {/* Summary Badge Row */}
    <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 10, fontSize: 11, fontWeight: 600 }}>
      {counts.added > 0 && (
        <span style={{ color: '#FACC15', background: 'rgba(250, 204, 21, 0.12)', padding: '2px 6px', borderRadius: 3 }}>
          +{counts.added} added
        </span>
      )}
      {counts.weakened > 0 && (
        <span style={{ color: '#FB923C', background: 'rgba(251, 146, 60, 0.12)', padding: '2px 6px', borderRadius: 3 }}>
          {counts.weakened} weakened
        </span>
      )}
      {counts.removed > 0 && (
        <span style={{ color: '#94A3B8', background: 'rgba(148, 163, 184, 0.12)', padding: '2px 6px', borderRadius: 3 }}>
          -{counts.removed} removed
        </span>
      )}
      {counts.touched > 0 && (
        <span style={{ color: '#E2E8F0', background: 'rgba(255, 255, 255, 0.08)', padding: '2px 6px', borderRadius: 3 }}>
          {counts.touched} touched
        </span>
      )}
      {counts.added === 0 && counts.weakened === 0 && counts.removed === 0 && counts.touched === 0 && (
        <span style={{ color: '#64748B' }}>No graph changes</span>
      )}
    </div>

    <div style={{ fontSize: 10, fontWeight: 600, color: '#6B7280', marginBottom: 6, textTransform: 'uppercase' }}>
      DIFF INDICATORS
    </div>

    <div className="hud-legend-grid" style={{ gridTemplateColumns: '1fr', gap: 6 }}>
      <div className="hud-legend-item">
        <span style={{ width: 12, height: 12, borderRadius: '50%', border: '2px solid #FACC15', display: 'inline-block', flexShrink: 0 }} />
        <span>Gold ring (pulse): Added node</span>
      </div>
      <div className="hud-legend-item">
        <span style={{ width: 12, height: 12, borderRadius: '50%', border: '2px solid #FB923C', display: 'inline-block', flexShrink: 0 }} />
        <span>Amber ring: Weakened guard</span>
      </div>
      <div className="hud-legend-item">
        <span style={{ width: 12, height: 12, borderRadius: '50%', border: '1.5px solid #FFFFFF', display: 'inline-block', flexShrink: 0 }} />
        <span>Thin white ring: Touched file node</span>
      </div>
      <div className="hud-legend-item">
        <span style={{ width: 12, height: 12, borderRadius: '50%', border: '1.5px dashed #94A3B8', display: 'inline-block', flexShrink: 0 }} />
        <span>Wireframe sphere: Removed node</span>
      </div>
      <div className="hud-legend-item">
        <div style={{ width: 16, height: 3, background: '#FACC15', borderRadius: 1, flexShrink: 0, boxShadow: '0 0 4px #FACC15' }} />
        <span>Gold edge + particles: Added path</span>
      </div>
      <div className="hud-legend-item">
        <div style={{ width: 16, height: 3, background: '#FB923C', borderRadius: 1, flexShrink: 0 }} />
        <span>Amber edge: Weakened path into sink</span>
      </div>
      <div className="hud-legend-item">
        <div style={{ width: 16, height: 2, background: 'rgba(255,255,255,0.4)', borderRadius: 1, flexShrink: 0 }} />
        <span>Thin white edge: Removed edge</span>
      </div>
    </div>

    <div className="hud-legend-footer" style={{ borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: 6, marginTop: 8 }}>
      Body: Entry (green) &bull; Sink (red) &bull; Guard (purple)
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
function buildNodeObject(node, isOnPath, animatedObjectsRef, diffMode, diffStatusType, weakenedInfo) {
  const group = new THREE.Group();
  const nodeType = String(node.type || '').toLowerCase();
  const radius = getNodeSize(node) / 2;
  const isDiffNode = Boolean(diffStatusType);

  // BODY COLOR: Always remains type colour! Never overwritten to red in diff mode.
  const color = getNodeColor(node);

  let coreOpacity;
  if (diffMode) {
    if (diffStatusType === 'removed') {
      coreOpacity = 0.30;
    } else if (isDiffNode) {
      coreOpacity = 0.95;
    } else {
      coreOpacity = 0.15; // Dimmed noticeably to 0.15 for untouched nodes
    }
  } else {
    coreOpacity = node.patched ? 0.4 : 0.95;
  }

  let coreMesh;

  if (diffStatusType === 'removed') {
    // GHOST NODE: hollow sphere, white dashed/wireframe outline, opacity 0.30
    const ghostGeo = new THREE.SphereGeometry(radius, 14, 14);
    const ghostMat = new THREE.MeshBasicMaterial({
      color: '#FFFFFF',
      wireframe: true,
      transparent: true,
      opacity: 0.30,
    });
    coreMesh = new THREE.Mesh(ghostGeo, ghostMat);
    group.add(coreMesh);

  } else if (nodeType === "source") {
    const geo = new THREE.IcosahedronGeometry(radius, 0);
    const mat = new THREE.MeshPhongMaterial({
      color,
      emissive: '#059669',
      emissiveIntensity: diffMode && !isDiffNode ? 0.05 : 0.6,
      shininess: 80,
      transparent: true,
      opacity: coreOpacity,
    });
    coreMesh = new THREE.Mesh(geo, mat);

    const shellGeo = new THREE.IcosahedronGeometry(radius + 1.8, 1);
    const shellMat = new THREE.MeshBasicMaterial({
      color: '#10B981',
      wireframe: true,
      transparent: true,
      opacity: diffMode ? (isDiffNode ? 0.45 : 0.02) : 0.35,
    });
    const shell = new THREE.Mesh(shellGeo, shellMat);
    group.add(shell);
    group.userData.shell = shell;

  } else if (nodeType === "sink") {
    const geo = new THREE.DodecahedronGeometry(radius, 0);
    const mat = new THREE.MeshPhongMaterial({
      color,
      emissive: '#DC2626',
      emissiveIntensity: diffMode && !isDiffNode ? 0.05 : 0.7,
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
      opacity: diffMode ? (isDiffNode ? 0.45 : 0.02) : (isHighRisk ? 0.45 : 0.25),
    });
    const shell = new THREE.Mesh(shellGeo, shellMat);
    group.add(shell);
    group.userData.shell = shell;

    const auraGeo = new THREE.SphereGeometry(radius + 4.0, 16, 16);
    const auraMat = new THREE.MeshLambertMaterial({
      color: '#DC2626',
      transparent: true,
      opacity: diffMode ? (isDiffNode ? 0.25 : 0.01) : (isHighRisk ? 0.22 : 0.1),
    });
    group.add(new THREE.Mesh(auraGeo, auraMat));

  } else if (nodeType === "sanitizer") {
    const geo = new THREE.OctahedronGeometry(radius, 0);
    const mat = new THREE.MeshPhongMaterial({
      color,
      emissive: '#6D28D9',
      emissiveIntensity: diffMode && !isDiffNode ? 0.05 : 0.5,
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
      opacity: diffMode ? (isDiffNode ? 0.45 : 0.02) : 0.4,
    });
    const shell = new THREE.Mesh(shellGeo, shellMat);
    group.add(shell);
    group.userData.shell = shell;

  } else if (nodeType === "intermediate") {
    const geo = new THREE.OctahedronGeometry(radius, 0);
    const mat = new THREE.MeshPhongMaterial({
      color,
      emissive: '#D97706',
      emissiveIntensity: diffMode && !isDiffNode ? 0.05 : 0.4,
      transparent: true,
      opacity: coreOpacity,
    });
    coreMesh = new THREE.Mesh(geo, mat);

  } else {
    const geo = new THREE.SphereGeometry(radius, 16, 16);
    const mat = new THREE.MeshPhongMaterial({
      color,
      emissive: isOnPath ? color : '#1E293B',
      emissiveIntensity: diffMode && !isDiffNode ? 0.05 : (isOnPath ? 0.6 : 0.2),
      shininess: 40,
      transparent: true,
      opacity: coreOpacity,
    });
    coreMesh = new THREE.Mesh(geo, mat);
  }

  if (coreMesh) {
    group.add(coreMesh);
    group.userData.coreMesh = coreMesh;
  }
  group.userData.nodeType = nodeType;
  group.userData.isOnPath = isOnPath;

  // ─── DIFF RINGS & HALOS ──────────────────────────────────────────────────────
  if (diffMode) {
    if (diffStatusType === 'added') {
      // Gold ring / halo #FACC15 with slow pulse (scale 1.0 to 1.25, ~1.5s loop)
      const haloGeo = new THREE.SphereGeometry(radius + 2.5, 16, 16);
      const haloMat = new THREE.MeshBasicMaterial({
        color: '#FACC15',
        wireframe: true,
        transparent: true,
        opacity: 0.85,
      });
      const haloMesh = new THREE.Mesh(haloGeo, haloMat);
      group.add(haloMesh);
      group.userData.addedHalo = haloMesh;

      const ringGeo = new THREE.TorusGeometry(radius + 1.8, 0.35, 12, 24);
      const ringMat = new THREE.MeshBasicMaterial({
        color: '#FACC15',
        transparent: true,
        opacity: 0.90,
      });
      const ringMesh = new THREE.Mesh(ringGeo, ringMat);
      ringMesh.rotation.x = Math.PI / 3;
      group.add(ringMesh);
      group.userData.addedRing = ringMesh;

    } else if (diffStatusType === 'weakened') {
      // Amber ring #FB923C, plus small text sprite label "A <before> -> <after>"
      const ringGeo = new THREE.TorusGeometry(radius + 2.0, 0.40, 12, 24);
      const ringMat = new THREE.MeshBasicMaterial({
        color: '#FB923C',
        transparent: true,
        opacity: 0.95,
      });
      const ringMesh = new THREE.Mesh(ringGeo, ringMat);
      ringMesh.rotation.x = Math.PI / 3;
      group.add(ringMesh);

      const before = weakenedInfo?.before != null ? Number(weakenedInfo.before).toFixed(2) : "0.90";
      const after = weakenedInfo?.after != null ? Number(weakenedInfo.after).toFixed(2) : "0.00";
      const weakenedLabel = `A ${before} -> ${after}`;
      const weakenedSprite = new SpriteText(weakenedLabel);
      weakenedSprite.color = "#FB923C";
      weakenedSprite.textHeight = 2.4;
      weakenedSprite.fontFace = "JetBrains Mono, monospace";
      weakenedSprite.position.set(0, -(radius + 3.2), 0);
      group.add(weakenedSprite);

    } else if (diffStatusType === 'touched') {
      // Thin white ring, no animation
      const ringGeo = new THREE.TorusGeometry(radius + 1.6, 0.20, 12, 24);
      const ringMat = new THREE.MeshBasicMaterial({
        color: '#FFFFFF',
        transparent: true,
        opacity: 0.75,
      });
      const ringMesh = new THREE.Mesh(ringGeo, ringMat);
      ringMesh.rotation.x = Math.PI / 3;
      group.add(ringMesh);
    }
  } else if (isOnPath && !node.patched) {
    // Normal attack path glow
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

  // ─── Text Sprite Label ───────────────────────────────────────────────────────
  const rawLabel = node.label || (node.id ? node.id.split(":").pop() : "?");
  const displayLabel = rawLabel.length > 22 ? rawLabel.slice(0, 22) + "…" : rawLabel;

  let labelText;
  if (diffStatusType === 'removed') {
    // Strikethrough style with combining stroke \u0336
    const strikethrough = (text) => text.split('').map(c => c + '\u0336').join('');
    labelText = `${strikethrough(displayLabel)}\n[REMOVED]`;
  } else {
    let tagSuffix = "";
    if (nodeType === "source") tagSuffix = "\nSRC";
    else if (nodeType === "sink") tagSuffix = "\nSINK · HIGH";
    else if (nodeType === "sanitizer") tagSuffix = "\nFLT";
    else if (nodeType === "intermediate") tagSuffix = "\nINT";
    labelText = displayLabel + tagSuffix;
  }

  const sprite = new SpriteText(labelText);
  if (diffMode) {
    if (diffStatusType === 'added') sprite.color = "#FACC15";
    else if (diffStatusType === 'weakened') sprite.color = "#FB923C";
    else if (diffStatusType === 'touched') sprite.color = "#E2E8F0";
    else if (diffStatusType === 'removed') sprite.color = "#94A3B8";
    else sprite.color = "#334155"; // Dimmed to 0.15 equivalent for untouched
  } else {
    sprite.color = node.patched ? "#64748B" : (isOnPath ? "#FFFFFF" : (nodeType === "sink" ? "#EF4444" : (nodeType === "source" ? "#10B981" : "#94A3B8")));
  }
  sprite.textHeight = (isOnPath || isDiffNode) ? 3.2 : (nodeType === 'normal' ? 2.0 : 2.6);
  sprite.fontFace = "JetBrains Mono, monospace";
  sprite.position.set(0, radius + 4.5, 0);
  group.add(sprite);

  if (animatedObjectsRef && animatedObjectsRef.current) {
    animatedObjectsRef.current.push(group);
  }

  return group;
}

// ─── Main GraphCanvas Component ──────────────────────────────────────────────
const GraphCanvas = ({ repoPath, onNodeClick }) => {
  const graph          = useStore((state) => state.graph);
  const path           = useStore((state) => state.path);
  const diffMode       = useStore((state) => state.diffMode);
  const selectedCommit = useStore((state) => state.selectedCommit);
  const newPaths       = useStore((state) => state.newPaths);
  const diffStatus     = useStore((state) => state.diffStatus);
  const setDiffStatus  = useStore((state) => state.setDiffStatus);
  const nodeVisibility = useStore((state) => state.nodeVisibility);
  const edgeVisibility = useStore((state) => state.edgeVisibility);
  const focusDepth     = useStore((state) => state.focusDepth);
  const selectedNode   = useStore((state) => state.selectedNode);
  const zoomTrigger    = useStore((state) => state.zoomTrigger);

  const containerRef       = useRef(null);
  const graphRef           = useRef(null);
  const [size, setSize]     = useState({ width: 800, height: 600 });
  const [viewMode, setViewMode] = useState('3d');
  const animatedObjectsRef = useRef([]);

  const selectedCommitHash = useMemo(() => {
    return selectedCommit?.commit_hash || selectedCommit?.hash || (typeof selectedCommit === 'string' ? selectedCommit : null);
  }, [selectedCommit]);

  // ─── Fetch commitGraphDiff on diffMode & commit change ───────────────────────
  useEffect(() => {
    if (!diffMode || !selectedCommitHash) {
      if (diffStatus !== null) {
        setDiffStatus(null);
      }
      return;
    }

    let isMounted = true;
    const effectiveRepo = repoPath || localStorage.getItem("repo_path") || "./demo_project";

    fetch(endpoints.commitGraphDiff(selectedCommitHash, effectiveRepo))
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then((data) => {
        if (isMounted) {
          setDiffStatus(data);
        }
      })
      .catch((err) => {
        console.warn("[GraphCanvas] Failed to fetch commit-graph-diff:", err);
        if (isMounted) {
          setDiffStatus({
            commit: selectedCommitHash,
            nodes: {},
            edges: {},
            removed_nodes: [],
            removed_edges: [],
            weakened: {},
            truncated: false,
          });
        }
      });

    return () => {
      isMounted = false;
    };
  }, [diffMode, selectedCommitHash, repoPath, setDiffStatus]);

  // ─── Base filtering (nodeVisibility, edgeVisibility, focusDepth) ─────────────
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

  // ─── Displayed Graph (injects ghost nodes & removed edges in diff mode only) ─
  const displayedGraph = useMemo(() => {
    if (!diffMode || !diffStatus) {
      return filteredGraph;
    }

    const currentNodes = filteredGraph.nodes || [];
    const currentLinks = filteredGraph.links || [];
    const existingNodeIds = new Set(currentNodes.map(n => n.id));

    // Synthetic ghost nodes from diffStatus.removed_nodes (respecting nodeVisibility)
    const removedNodes = (diffStatus.removed_nodes || []).filter(rn => {
      if (existingNodeIds.has(rn.id)) return false;
      const t = String(rn.type || 'normal').toLowerCase();
      return nodeVisibility[t] !== false;
    }).map(rn => ({
      ...rn,
      id: rn.id,
      label: rn.label || rn.id,
      type: rn.type || 'sanitizer',
      file: rn.file,
      line: rn.line,
      _isGhost: true,
      diff_status: 'removed',
    }));

    const allNodes = [...currentNodes, ...removedNodes];
    const allNodeIds = new Set(allNodes.map(n => n.id));

    // Removed ghost edges (only draw if both endpoints exist)
    const existingEdgeKeys = new Set(currentLinks.map(l => {
      const s = l.source?.id || l.source;
      const t = l.target?.id || l.target;
      return `${s}->${t}`;
    }));

    const removedEdges = (diffStatus.removed_edges || []).filter(re => {
      const key = `${re.source}->${re.target}`;
      if (existingEdgeKeys.has(key)) return false;
      return allNodeIds.has(re.source) && allNodeIds.has(re.target);
    }).map(re => ({
      source: re.source,
      target: re.target,
      _isGhostEdge: true,
      diff_status: 'removed',
      type: 'removed',
    }));

    return {
      nodes: allNodes,
      links: [...currentLinks, ...removedEdges],
    };
  }, [filteredGraph, diffMode, diffStatus, nodeVisibility]);

  // ─── Added paths and edges sets ──────────────────────────────────────────────
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

  // ─── Weakened sink edges set ─────────────────────────────────────────────────
  const weakenedSinkEdgeSet = useMemo(() => {
    if (!diffMode || !diffStatus?.weakened) return new Set();
    const weakenedIds = new Set(Object.keys(diffStatus.weakened));
    const set = new Set();
    const nodes = displayedGraph?.nodes || [];
    const links = displayedGraph?.links || [];
    const sinkIds = new Set(nodes.filter(n => String(n.type).toLowerCase() === 'sink').map(n => n.id));

    links.forEach(l => {
      const s = l.source?.id || l.source;
      const t = l.target?.id || l.target;
      if (weakenedIds.has(s) && sinkIds.has(t)) {
        set.add(`${s}->${t}`);
      }
    });

    if (set.size === 0) {
      links.forEach(l => {
        const s = l.source?.id || l.source;
        const t = l.target?.id || l.target;
        if (sinkIds.has(t) && (weakenedIds.has(s) || diffStatus.nodes?.[s] === 'weakened')) {
          set.add(`${s}->${t}`);
        }
      });
    }

    return set;
  }, [diffMode, diffStatus, displayedGraph]);

  // ─── Diff Status Counts for Legend HUD ────────────────────────────────────────
  const diffCounts = useMemo(() => {
    if (!diffMode) return { added: 0, weakened: 0, removed: 0, touched: 0 };
    let added = 0;
    let weakened = 0;
    let touched = 0;
    let removed = diffStatus?.removed_nodes?.length || 0;

    if (diffStatus?.nodes) {
      Object.values(diffStatus.nodes).forEach(status => {
        if (status === 'added') added++;
        else if (status === 'weakened') weakened++;
        else if (status === 'touched') touched++;
      });
    }

    if (diffStatus?.weakened) {
      weakened = Math.max(weakened, Object.keys(diffStatus.weakened).length);
    }

    if (added === 0 && newPaths?.length) {
      const addedIds = new Set();
      newPaths.forEach(p => {
        if (Array.isArray(p)) p.forEach(id => addedIds.add(id));
      });
      added = addedIds.size;
    }

    return { added, weakened, removed, touched };
  }, [diffMode, diffStatus, newPaths]);

  // ─── Edge diff checkers ──────────────────────────────────────────────────────
  const isAddedEdge = (link) => {
    const s = link.source?.id || link.source;
    const t = link.target?.id || link.target;
    const key = `${s}->${t}`;
    return (
      link.diff_status === 'added' ||
      diffStatus?.edges?.[key] === 'added' ||
      diffLinkSet.has(key)
    );
  };

  const isRemovedEdge = (link) => {
    return link._isGhostEdge || link.diff_status === 'removed';
  };

  const isWeakenedSinkEdge = (link) => {
    const s = link.source?.id || link.source;
    const t = link.target?.id || link.target;
    const key = `${s}->${t}`;
    return weakenedSinkEdgeSet.has(key);
  };

  // ─── Resize Observer ─────────────────────────────────────────────────────────
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

  // ─── Disposal on Diff Mode change or unmount ─────────────────────────────────
  useEffect(() => {
    return () => {
      animatedObjectsRef.current.forEach(disposeThreeObject);
      animatedObjectsRef.current = [];
    };
  }, [diffMode]);

  // ─── Animation Loop (per-frame rotations and diff halo pulse) ────────────────
  useEffect(() => {
    let animId;
    let clock = 0;

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

        // Added node pulse: scale 1.0 to 1.25 with ~1.5s loop (freq ~4.19 rad/s)
        if (grp.userData.addedHalo) {
          const haloPulse = 1.0 + 0.125 * (1 + Math.sin(clock * 4.19 + i));
          grp.userData.addedHalo.scale.set(haloPulse, haloPulse, haloPulse);
        }

        if (grp.userData.addedRing) {
          const ringPulse = 1.0 + 0.125 * (1 + Math.sin(clock * 4.19 + i));
          grp.userData.addedRing.scale.set(ringPulse, ringPulse, ringPulse);
          grp.userData.addedRing.rotation.z += 0.012;
        }
      }

      animId = requestAnimationFrame(animate);
    };

    if (viewMode === '3d') {
      animate();
    }

    return () => {
      if (animId) cancelAnimationFrame(animId);
    };
  }, [viewMode, displayedGraph]);

  const pathNodeSet = useMemo(() => new Set(path), [path]);
  const pathEdgeSet = useMemo(() => {
    const s = new Set();
    for (let i = 0; i < path.length - 1; i++) {
      s.add(`${path[i]}->${path[i + 1]}`);
    }
    return s;
  }, [path]);

  const stats = useMemo(() => {
    const nodes = displayedGraph?.nodes || [];
    const links = displayedGraph?.links || [];
    const sources = nodes.filter((n) => String(n.type).toLowerCase() === 'source').length;
    const sinks = nodes.filter((n) => String(n.type).toLowerCase() === 'sink').length;
    return {
      nodes: nodes.length,
      edges: links.length,
      sources,
      sinks,
    };
  }, [displayedGraph]);

  useEffect(() => {
    if (graphRef.current) {
      setTimeout(() => {
        try {
          graphRef.current.zoomToFit(600, 80);
        } catch (_) {}
      }, 1400);
    }
  }, [graph]);

  // ─── Camera Focus on Selected Node (Direction 2: DiffViewer badge click) ─────
  useEffect(() => {
    if (!selectedNode || !graphRef.current) return;
    const targetId = typeof selectedNode === 'string' ? selectedNode : selectedNode.id;
    const nodes = displayedGraph?.nodes || [];
    const target = nodes.find(n => n.id === targetId);
    if (target && target.x != null && target.y != null && target.z != null) {
      try {
        graphRef.current.cameraPosition(
          { x: target.x, y: target.y - 15, z: target.z + 130 },
          { x: target.x, y: target.y, z: target.z },
          800
        );
      } catch (_) {}
    }
  }, [selectedNode, zoomTrigger, displayedGraph]);

  // ─── Multi-path Zoom Fit ─────────────────────────────────────────────────────
  useEffect(() => {
    if (!zoomTrigger || !graphRef.current || !path.length || selectedNode) return;

    const storeNodes = useStore.getState().graph.nodes || [];
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
  }, [zoomTrigger, path, selectedNode]);

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
            graphData={displayedGraph}

            nodeLabel={(node) => {
              if (node._isGhost || node.diff_status === 'removed') {
                return `[REMOVED] ${node.label || node.id} · ${node.type || "node"} (deleted in commit)`;
              }
              const status = diffMode ? getNodeDiffStatus(node, diffStatus, diffNodeSet) : null;
              const prefix = status ? `[${status.toUpperCase()}] ` : '';
              return `${prefix}${node.label || node.id} · ${node.type || "node"} · line ${node.line || "?"}`;
            }}
            nodeThreeObject={(node) => {
              const diffStatusType = diffMode ? getNodeDiffStatus(node, diffStatus, diffNodeSet) : null;
              const weakenedInfo = diffStatus?.weakened?.[node.id] || null;
              return buildNodeObject(
                node,
                pathNodeSet.has(node.id),
                animatedObjectsRef,
                diffMode,
                diffStatusType,
                weakenedInfo
              );
            }}
            nodeThreeObjectExtend={false}
            onNodeClick={(node) => onNodeClick(node)}
            nodeVal={(node) => getNodeSize(node) / 2}

            linkCurvature={0.12}
            linkWidth={(link) => {
              if (diffMode) {
                if (isAddedEdge(link)) return 3.5;
                if (isWeakenedSinkEdge(link)) return 3.0;
                if (isRemovedEdge(link)) return 1.2;
                return getEdgeStyle(link).width;
              }
              const s = link.source?.id || link.source;
              const t = link.target?.id || link.target;
              if (pathEdgeSet.has(`${s}->${t}`) || link.on_attack_path) return 3.5;
              return getEdgeStyle(link).width;
            }}
            linkColor={(link) => {
              if (diffMode) {
                if (isAddedEdge(link)) return '#FACC15';
                if (isWeakenedSinkEdge(link)) return '#FB923C';
                if (isRemovedEdge(link)) return '#FFFFFF';
                return getEdgeStyle(link).color;
              }
              const s = link.source?.id || link.source;
              const t = link.target?.id || link.target;
              if (pathEdgeSet.has(`${s}->${t}`) || link.on_attack_path) return 'rgba(239, 68, 68, 0.95)';
              if (link.patched) return '#374151';
              return getEdgeStyle(link).color;
            }}
            linkOpacity={(link) => {
              if (diffMode) {
                if (isAddedEdge(link)) return 1.0;
                if (isWeakenedSinkEdge(link)) return 0.95;
                if (isRemovedEdge(link)) return 0.35;
                return 0.08; // Untouched edges noticeably dimmed
              }
              return getEdgeStyle(link).opacity;
            }}

            linkDirectionalParticles={(link) => {
              if (diffMode) {
                return isAddedEdge(link) ? 4 : 0;
              }
              const s = link.source?.id || link.source;
              const t = link.target?.id || link.target;
              return pathEdgeSet.has(`${s}->${t}`) ? 6 : 0;
            }}
            linkDirectionalParticleWidth={3.0}
            linkDirectionalParticleColor={(link) => {
              if (diffMode) return "#FACC15";
              return "#F59E0B";
            }}
            linkDirectionalArrowLength={4.5}
            linkDirectionalArrowRelPos={1}

            backgroundColor="#050811"
            showNavInfo={false}
            cooldownTicks={120}
          />

          {diffMode ? (
            <DiffLegendHUD counts={diffCounts} />
          ) : (
            <LegendHUD />
          )}

          <ControlsHintHUD />
        </>
      )}

      {/* ── 2D SCHEMATIC VIEW ────────────────────────────────────────────── */}
      {viewMode === '2d' && (
        <SchematicView
          graph={displayedGraph}
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