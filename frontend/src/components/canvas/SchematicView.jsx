import { useMemo, useState } from "react";
import ViewToggle from "./ViewToggle";

// ─── Color Palette Matching Mockup ───────────────────────────────────────────
const T = {
  bg:         "#050811",
  dotGrid:    "#132030",
  panel:      "#0c1527",
  border:     "#1E2D45",
  borderBright: "#2B3F60",
  ink:        "#F8FAFC",
  inkDim:     "#94A3B8",
  inkFaint:   "#64748B",
  source:     "#10B981",
  sink:       "#EF4444",
  intermediate:"#F59E0B",
  sanitizer:  "#0EA5E9",
  normal:     "#3B82F6",
  patched:    "#64748B",
};

// ─── Node chip dimensions ────────────────────────────────────────────────────
const NW      = 180;   // chip width
const NH      = 54;    // chip height
const PIN_LEN = 14;

// ─── Layout constants ─────────────────────────────────────────────────────────
const COL_SPACING = 310;
const ROW_SPACING = 140;
const PAD_LEFT    = 160;
const PAD_TOP     = 100;
const PAD_RIGHT   = 140;
const PAD_BOTTOM  = 100;

// ─── Type metadata ───────────────────────────────────────────────────────────
function typeMeta(type, risk) {
  const t = String(type || "").toLowerCase();
  const isHighRisk = String(risk).toUpperCase() === "CRITICAL" || String(risk).toUpperCase() === "HIGH";

  switch (t) {
    case "source":       return { color: T.source,       tag: "● SOURCE",       opacity: 1    };
    case "sink":         return { color: T.sink,         tag: isHighRisk ? "💀 SINK · HIGH" : "● SINK", opacity: 1 };
    case "sanitizer":    return { color: T.sanitizer,    tag: "● SANITIZER",    opacity: 1    };
    case "intermediate": return { color: T.intermediate, tag: "● INTERMEDIATE", opacity: 1    };
    case "patched":      return { color: T.patched,      tag: "● PATCHED",     opacity: 0.55 };
    default:             return { color: T.normal,       tag: "● NORMAL",       opacity: 0.95 };
  }
}

// ─── Layout computation ───────────────────────────────────────────────────────
function computeLayout(nodes, links) {
  const adj   = {};
  const inDeg = {};

  nodes.forEach((n) => {
    adj[n.id]   = [];
    inDeg[n.id] = 0;
  });

  links.forEach((l) => {
    const src = l.source?.id ?? l.source;
    const tgt = l.target?.id ?? l.target;
    if (adj[src])              adj[src].push(tgt);
    if (inDeg[tgt] !== undefined) inDeg[tgt]++;
  });

  const depth = {};
  const queue = [];

  nodes
    .filter((n) => String(n.type || "").toLowerCase() === "source")
    .forEach((n) => { depth[n.id] = 0; queue.push(n.id); });

  nodes
    .filter((n) => inDeg[n.id] === 0 && depth[n.id] === undefined)
    .forEach((n) => { depth[n.id] = 0; queue.push(n.id); });

  let qi = 0;
  while (qi < queue.length) {
    const id = queue[qi++];
    (adj[id] || []).forEach((tgtId) => {
      const next = (depth[id] ?? 0) + 1;
      if (depth[tgtId] === undefined || depth[tgtId] < next) {
        depth[tgtId] = next;
        queue.push(tgtId);
      }
    });
  }

  const TYPE_FALLBACK = { source: 0, normal: 1, function: 1, intermediate: 2, sanitizer: 2, sink: 3, patched: 3 };
  nodes.forEach((n) => {
    if (depth[n.id] === undefined) {
      depth[n.id] = TYPE_FALLBACK[String(n.type || "").toLowerCase()] ?? 1;
    }
  });

  const maxDepth = Math.max(...Object.values(depth), 0);
  const buckets  = Array.from({ length: maxDepth + 1 }, () => []);
  nodes.forEach((n) => buckets[depth[n.id]].push(n.id));

  const positions   = {};
  let maxNodesInCol = 0;

  buckets.forEach((ids, lvl) => {
    maxNodesInCol = Math.max(maxNodesInCol, ids.length);
    ids.forEach((id, rowIdx) => {
      positions[id] = {
        x: PAD_LEFT + lvl * COL_SPACING,
        y: PAD_TOP + rowIdx * ROW_SPACING + ROW_SPACING / 2,
      };
    });
  });

  const numCols = maxDepth + 1;
  const canvasW = Math.max(900, PAD_LEFT + (numCols - 1) * COL_SPACING + NW / 2 + PAD_RIGHT);
  const canvasH = Math.max(540, PAD_TOP + Math.max(maxNodesInCol, 1) * ROW_SPACING + PAD_BOTTOM);

  return { positions, canvasW, canvasH, numCols };
}

// ─── Orthogonal Manhattan Route ───────────────────────────────────────────────
function manhattanPath(ax, ay, bx, by) {
  const exitX  = ax + NW / 2 + PIN_LEN;
  const entryX = bx - NW / 2 - PIN_LEN;

  if (exitX >= entryX - 20) {
    const loopY = Math.max(ay, by) + ROW_SPACING * 0.55;
    const leftX = Math.min(ax, bx) - NW / 2 - 40;
    return [
      `M ${ax + NW / 2} ${ay}`,
      `H ${exitX}`,
      `V ${loopY}`,
      `H ${leftX}`,
      `V ${by}`,
      `H ${bx - NW / 2}`,
    ].join(" ");
  }

  const midX = (exitX + entryX) / 2;
  return [
    `M ${ax + NW / 2} ${ay}`,
    `H ${midX}`,
    `V ${by}`,
    `H ${bx - NW / 2}`,
  ].join(" ");
}

// ─── 2D PCB Chip Component ────────────────────────────────────────────────────
function Chip({ node, pos, isSelected, isOnPath, isDimmed, onNodeClick }) {
  const m  = typeMeta(node.type, node.risk);
  const x  = pos.x - NW / 2;
  const y  = pos.y - NH / 2;
  const cx = pos.x;
  const cy = pos.y;

  const isSink = String(node.type || "").toLowerCase() === "sink";
  const isPat  = String(node.type || "").toLowerCase() === "patched";

  const raw = node.label || node.id || "?";
  const labelStr = raw.length > 20 ? raw.slice(0, 19) + "…" : raw;
  const fileStr  = node.file ? (node.file.split(/[/\\]/).pop() + (node.line ? `:${node.line}` : "")) : "";

  return (
    <g
      style={{ cursor: "pointer", opacity: isDimmed ? 0.25 : m.opacity }}
      onClick={() => onNodeClick && onNodeClick(node)}
    >
      {/* Outer Glow for Sinks or Active Path */}
      {(isSink || isOnPath) && !isPat && (
        <rect
          x={x - 4} y={y - 4}
          width={NW + 8} height={NH + 8}
          rx={8}
          fill="none"
          stroke={isSink ? T.sink : T.source}
          strokeWidth={1.8}
          opacity={0.5}
        />
      )}

      {/* Main Chip Card */}
      <rect
        x={x} y={y}
        width={NW} height={NH}
        rx={6}
        fill={T.panel}
        stroke={isSelected ? "#FFFFFF" : m.color}
        strokeWidth={isSelected ? 2 : 1.4}
      />

      {/* Left accent color bar */}
      <rect
        x={x} y={y}
        width={5} height={NH}
        rx={2}
        fill={m.color}
      />

      {/* Type Tag (Header) */}
      <text
        x={x + 12} y={y + 16}
        fontFamily="'JetBrains Mono', monospace"
        fontSize={8.5}
        fontWeight={800}
        fill={m.color}
        letterSpacing={0.5}
      >
        {m.tag}
      </text>

      {/* Function / Main Label */}
      <text
        x={x + 12} y={y + 32}
        fontFamily="'JetBrains Mono', monospace"
        fontSize={11.5}
        fontWeight={700}
        fill={isPat ? T.inkFaint : T.ink}
        style={{ textDecoration: isPat ? "line-through" : "none", userSelect: "none" }}
      >
        {labelStr}
      </text>

      {/* Truncated File:Line sub-label */}
      {fileStr && (
        <text
          x={x + 12} y={y + 45}
          fontFamily="'JetBrains Mono', monospace"
          fontSize={8.5}
          fill={T.inkFaint}
          style={{ userSelect: "none" }}
        >
          {fileStr}
        </text>
      )}
    </g>
  );
}

// ─── Edge Component ───────────────────────────────────────────────────────────
function Edge({ link, positions, pathEdgeSet }) {
  const srcId = link.source?.id ?? link.source;
  const tgtId = link.target?.id ?? link.target;

  const a = positions[srcId];
  const b = positions[tgtId];
  if (!a || !b || srcId === tgtId) return null;

  const edgeKey  = `${srcId}->${tgtId}`;
  const isOnPath = pathEdgeSet.has(edgeKey);
  const color    = link.patched ? T.patched : (isOnPath || link.on_attack_path ? T.sink : T.borderBright);
  const width    = isOnPath ? 2.5 : 1.2;
  const d        = manhattanPath(a.x, a.y, b.x, b.y);

  return (
    <path
      d={d}
      fill="none"
      stroke={color}
      strokeWidth={width}
      strokeDasharray={link.patched ? "3 3" : "none"}
      opacity={isOnPath ? 0.95 : 0.45}
      markerEnd="url(#arrow)"
    />
  );
}

// ─── Compact Legend Key ───────────────────────────────────────────────────────
function SchematicLegend() {
  const items = [
    { color: T.source,       label: "Source"       },
    { color: T.sink,         label: "Sink"         },
    { color: T.intermediate, label: "Intermediate" },
    { color: T.sanitizer,    label: "Sanitizer"    },
    { color: T.normal,       label: "Normal"       },
    { color: T.patched,      label: "Patched"      },
  ];
  return (
    <div
      style={{
        position: "absolute",
        bottom: 20,
        left: 20,
        background: "rgba(12, 21, 39, 0.92)",
        border: `1px solid ${T.border}`,
        borderRadius: 8,
        padding: "10px 14px",
        fontSize: 11,
        zIndex: 20,
        backdropFilter: "blur(12px)",
      }}
    >
      <div style={{
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: 9.5, fontWeight: 800, letterSpacing: 1, color: T.inkFaint,
        marginBottom: 8, textTransform: "uppercase",
      }}>
        SCHEMATIC KEY
      </div>
      {items.map(({ color, label }) => (
        <div key={label} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5 }}>
          <span style={{ width: 8, height: 8, background: color, flexShrink: 0, borderRadius: 2 }} />
          <span style={{ color: T.inkDim, fontFamily: "'JetBrains Mono', monospace", fontSize: 10.5 }}>
            {label}
          </span>
        </div>
      ))}
    </div>
  );
}

// ─── 2D Canvas Controls (Bottom Right) ────────────────────────────────────────
function SchematicControls() {
  return (
    <div
      style={{
        position: "absolute",
        bottom: 20,
        right: 20,
        background: "rgba(12, 21, 39, 0.92)",
        border: `1px solid ${T.border}`,
        borderRadius: 8,
        padding: "4px 8px",
        display: "flex",
        flexDirection: "column",
        gap: 6,
        zIndex: 20,
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: 11,
        color: T.inkDim,
        alignItems: "center",
      }}
    >
      <button style={{ background: "none", border: "none", color: T.inkDim, cursor: "pointer" }}>🔒</button>
      <button style={{ background: "none", border: "none", color: T.inkDim, cursor: "pointer", fontSize: 14 }}>+</button>
      <button style={{ background: "none", border: "none", color: T.inkDim, cursor: "pointer", fontSize: 14 }}>−</button>
      <span style={{ fontSize: 9, color: T.inkFaint, cursor: "pointer" }}>Fit</span>
    </div>
  );
}

// ─── Main SchematicView Component ─────────────────────────────────────────────
const SchematicView = ({ graph, path, onNodeClick, viewMode, setViewMode }) => {
  const nodes = graph?.nodes || [];
  const links = graph?.links || [];

  const [filterText, setFilterText] = useState('');
  const [filterType, setFilterType] = useState('ALL');

  const pathNodeSet = useMemo(() => new Set(path || []), [path]);
  const pathEdgeSet = useMemo(() => {
    const s = new Set();
    for (let i = 0; i < (path || []).length - 1; i++) {
      s.add(`${path[i]}->${path[i + 1]}`);
    }
    return s;
  }, [path]);

  const isNodeMatchingFilter = (node) => {
    if (!node) return false;
    const type = String(node.type || '').toLowerCase();
    const risk = String(node.risk || 'LOW').toUpperCase();

    if (filterType === 'SOURCES' && type !== 'source') return false;
    if (filterType === 'SINKS' && type !== 'sink') return false;
    if (filterType === 'SANITY' && type !== 'sanitizer') return false;
    if (filterType === 'HIGH' && risk !== 'CRITICAL' && risk !== 'HIGH') return false;

    if (filterText.trim()) {
      const q = filterText.toLowerCase();
      const label = String(node.label || '').toLowerCase();
      const id = String(node.id || '').toLowerCase();
      const file = String(node.file || '').toLowerCase();
      if (!label.includes(q) && !id.includes(q) && !file.includes(q)) return false;
    }
    return true;
  };

  const { positions, canvasW, canvasH } = useMemo(
    () => computeLayout(nodes, links),
    [nodes.length, links.length]
  );

  return (
    <div style={{ position: "relative", width: "100%", height: "100%", background: T.bg }}>
      {/* ── TOP SCHEMATIC HEADER BAR ────────────────────────────────────────── */}
      <div className="schematic-header-bar">
        <div className="schematic-title-wrap">
          <span className="schematic-title">SCHEMATIC CIRCUIT VIEW</span>
          <span className="schematic-sub">2D DATA FLOW</span>
        </div>

        <div className="schematic-controls-center">
          <input
            type="text"
            placeholder="Search nodes... /"
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            className="schematic-search-input"
          />

          <div className="schematic-filter-pills">
            <button className={`sch-pill ${filterType === 'ALL' ? 'active' : ''}`} onClick={() => setFilterType('ALL')}>All</button>
            <button className={`sch-pill source ${filterType === 'SOURCES' ? 'active' : ''}`} onClick={() => setFilterType('SOURCES')}>● Source</button>
            <button className={`sch-pill sink ${filterType === 'SINKS' ? 'active' : ''}`} onClick={() => setFilterType('SINKS')}>● Sink</button>
            <button className={`sch-pill high ${filterType === 'HIGH' ? 'active' : ''}`} onClick={() => setFilterType('HIGH')}>● High Risk</button>
            <button className={`sch-pill sanitizer ${filterType === 'SANITY' ? 'active' : ''}`} onClick={() => setFilterType('SANITY')}>● Sanitizer</button>
          </div>
        </div>

        <ViewToggle mode={viewMode} onChange={setViewMode} />
      </div>

      {/* ── 2D CANVAS AREA ─────────────────────────────────────────────────── */}
      <div
        className="vg-scroll"
        style={{
          width: "100%",
          height: "100%",
          overflow: "auto",
          background: T.bg,
          paddingTop: 60,
        }}
      >
        <svg
          width={canvasW}
          height={canvasH}
          xmlns="http://www.w3.org/2000/svg"
          style={{ display: "block" }}
        >
          <defs>
            <pattern id="dot-grid-2d" x="0" y="0" width="24" height="24" patternUnits="userSpaceOnUse">
              <circle cx="12" cy="12" r="1" fill={T.dotGrid} opacity="0.6" />
            </pattern>

            <marker
              id="arrow"
              viewBox="0 0 10 10" refX="9" refY="5"
              markerWidth="5" markerHeight="5"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 9 5 L 0 9 z" fill={T.inkFaint} opacity="0.8" />
            </marker>
          </defs>

          <rect width={canvasW} height={canvasH} fill={T.bg} />
          <rect width={canvasW} height={canvasH} fill="url(#dot-grid-2d)" />

          {/* Edges */}
          {links.map((link, i) => (
            <Edge
              key={i}
              link={link}
              positions={positions}
              pathEdgeSet={pathEdgeSet}
            />
          ))}

          {/* Nodes */}
          {nodes.map((node) => {
            const pos = positions[node.id];
            if (!pos) return null;
            const isOnPath = pathNodeSet.has(node.id);
            const matchesFilter = isNodeMatchingFilter(node);
            const isDimmed = (filterText || filterType !== 'ALL') ? !matchesFilter : false;

            return (
              <Chip
                key={node.id}
                node={node}
                pos={pos}
                isSelected={isOnPath}
                isOnPath={isOnPath}
                isDimmed={isDimmed}
                onNodeClick={onNodeClick}
              />
            );
          })}
        </svg>
      </div>

      <SchematicLegend />
      <SchematicControls />
    </div>
  );
};

export default SchematicView;
