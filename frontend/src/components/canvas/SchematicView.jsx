import { useMemo } from "react";

// ─── Palette ─────────────────────────────────────────────────────────────────
const T = {
  bg:         "#080c14",   // matches 3D view backgroundColor
  dotGrid:    "#132030",   // dimmed to suit the darker base
  panel:      "#0F2530",
  border:     "#1C3D4B",
  borderSoft: "#16323E",
  ink:        "#E7EEF0",
  inkDim:     "#7FA0AC",
  inkFaint:   "#4E7583",
  trace:      "#49C7C0",
  traceDim:   "#245257",
  danger:     "#FF6B57",
  dangerDim:  "#5C2A22",
  guard:      "#9B8CFF",
  guardDim:   "#3A3568",
  warn:       "#FFC857",
  patched:    "#4A5D66",
};

// ─── Node chip dimensions ────────────────────────────────────────────────────
const NW      = 160;   // chip width
const NH      = 48;    // chip height
const PIN_LEN = 14;

// ─── Layout constants ─────────────────────────────────────────────────────────
const COL_SPACING = 300;   // px between column centres
const ROW_SPACING = 130;   // px between node centres in a column
const PAD_LEFT    = 160;   // canvas left margin (room for source connectors + pins)
const PAD_TOP     = 90;    // canvas top margin
const PAD_RIGHT   = 140;   // canvas right margin
const PAD_BOTTOM  = 100;   // canvas bottom margin

// ─── Type metadata ───────────────────────────────────────────────────────────
function typeMeta(type) {
  const t = String(type || "").toLowerCase();
  switch (t) {
    case "source":       return { color: T.trace,   tag: "SRC",  dash: "none", opacity: 1    };
    case "sink":         return { color: T.danger,  tag: "SINK", dash: "none", opacity: 1    };
    case "sanitizer":    return { color: T.guard,   tag: "FLT",  dash: "5 3",  opacity: 1    };
    case "intermediate":
    case "function":     return { color: T.warn,    tag: "INT",  dash: "none", opacity: 0.9  };
    case "patched":      return { color: T.patched, tag: "PAT",  dash: "3 3",  opacity: 0.52 };
    default:             return { color: T.inkDim,  tag: "—",    dash: "none", opacity: 0.8  };
  }
}

// ─── Edge colour / dash ───────────────────────────────────────────────────────
function edgeColor(link, isOnPath) {
  if (link.patched)                    return T.patched;
  if (isOnPath || link.on_attack_path) return T.danger;
  const t = String(link.type || "").toLowerCase();
  if (t === "sanitized")               return T.guard;
  return T.traceDim;
}

function edgeDash(link, isOnPath) {
  if (link.patched)                    return "2 5";
  if (isOnPath || link.on_attack_path) return "none";
  const t = String(link.type || "").toLowerCase();
  if (t === "sanitized")               return "6 4";
  return "none";
}

// ─── Layout ──────────────────────────────────────────────────────────────────
/**
 * Returns { positions, canvasW, canvasH, numCols }
 *
 * Uses BFS from source nodes to assign each node a "depth level".
 * That depth becomes the column, spreading nodes across the full
 * horizontal width of the canvas rather than stacking them all
 * into 4 fixed type-based columns.
 *
 * Fallback for disconnected / unvisited nodes: type-based bucket.
 */
function computeLayout(nodes, links) {
  // Build forward adjacency and in-degree maps
  const adj   = {};   // id → [targetId, ...]
  const inDeg = {};   // id → number

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

  // ── BFS from roots (nodes with 0 in-degree, or source-typed) ─────────────
  const depth = {};
  const queue = [];

  // Prefer nodes the graph designates as source-type first
  nodes
    .filter((n) => String(n.type || "").toLowerCase() === "source")
    .forEach((n) => { depth[n.id] = 0; queue.push(n.id); });

  // Then any node with no incoming edges not already queued
  nodes
    .filter((n) => inDeg[n.id] === 0 && depth[n.id] === undefined)
    .forEach((n) => { depth[n.id] = 0; queue.push(n.id); });

  // Propagate depths (longest-path BFS so sinks end up furthest right)
  let qi = 0;
  while (qi < queue.length) {
    const id = queue[qi++];
    (adj[id] || []).forEach((tgtId) => {
      const next = (depth[id] ?? 0) + 1;
      if (depth[tgtId] === undefined || depth[tgtId] < next) {
        depth[tgtId] = next;
        queue.push(tgtId);   // re-queue for relaxation
      }
    });
  }

  // Fallback: any node not reached gets a level based on type
  const TYPE_FALLBACK = { source: 0, sanitizer: 1, normal: 2, function: 2, intermediate: 2, sink: 3, patched: 3 };
  nodes.forEach((n) => {
    if (depth[n.id] === undefined) {
      depth[n.id] = TYPE_FALLBACK[String(n.type || "").toLowerCase()] ?? 1;
    }
  });

  // ── Build per-level buckets ───────────────────────────────────────────────
  const maxDepth = Math.max(...Object.values(depth), 0);
  const buckets  = Array.from({ length: maxDepth + 1 }, () => []);
  nodes.forEach((n) => buckets[depth[n.id]].push(n.id));

  // ── Assign pixel positions ────────────────────────────────────────────────
  const positions    = {};
  let maxNodesInCol  = 0;

  buckets.forEach((ids, lvl) => {
    maxNodesInCol = Math.max(maxNodesInCol, ids.length);
    ids.forEach((id, rowIdx) => {
      positions[id] = {
        x: PAD_LEFT + lvl * COL_SPACING,
        y: PAD_TOP + rowIdx * ROW_SPACING + ROW_SPACING / 2,
      };
    });
  });

  const numCols  = maxDepth + 1;
  const canvasW  = Math.max(900, PAD_LEFT + (numCols - 1) * COL_SPACING + NW / 2 + PAD_RIGHT);
  const canvasH  = Math.max(520, PAD_TOP + Math.max(maxNodesInCol, 1) * ROW_SPACING + PAD_BOTTOM);

  return { positions, canvasW, canvasH, numCols };
}


// ─── Orthogonal (Manhattan) path ─────────────────────────────────────────────
/**
 * Draws a right-angle route:
 *   exit right-pin  → horizontal to midX → vertical to target Y → horizontal to left-pin
 *
 * If the source is to the right of the target (back-edge), arcs around the
 * outside with a wider detour.
 */
function manhattanPath(ax, ay, bx, by) {
  const exitX  = ax + NW / 2 + PIN_LEN;
  const entryX = bx - NW / 2 - PIN_LEN;

  // Back-edge: loop around below
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

// ─── Chip ─────────────────────────────────────────────────────────────────────
function Chip({ node, pos, isSelected, isOnPath, onNodeClick }) {
  const m   = typeMeta(node.type);
  const x   = pos.x - NW / 2;
  const y   = pos.y - NH / 2;
  const cx  = pos.x;
  const cy  = pos.y;

  const isSink = String(node.type || "").toLowerCase() === "sink";
  const isSan  = String(node.type || "").toLowerCase() === "sanitizer";
  const isSrc  = String(node.type || "").toLowerCase() === "source";
  const isPat  = String(node.type || "").toLowerCase() === "patched";

  const filterId = `glow-${node.id.replace(/[^a-z0-9]/gi, "_")}`;
  const raw      = node.label || node.id || "?";
  const labelStr = raw.length > 20 ? raw.slice(0, 19) + "…" : raw;

  return (
    <g
      style={{ cursor: "pointer", opacity: m.opacity }}
      onClick={() => onNodeClick && onNodeClick(node)}
    >
      {/* SVG filter — only defined if this node needs glow */}
      {isSink && (
        <defs>
          <filter id={filterId} x="-80%" y="-80%" width="260%" height="260%">
            <feGaussianBlur stdDeviation="8" result="b1" />
            <feGaussianBlur stdDeviation="4" result="b2" />
            <feMerge>
              <feMergeNode in="b1" />
              <feMergeNode in="b2" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
      )}

      {/* Attack-path selection halo */}
      {isOnPath && !isPat && (
        <rect
          x={x - 6} y={y - 6}
          width={NW + 12} height={NH + 12}
          rx={8}
          fill="none"
          stroke={isSink ? T.danger : T.trace}
          strokeWidth={1.5}
          opacity={0.4}
          strokeDasharray="4 3"
        />
      )}

      {/* Main chip body */}
      <g filter={isSink ? `url(#${filterId})` : undefined}>
        <rect
          x={x} y={y}
          width={NW} height={NH}
          rx={4}
          fill={T.panel}
          stroke={isSelected ? T.ink : m.color}
          strokeWidth={isSelected ? 2.2 : isPat ? 1 : 1.5}
          strokeDasharray={isSelected ? "none" : m.dash}
        />
        {/* Left accent bar */}
        <rect
          x={x} y={y}
          width={7} height={NH}
          rx={3}
          fill={m.color}
          opacity={isPat ? 0.35 : 0.9}
        />
        {/* Sanitizer notch in left bar */}
        {isSan && (
          <polygon
            points={`${x},${cy - 8} ${x + 7},${cy} ${x},${cy + 8}`}
            fill={T.panel}
            opacity={0.95}
          />
        )}
      </g>

      {/* Source left-connector block */}
      {isSrc && (
        <g opacity={0.75}>
          <rect
            x={x - 18} y={cy - 6}
            width={10} height={12}
            rx={1.5}
            fill="none"
            stroke={T.trace}
            strokeWidth={1}
          />
          <line x1={x - 8} y1={cy} x2={x} y2={cy} stroke={T.trace} strokeWidth={1} />
        </g>
      )}

      {/* Left pin nub */}
      <line
        x1={x - PIN_LEN} y1={cy}
        x2={x}            y2={cy}
        stroke={m.color}
        strokeWidth={1.4}
        opacity={0.55}
      />
      {/* Right pin nub */}
      <line
        x1={x + NW}           y1={cy}
        x2={x + NW + PIN_LEN} y2={cy}
        stroke={m.color}
        strokeWidth={1.4}
        opacity={0.55}
      />

      {/* Type tag (above chip) */}
      <text
        x={x + 11} y={y - 6}
        fontFamily="'IBM Plex Mono', monospace"
        fontSize={8.5}
        fill={m.color}
        letterSpacing={1.2}
        opacity={0.9}
      >
        {m.tag}
      </text>

      {/* Main label */}
      <text
        x={cx + 4} y={cy + 4}
        textAnchor="middle"
        fontFamily="'IBM Plex Mono', monospace"
        fontSize={11}
        fill={isPat ? T.inkFaint : T.ink}
        style={{ textDecoration: isPat ? "line-through" : "none", userSelect: "none" }}
      >
        {labelStr}
      </text>

      {/* File / line sub-label */}
      {(node.file || node.line) && (
        <text
          x={cx + 4} y={cy + 18}
          textAnchor="middle"
          fontFamily="'IBM Plex Mono', monospace"
          fontSize={8.5}
          fill={T.inkFaint}
          style={{ userSelect: "none" }}
        >
          {[node.file, node.line ? `L${node.line}` : null].filter(Boolean).join(" · ")}
        </text>
      )}
    </g>
  );
}

// ─── Edge ─────────────────────────────────────────────────────────────────────
function Edge({ link, positions, pathEdgeSet }) {
  const srcId = link.source?.id ?? link.source;
  const tgtId = link.target?.id ?? link.target;

  const a = positions[srcId];
  const b = positions[tgtId];
  if (!a || !b || srcId === tgtId) return null;

  const edgeKey  = `${srcId}->${tgtId}`;
  const isOnPath = pathEdgeSet.has(edgeKey);
  const color    = edgeColor(link, isOnPath);
  const dash     = edgeDash(link, isOnPath);
  const width    = isOnPath ? 2.4 : link.on_attack_path ? 1.8 : 1.2;
  const d        = manhattanPath(a.x, a.y, b.x, b.y);

  return (
    <path
      d={d}
      fill="none"
      stroke={color}
      strokeWidth={width}
      strokeDasharray={dash}
      opacity={isOnPath ? 0.95 : link.on_attack_path ? 0.8 : 0.45}
      markerEnd="url(#arrow)"
      style={isOnPath ? { animation: "sch-pulse 1.8s ease-in-out infinite" } : undefined}
    />
  );
}

// ─── Legend ──────────────────────────────────────────────────────────────────
function SchematicLegend() {
  const items = [
    { color: T.trace,   label: "Source · entry point" },
    { color: T.danger,  label: "Sink · dangerous op"  },
    { color: T.guard,   label: "Sanitizer / filter"   },
    { color: T.warn,    label: "Intermediate / tainted"},
    { color: T.inkDim,  label: "Normal · logic"       },
    { color: T.patched, label: "Patched node"          },
  ];
  return (
    <div
      style={{
        position: "absolute",
        bottom: 20,
        left: 20,
        background: "rgba(15,37,48,0.96)",
        border: `1px solid ${T.border}`,
        padding: "10px 14px",
        fontSize: 11,
        zIndex: 10,
        pointerEvents: "none",
      }}
    >
      <div style={{
        fontFamily: "'IBM Plex Mono', monospace",
        fontSize: 9, letterSpacing: 1.5, color: T.inkFaint,
        marginBottom: 8, textTransform: "uppercase",
      }}>
        Schematic Key
      </div>
      {items.map(({ color, label }) => (
        <div key={label} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5 }}>
          <span style={{ width: 10, height: 10, background: color, flexShrink: 0, borderRadius: 1 }} />
          <span style={{ color: T.inkDim, fontFamily: "'IBM Plex Mono', monospace", fontSize: 11 }}>
            {label}
          </span>
        </div>
      ))}
      <div style={{
        borderTop: `1px solid ${T.borderSoft}`, marginTop: 8, paddingTop: 8,
        color: T.inkFaint, fontFamily: "'IBM Plex Mono', monospace",
        fontSize: 9, textTransform: "uppercase", letterSpacing: 1,
      }}>
        Trace opacity = confidence
      </div>
    </div>
  );
}

// ─── Empty state ──────────────────────────────────────────────────────────────
function EmptyState() {
  return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center",
      justifyContent: "center", height: "100%",
      color: T.inkFaint, fontFamily: "'IBM Plex Mono', monospace", gap: 12,
    }}>
      <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
        <rect x="4" y="16" width="40" height="16" rx="3" stroke={T.inkFaint} strokeWidth="1.5" />
        <line x1="0" y1="24" x2="4" y2="24" stroke={T.inkFaint} strokeWidth="1.5" />
        <line x1="44" y1="24" x2="48" y2="24" stroke={T.inkFaint} strokeWidth="1.5" />
        <circle cx="24" cy="24" r="3" fill={T.inkFaint} opacity="0.4" />
      </svg>
      <span style={{ fontSize: 12, letterSpacing: 1, textTransform: "uppercase" }}>No graph data</span>
      <span style={{ fontSize: 10, opacity: 0.6 }}>Scan a project to populate the schematic</span>
    </div>
  );
}

// ─── SchematicView ────────────────────────────────────────────────────────────
/**
 * 2D PCB schematic renderer — scrollable canvas.
 *
 * Props:
 *   graph       : { nodes: [], links: [] }
 *   path        : string[]               — highlighted attack-path node IDs
 *   onNodeClick : (node) => void
 */
const SchematicView = ({ graph, path, onNodeClick }) => {
  const nodes = graph?.nodes || [];
  const links = graph?.links || [];

  const pathNodeSet = useMemo(() => new Set(path || []), [path]);
  const pathEdgeSet = useMemo(() => {
    const s = new Set();
    for (let i = 0; i < (path || []).length - 1; i++) {
      s.add(`${path[i]}->${path[i + 1]}`);
    }
    return s;
  }, [path]);

  // Layout + canvas size computed together, memoised on node/link count changes
  const { positions, canvasW, canvasH, numCols } = useMemo(
    () => computeLayout(nodes, links),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [nodes.length, links.length]
  );

  if (!nodes.length) {
    return (
      <div style={{ position: "relative", width: "100%", height: "100%", background: T.bg }}>
        <EmptyState />
      </div>
    );
  }

  return (
    /*
     * Outer wrapper: position:relative so the legend can be fixed to the
     * viewport corner of this container regardless of scroll position.
     */
    <div style={{ position: "relative", width: "100%", height: "100%" }}>
      <style>{`
        @keyframes sch-pulse { 0%,100%{opacity:0.95} 50%{opacity:0.38} }
        /* Custom scrollbar to match the dark theme */
        .vg-scroll::-webkit-scrollbar        { width: 8px; height: 8px; }
        .vg-scroll::-webkit-scrollbar-track  { background: #0B1D26; }
        .vg-scroll::-webkit-scrollbar-thumb  { background: #1C3D4B; border-radius: 4px; }
        .vg-scroll::-webkit-scrollbar-thumb:hover { background: #245257; }
      `}</style>

      {/*
       * Scrollable viewport — both axes.
       * The SVG inside is sized to its real pixel dimensions so nodes are
       * laid out with full breathing room.
       */}
      <div
        className="vg-scroll"
        style={{
          width: "100%",
          height: "100%",
          overflow: "auto",
          background: T.bg,
        }}
      >
        <svg
          width={canvasW}
          height={canvasH}
          xmlns="http://www.w3.org/2000/svg"
          style={{ display: "block" }}
        >
          <defs>
            {/* Blueprint dot-grid pattern */}
            <pattern id="dot-grid" x="0" y="0" width="24" height="24" patternUnits="userSpaceOnUse">
              <circle cx="12" cy="12" r="1" fill={T.dotGrid} opacity="0.7" />
            </pattern>

            {/* Arrowhead marker */}
            <marker
              id="arrow"
              viewBox="0 0 10 10" refX="9" refY="5"
              markerWidth="5" markerHeight="5"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 9 5 L 0 9 z" fill={T.inkFaint} opacity="0.75" />
            </marker>
          </defs>

          {/* Background */}
          <rect width={canvasW} height={canvasH} fill={T.bg} />
          <rect width={canvasW} height={canvasH} fill="url(#dot-grid)" />

          {/* Canvas header label */}
          <text
            x="24" y="32"
            fontFamily="'IBM Plex Mono', monospace"
            fontSize={10} fill={T.inkFaint} letterSpacing={1.5}
          >
            SCHEMATIC · TAINT FLOW · 2D
          </text>
          <text
            x="24" y="46"
            fontFamily="'IBM Plex Mono', monospace"
            fontSize={8.5} fill={T.inkFaint} letterSpacing={1} opacity={0.6}
          >
            {nodes.length} NODES · {links.length} EDGES
          </text>

          {/* Column rail guides — one per depth level */}
          {Array.from({ length: numCols }, (_, i) => {
            const cx = PAD_LEFT + i * COL_SPACING;
            return (
              <line
                key={i}
                x1={cx} y1={PAD_TOP - 20}
                x2={cx} y2={canvasH - PAD_BOTTOM + 20}
                stroke={T.border}
                strokeWidth={1}
                strokeDasharray="2 6"
                opacity={0.25}
              />
            );
          })}

          {/* ── Edges (behind nodes) ───────────────────────────────────────── */}
          {links.map((link, i) => (
            <Edge
              key={i}
              link={link}
              positions={positions}
              pathEdgeSet={pathEdgeSet}
            />
          ))}

          {/* ── Nodes ─────────────────────────────────────────────────────── */}
          {nodes.map((node) => {
            const pos = positions[node.id];
            if (!pos) return null;
            return (
              <Chip
                key={node.id}
                node={node}
                pos={pos}
                isSelected={pathNodeSet.has(node.id)}
                isOnPath={pathNodeSet.has(node.id)}
                onNodeClick={onNodeClick}
              />
            );
          })}
        </svg>
      </div>

      {/* Legend stays fixed at the bottom-left of the container viewport */}
      <SchematicLegend />
    </div>
  );
};

export default SchematicView;
