import { useMemo } from "react";

// ─── Palette ─────────────────────────────────────────────────────────────────
const T = {
  bg:         "#0B1D26",
  dotGrid:    "#1C3D4B",
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
const NW = 148;   // chip width
const NH = 44;    // chip height
const PIN_LEN = 12;

// ─── Type metadata ───────────────────────────────────────────────────────────
function typeMeta(type) {
  const t = String(type || "").toLowerCase();
  switch (t) {
    case "source":
      return { color: T.trace,   tag: "SRC", dash: "none",  opacity: 1 };
    case "sink":
      return { color: T.danger,  tag: "SINK", dash: "none", opacity: 1 };
    case "sanitizer":
      return { color: T.guard,   tag: "FLT",  dash: "5 3",  opacity: 1 };
    case "intermediate":
    case "function":
      return { color: T.warn,    tag: "INT",  dash: "none",  opacity: 0.9 };
    case "patched":
      return { color: T.patched, tag: "PAT",  dash: "3 3",  opacity: 0.52 };
    default:
      return { color: T.inkDim,  tag: "—",    dash: "none",  opacity: 0.8 };
  }
}

// ─── Edge colour ─────────────────────────────────────────────────────────────
function edgeColor(link, isOnPath) {
  if (link.patched)              return T.patched;
  if (isOnPath || link.on_attack_path) return T.danger;
  const t = String(link.type || "").toLowerCase();
  if (t === "sanitized")         return T.guard;
  return T.traceDim;
}

function edgeDash(link, isOnPath) {
  if (link.patched)              return "2 5";
  if (isOnPath || link.on_attack_path) return "none";
  const t = String(link.type || "").toLowerCase();
  if (t === "sanitized")         return "6 4";
  return "none";
}

// ─── Layout ──────────────────────────────────────────────────────────────────
/**
 * Simple layered column layout — no physics, no external lib.
 *
 * Columns (left → right):
 *   0 : source
 *   1 : function / intermediate  (first hop from source)
 *   2 : sanitizer + normal/function (second hop)
 *   3 : sink + patched
 *
 * Nodes that don't fit a type bucket go to column 1.
 */
function computeLayout(nodes, links, W, H) {
  const COLS = 4;
  const COL_X = [0.10, 0.33, 0.57, 0.80]; // fractional x centres
  const PAD_TOP = 60;

  // bucket
  const buckets = Array.from({ length: COLS }, () => []);

  nodes.forEach((n) => {
    const t = String(n.type || "").toLowerCase();
    if (t === "source") {
      buckets[0].push(n.id);
    } else if (t === "sink") {
      buckets[3].push(n.id);
    } else if (t === "patched") {
      buckets[3].push(n.id);
    } else if (t === "sanitizer") {
      buckets[2].push(n.id);
    } else if (t === "function" || t === "intermediate") {
      buckets[1].push(n.id);
    } else {
      // "normal" or unknown — distribute across middle cols by degree
      const degree = links.filter(
        (l) =>
          (l.source === n.id || l.source?.id === n.id) ||
          (l.target === n.id || l.target?.id === n.id)
      ).length;
      buckets[degree > 2 ? 1 : 2].push(n.id);
    }
  });

  const positions = {};
  buckets.forEach((ids, colIdx) => {
    const count = ids.length;
    const x = COL_X[colIdx] * W;
    ids.forEach((id, rowIdx) => {
      const slotH = (H - PAD_TOP) / Math.max(count, 1);
      const y = PAD_TOP + slotH * rowIdx + slotH / 2;
      positions[id] = { x, y };
    });
  });

  return positions;
}

// ─── Orthogonal (Manhattan) path ─────────────────────────────────────────────
function manhattanPath(ax, ay, bx, by) {
  // exit right → mid → enter left
  const ex = ax + NW / 2 + PIN_LEN;   // right pin exit
  const tx = bx - NW / 2 - PIN_LEN;  // left  pin entry

  // If source is right of target, curve back
  if (ex >= tx - 10) {
    const midX = Math.min(ax, bx) - 30;
    return `M ${ax + NW / 2} ${ay}
            H ${ex}
            V ${ay + (by > ay ? 30 : -30)}
            H ${midX}
            V ${by}
            H ${tx}
            H ${bx - NW / 2}`;
  }

  const midX = (ex + tx) / 2;
  return `M ${ax + NW / 2} ${ay}
          H ${midX}
          V ${by}
          H ${bx - NW / 2}`;
}

// ─── Chip component ──────────────────────────────────────────────────────────
function Chip({ node, pos, isSelected, isOnPath, onNodeClick }) {
  const m    = typeMeta(node.type);
  const x    = pos.x - NW / 2;
  const y    = pos.y - NH / 2;
  const cx   = pos.x;
  const cy   = pos.y;
  const isSink = String(node.type || "").toLowerCase() === "sink";
  const isSan  = String(node.type || "").toLowerCase() === "sanitizer";
  const isSrc  = String(node.type || "").toLowerCase() === "source";
  const isPat  = String(node.type || "").toLowerCase() === "patched";

  const filterId = `glow-${node.id}`;
  const raw      = node.label || node.id || "?";
  const labelStr = raw.length > 18 ? raw.slice(0, 17) + "…" : raw;

  const strokeColor = isSelected ? T.ink : m.color;
  const strokeW     = isSelected ? 2.2 : 1.4;

  return (
    <g
      style={{ cursor: "pointer", opacity: m.opacity }}
      onClick={() => onNodeClick && onNodeClick(node)}
    >
      {/* Glow filter definition for sinks */}
      {isSink && (
        <defs>
          <filter id={filterId} x="-70%" y="-70%" width="240%" height="240%">
            <feGaussianBlur stdDeviation="7" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
      )}

      {/* Attack-path halo */}
      {isOnPath && !isPat && (
        <rect
          x={x - 4} y={y - 4}
          width={NW + 8} height={NH + 8}
          rx={7}
          fill="none"
          stroke={isSink ? T.danger : T.trace}
          strokeWidth={1.5}
          opacity={0.45}
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
          stroke={strokeColor}
          strokeWidth={strokeW}
          strokeDasharray={isSelected ? "none" : m.dash}
        />

        {/* Left accent bar */}
        <rect
          x={x} y={y}
          width={6} height={NH}
          rx="2 0 0 2"
          fill={m.color}
          opacity={isPat ? 0.38 : 0.88}
        />

        {/* Sanitizer notch overlay — small triangle cut on bar */}
        {isSan && (
          <polygon
            points={`${x},${y + NH / 2 - 7} ${x + 6},${y + NH / 2} ${x},${y + NH / 2 + 7}`}
            fill={T.panel}
            opacity={0.9}
          />
        )}

        {/* Source left-entry connector mark */}
        {isSrc && (
          <>
            <rect
              x={x - 14} y={cy - 5}
              width={8} height={10}
              rx={1}
              fill="none"
              stroke={T.trace}
              strokeWidth={1}
              opacity={0.7}
            />
            <line
              x1={x - 6} y1={cy}
              x2={x}     y2={cy}
              stroke={T.trace}
              strokeWidth={1}
              opacity={0.7}
            />
          </>
        )}
      </g>

      {/* Left pin nub */}
      <line
        x1={x - PIN_LEN} y1={cy}
        x2={x}            y2={cy}
        stroke={m.color}
        strokeWidth={1.2}
        opacity={0.6}
      />
      {/* Right pin nub */}
      <line
        x1={x + NW}           y1={cy}
        x2={x + NW + PIN_LEN} y2={cy}
        stroke={m.color}
        strokeWidth={1.2}
        opacity={0.6}
      />

      {/* Type tag — above chip */}
      <text
        x={x + 10}
        y={y - 5}
        fontFamily="'IBM Plex Mono', monospace"
        fontSize={8}
        fill={m.color}
        letterSpacing={1.2}
        opacity={0.9}
      >
        {m.tag}
      </text>

      {/* Main label */}
      <text
        x={cx + 4}
        y={cy + 4}
        textAnchor="middle"
        fontFamily="'IBM Plex Mono', monospace"
        fontSize={10.5}
        fill={isPat ? T.inkFaint : T.ink}
        style={{ textDecoration: isPat ? "line-through" : "none", userSelect: "none" }}
      >
        {labelStr}
      </text>

      {/* File / line sub-label */}
      {(node.file || node.line) && (
        <text
          x={cx + 4}
          y={cy + 16}
          textAnchor="middle"
          fontFamily="'IBM Plex Mono', monospace"
          fontSize={8}
          fill={T.inkFaint}
          style={{ userSelect: "none" }}
        >
          {[node.file, node.line ? `L${node.line}` : null].filter(Boolean).join(" · ")}
        </text>
      )}
    </g>
  );
}

// ─── Edge component ──────────────────────────────────────────────────────────
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
  const width    = isOnPath ? 2.2 : link.on_attack_path ? 1.8 : 1.2;
  const d        = manhattanPath(a.x, a.y, b.x, b.y);

  return (
    <path
      d={d}
      fill="none"
      stroke={color}
      strokeWidth={width}
      strokeDasharray={dash}
      opacity={isOnPath ? 1 : link.on_attack_path ? 0.85 : 0.5}
      markerEnd="url(#arrow)"
      style={
        isOnPath
          ? { animation: "sch-pulse 1.8s ease-in-out infinite" }
          : undefined
      }
    />
  );
}

// ─── Legend ──────────────────────────────────────────────────────────────────
function SchematicLegend() {
  const items = [
    { color: T.trace,   label: "Source · entry point" },
    { color: T.danger,  label: "Sink · dangerous op" },
    { color: T.guard,   label: "Sanitizer / filter" },
    { color: T.warn,    label: "Intermediate / tainted" },
    { color: T.inkDim,  label: "Normal · logic" },
    { color: T.patched, label: "Patched node" },
  ];
  return (
    <div
      style={{
        position: "absolute",
        bottom: 20,
        left: 20,
        background: "rgba(15,37,48,0.94)",
        border: `1px solid ${T.border}`,
        padding: "10px 14px",
        fontSize: 11,
        zIndex: 10,
      }}
    >
      <div
        style={{
          fontFamily: "'IBM Plex Mono', monospace",
          fontSize: 9,
          letterSpacing: 1.5,
          color: T.inkFaint,
          marginBottom: 8,
          textTransform: "uppercase",
        }}
      >
        Schematic Key
      </div>
      {items.map(({ color, label }) => (
        <div
          key={label}
          style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5 }}
        >
          <span
            style={{
              width: 10,
              height: 10,
              background: color,
              flexShrink: 0,
              borderRadius: 1,
            }}
          />
          <span
            style={{
              color: T.inkDim,
              fontFamily: "'IBM Plex Mono', monospace",
              fontSize: 11,
            }}
          >
            {label}
          </span>
        </div>
      ))}
      <div
        style={{
          borderTop: `1px solid ${T.borderSoft}`,
          marginTop: 8,
          paddingTop: 8,
          color: T.inkFaint,
          fontFamily: "'IBM Plex Mono', monospace",
          fontSize: 9,
          textTransform: "uppercase",
          letterSpacing: 1,
        }}
      >
        Trace opacity = confidence
      </div>
    </div>
  );
}

// ─── Empty / loading state ────────────────────────────────────────────────────
function EmptyState() {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        height: "100%",
        color: T.inkFaint,
        fontFamily: "'IBM Plex Mono', monospace",
        gap: 12,
      }}
    >
      <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
        <rect x="4" y="16" width="40" height="16" rx="3" stroke={T.inkFaint} strokeWidth="1.5" />
        <line x1="0" y1="24" x2="4" y2="24" stroke={T.inkFaint} strokeWidth="1.5" />
        <line x1="44" y1="24" x2="48" y2="24" stroke={T.inkFaint} strokeWidth="1.5" />
        <circle cx="24" cy="24" r="3" fill={T.inkFaint} opacity="0.4" />
      </svg>
      <span style={{ fontSize: 12, letterSpacing: 1, textTransform: "uppercase" }}>
        No graph data
      </span>
      <span style={{ fontSize: 10, opacity: 0.6 }}>
        Scan a project to populate the schematic
      </span>
    </div>
  );
}

// ─── SchematicView ────────────────────────────────────────────────────────────
/**
 * 2D PCB schematic renderer.
 *
 * Props:
 *   graph       : { nodes: [], links: [] }   — same shape as 3D view
 *   path        : string[]                   — ordered node IDs on highlighted path
 *   onNodeClick : (node) => void             — same callback as 3D view
 */
const SchematicView = ({ graph, path, onNodeClick }) => {
  const nodes = graph?.nodes || [];
  const links = graph?.links || [];

  // Build path sets for highlight
  const pathNodeSet = useMemo(() => new Set(path || []), [path]);
  const pathEdgeSet = useMemo(() => {
    const s = new Set();
    for (let i = 0; i < (path || []).length - 1; i++) {
      s.add(`${path[i]}->${path[i + 1]}`);
    }
    return s;
  }, [path]);

  // Dimensions — we work in a fixed 960×560 viewBox and let SVG scale
  const VW = 960;
  const VH = 560;

  // Compute layout positions (memoised; recomputes when nodes/links change)
  const positions = useMemo(
    () => computeLayout(nodes, links, VW, VH),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [nodes.length, links.length]
  );

  if (!nodes.length) return <EmptyState />;

  return (
    <div style={{ position: "relative", width: "100%", height: "100%" }}>
      <style>{`
        @keyframes sch-pulse { 0%,100%{opacity:1} 50%{opacity:0.45} }
        @keyframes sch-heat  { 0%,100%{opacity:1} 50%{opacity:0.65} }
      `}</style>

      {/* ── SVG canvas ─────────────────────────────────────────────────────── */}
      <svg
        viewBox={`0 0 ${VW} ${VH}`}
        style={{ width: "100%", height: "100%", display: "block" }}
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          {/* Blueprint dot-grid background pattern */}
          <pattern
            id="dot-grid"
            x="0" y="0"
            width="20" height="20"
            patternUnits="userSpaceOnUse"
          >
            <circle cx="10" cy="10" r="0.9" fill={T.dotGrid} />
          </pattern>

          {/* Arrow marker for edge ends */}
          <marker
            id="arrow"
            viewBox="0 0 8 8"
            refX="7" refY="4"
            markerWidth="6" markerHeight="6"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 8 4 L 0 8 z" fill={T.inkFaint} opacity="0.7" />
          </marker>
        </defs>

        {/* Background */}
        <rect width={VW} height={VH} fill={T.bg} />
        <rect width={VW} height={VH} fill="url(#dot-grid)" />

        {/* Canvas label */}
        <text
          x="20" y="26"
          fontFamily="'IBM Plex Mono', monospace"
          fontSize={9}
          fill={T.inkFaint}
          letterSpacing={1.5}
        >
          SCHEMATIC · TAINT FLOW · 2D
        </text>

        {/* ── Edges (drawn below nodes) ─────────────────────────────────── */}
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

      {/* ── Legend ──────────────────────────────────────────────────────── */}
      <SchematicLegend />
    </div>
  );
};

export default SchematicView;
