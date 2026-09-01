import { useState } from "react";
import useStore from "../../store/useStore";

// Default visibility state for all filter types
const DEFAULT_NODE_FILTERS = {
  source:    true,
  sink:      true,
  sanitizer: true,
  normal:    true,
};

const DEFAULT_EDGE_FILTERS = {
  call:              true,
  cross_file_call:   true,
  reaching_def_flow: true,
  dataflow:          true,
  same_file_call:    true,
  extends:           true,
  implements:        true,
  imports:           true,
};

const NODE_TYPE_META = [
  { key: "source",    label: "Entry / Source", color: "#10B981", icon: "⬤" },
  { key: "sink",      label: "Sink",            color: "#EF4444", icon: "⬤" },
  { key: "sanitizer", label: "Guard / Filter",  color: "#8B5CF6", icon: "⬤" },
  { key: "normal",    label: "Method / Normal", color: "#3B82F6", icon: "⬤" },
];

const EDGE_TYPE_META = [
  { key: "call",              label: "Calls",            color: "#3B82F6" },
  { key: "cross_file_call",   label: "Cross-file Call",  color: "#06B6D4" },
  { key: "reaching_def_flow", label: "Taint Flow",       color: "#8B5CF6" },
  { key: "dataflow",          label: "Data Flow",        color: "#06B6D4" },
  { key: "same_file_call",    label: "Same-file Call",   color: "#6B7280" },
  { key: "extends",           label: "Extends",          color: "#F59E0B" },
  { key: "implements",        label: "Implements",       color: "#EC4899" },
  { key: "imports",           label: "Imports",          color: "#6B7280" },
];

const FOCUS_HOPS = [
  { label: "All", value: null },
  { label: "1 hop", value: 1 },
  { label: "2 hops", value: 2 },
  { label: "3 hops", value: 3 },
  { label: "5 hops", value: 5 },
];

export default function ExplorerPanel({ collapsed, onToggle }) {
  const [nodeFilters, setNodeFilters]   = useState(DEFAULT_NODE_FILTERS);
  const [edgeFilters, setEdgeFilters]   = useState(DEFAULT_EDGE_FILTERS);
  const [focusHops,   setFocusHops]     = useState(null);
  const [activeTab,   setActiveTab]     = useState("filters"); // "explorer" | "filters"

  const setNodeVisibility = useStore(s => s.setNodeVisibility);
  const setEdgeVisibility = useStore(s => s.setEdgeVisibility);
  const setFocusDepth     = useStore(s => s.setFocusDepth);
  const graph             = useStore(s => s.graph);
  const selectedNode      = useStore(s => s.selectedNode);

  const toggleNode = (key) => {
    const next = { ...nodeFilters, [key]: !nodeFilters[key] };
    setNodeFilters(next);
    setNodeVisibility(next);
  };

  const toggleEdge = (key) => {
    const next = { ...edgeFilters, [key]: !edgeFilters[key] };
    setEdgeFilters(next);
    setEdgeVisibility(next);
  };

  const handleFocusHop = (val) => {
    setFocusHops(val);
    setFocusDepth(val);
  };

  // Count nodes by type for the explorer tab
  const nodes = graph?.nodes || [];
  const nodeCounts = NODE_TYPE_META.reduce((acc, m) => {
    acc[m.key] = nodes.filter(n =>
      String(n.type||'').toLowerCase() === m.key ||
      (m.key === 'source' && String(n.type||'').toLowerCase() === 'source')
    ).length;
    return acc;
  }, {});

  const S = {
    panel: {
      width: collapsed ? 0 : 220,
      minWidth: collapsed ? 0 : 220,
      height: "100%",
      background: "#0D1117",
      borderRight: "1px solid #21262D",
      display: "flex",
      flexDirection: "column",
      overflow: "hidden",
      transition: "width 0.2s ease, min-width 0.2s ease",
      flexShrink: 0,
    },
    header: {
      display: "flex",
      borderBottom: "1px solid #21262D",
      flexShrink: 0,
    },
    tab: (active) => ({
      flex: 1,
      padding: "10px 0",
      textAlign: "center",
      fontSize: 12,
      fontWeight: active ? 600 : 400,
      color: active ? "#E6EDF3" : "#6E7681",
      cursor: "pointer",
      background: "none",
      border: "none",
      borderBottom: active ? "2px solid #58A6FF" : "2px solid transparent",
    }),
    body:      { flex: 1, overflowY: "auto", padding: "12px 10px" },
    section:   { marginBottom: 20 },
    secTitle:  { fontSize: 10, fontWeight: 600, color: "#6E7681",
                  textTransform: "uppercase", letterSpacing: "0.08em",
                  marginBottom: 8 },
    secDesc:   { fontSize: 10, color: "#4B5563", marginBottom: 8, lineHeight: 1.5 },
    filterRow: (active) => ({
      display: "flex", alignItems: "center", gap: 8,
      padding: "5px 6px", borderRadius: 6, cursor: "pointer",
      background: active ? "rgba(88,166,255,0.06)" : "transparent",
      marginBottom: 2,
    }),
    dot:     (color) => ({
      width: 8, height: 8, borderRadius: "50%",
      background: color, flexShrink: 0,
    }),
    dash:    (color, active) => ({
      width: 20, height: 3,
      background: active ? color : "#374151",
      borderRadius: 2, flexShrink: 0,
      opacity: active ? 1 : 0.4,
    }),
    label:   (active) => ({
      fontSize: 12, color: active ? "#E6EDF3" : "#6E7681",
      flex: 1,
    }),
    count:   { fontSize: 10, color: "#4B5563" },
    toggle:  (active) => ({
      width: 10, height: 10, borderRadius: "50%",
      background: active ? "#58A6FF" : "#30363D",
      flexShrink: 0,
    }),
    hopRow:  { display: "flex", flexWrap: "wrap", gap: 4, marginTop: 6 },
    hopBtn:  (active) => ({
      padding: "3px 10px", borderRadius: 4, fontSize: 11,
      cursor: "pointer",
      background: active ? "#1F6FEB" : "#21262D",
      color: active ? "#fff" : "#8B949E",
      border: "1px solid " + (active ? "#1F6FEB" : "#30363D"),
    }),
    legend:  { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 },
    legItem: { display: "flex", alignItems: "center", gap: 5, fontSize: 11,
               color: "#8B949E" },
    collapseBtn: {
      position: "absolute",
      left: collapsed ? 4 : 212,
      top: "50%",
      transform: "translateY(-50%)",
      zIndex: 100,
      background: "#21262D",
      border: "1px solid #30363D",
      borderRadius: 4,
      color: "#8B949E",
      cursor: "pointer",
      padding: "2px 5px",
      fontSize: 11,
      transition: "left 0.2s ease",
    },
  };

  return (
    <div style={{ position: "relative", display: "flex", flexShrink: 0 }}>
      <button style={S.collapseBtn} onClick={onToggle} title={collapsed ? "Expand" : "Collapse"}>
        {collapsed ? "›" : "‹"}
      </button>
      <div style={S.panel}>
        {/* Tab header */}
        <div style={S.header}>
          <button style={S.tab(activeTab === "explorer")}
                  onClick={() => setActiveTab("explorer")}>Explorer</button>
          <button style={S.tab(activeTab === "filters")}
                  onClick={() => setActiveTab("filters")}>Filters</button>
        </div>

        <div style={S.body}>

          {/* ── EXPLORER TAB ── */}
          {activeTab === "explorer" && (
            <>
              <div style={S.section}>
                <div style={S.secTitle}>Node counts</div>
                {NODE_TYPE_META.map(m => (
                  <div key={m.key} style={S.filterRow(true)}>
                    <div style={S.dot(m.color)} />
                    <span style={S.label(true)}>{m.label}</span>
                    <span style={S.count}>{nodeCounts[m.key] || 0}</span>
                  </div>
                ))}
              </div>
              <div style={S.section}>
                <div style={S.secTitle}>Selected node</div>
                {selectedNode ? (
                  <div style={{ fontSize: 12, color: "#8B949E", lineHeight: 1.6 }}>
                    <div style={{ color: "#E6EDF3", marginBottom: 2 }}>
                      {selectedNode.label || selectedNode.id}
                    </div>
                    <div>Type: {selectedNode.type}</div>
                    <div>File: {selectedNode.file?.split('/').pop() || '—'}</div>
                    <div>Line: {selectedNode.line || '—'}</div>
                    {selectedNode.cwe && <div>CWE: {selectedNode.cwe}</div>}
                    {selectedNode.residual_risk != null &&
                      <div>Risk: {selectedNode.residual_risk.toFixed(3)}</div>}
                  </div>
                ) : (
                  <div style={{ fontSize: 11, color: "#4B5563" }}>Click a node in the graph</div>
                )}
              </div>
            </>
          )}

          {/* ── FILTERS TAB ── */}
          {activeTab === "filters" && (
            <>
              {/* Node types */}
              <div style={S.section}>
                <div style={S.secTitle}>Node types</div>
                <div style={S.secDesc}>Toggle visibility of node types in the graph</div>
                {NODE_TYPE_META.map(m => (
                  <div key={m.key} style={S.filterRow(nodeFilters[m.key])}
                       onClick={() => toggleNode(m.key)}>
                    <div style={S.dot(nodeFilters[m.key] ? m.color : "#374151")} />
                    <span style={S.label(nodeFilters[m.key])}>{m.label}</span>
                    <div style={S.toggle(nodeFilters[m.key])} />
                  </div>
                ))}
              </div>

              {/* Edge types */}
              <div style={S.section}>
                <div style={S.secTitle}>Edge types</div>
                <div style={S.secDesc}>Toggle visibility of relationship types</div>
                {EDGE_TYPE_META.map(m => (
                  <div key={m.key} style={S.filterRow(edgeFilters[m.key])}
                       onClick={() => toggleEdge(m.key)}>
                    <div style={S.dash(m.color, edgeFilters[m.key])} />
                    <span style={S.label(edgeFilters[m.key])}>{m.label}</span>
                    <div style={S.toggle(edgeFilters[m.key])} />
                  </div>
                ))}
              </div>

              {/* Focus depth */}
              <div style={S.section}>
                <div style={S.secTitle}>Focus depth</div>
                <div style={S.secDesc}>Show nodes within N hops of selection</div>
                <div style={S.hopRow}>
                  {FOCUS_HOPS.map(h => (
                    <button key={h.label} style={S.hopBtn(focusHops === h.value)}
                            onClick={() => handleFocusHop(h.value)}>
                      {h.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Color legend */}
              <div style={S.section}>
                <div style={S.secTitle}>Color legend</div>
                <div style={S.legend}>
                  {NODE_TYPE_META.map(m => (
                    <div key={m.key} style={S.legItem}>
                      <div style={{ ...S.dot(m.color) }} />
                      {m.label.split(" / ")[0]}
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
