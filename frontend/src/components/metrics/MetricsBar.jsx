import { useEffect, useState } from "react";
import useStore from "../../store/useStore";
import { API_BASE } from "../../services/api";

const MetricsBar = ({ onScan }) => {
  const graph = useStore((state) => state.graph);
  const loading = useStore((state) => state.loading);

  const downloadReport = (format) => {
    const url = `${API_BASE}/api/report/${format}`;
    const link = document.createElement("a");
    link.href = url;
    link.download = `vulngraph_report.${format}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const [metrics, setMetrics] = useState({
    nodes: 0,
    edges: 0,
    sources: 0,
    sinks: 0,
    patched: 0,
    time: null,
  });

  useEffect(() => {
    if (graph && graph.nodes) {
      const nodes = graph.nodes;
      const sources = nodes.filter((n) => n.type === "source").length;
      const sinks = nodes.filter((n) => n.type === "sink").length;
      const patched = nodes.filter((n) => n.patched).length;

      setMetrics((prev) => ({
        nodes: nodes.length,
        edges: graph.links ? graph.links.length : 0,
        sources,
        sinks,
        patched,
        // Update time only if node count changed (simulate new scan) or if null
        time: (prev.nodes !== nodes.length || !prev.time) ? new Date().toLocaleTimeString() : prev.time,
      }));
    }
  }, [graph]);

  if (!graph || !graph.nodes || graph.nodes.length === 0) {
    return null;
  }

  return (
    <div className="metrics-bar">
      <div className="metric-item">
        <span className="metric-icon">🌐</span>
        <div className="metric-data">
          <span className="metric-value">{metrics.nodes}</span>
          <span className="metric-label">Nodes</span>
        </div>
      </div>
      <div className="metric-item">
        <span className="metric-icon">⚡</span>
        <div className="metric-data">
          <span className="metric-value">{metrics.edges}</span>
          <span className="metric-label">Data Flows</span>
        </div>
      </div>
      <div className="metric-item">
        <span className="metric-icon" style={{ color: "var(--color-source)" }}>📥</span>
        <div className="metric-data">
          <span className="metric-value" style={{ color: "var(--color-source)" }}>{metrics.sources}</span>
          <span className="metric-label">Sources</span>
        </div>
      </div>
      <div className="metric-item">
        <span className="metric-icon" style={{ color: "var(--color-sink)" }}>💥</span>
        <div className="metric-data">
          <span className="metric-value" style={{ color: "var(--color-sink)" }}>{metrics.sinks}</span>
          <span className="metric-label">Sinks</span>
        </div>
      </div>
      <div className="metric-item">
        <span className="metric-icon" style={{ color: "var(--accent-blue)" }}>🛡️</span>
        <div className="metric-data">
          <span className="metric-value" style={{ color: "var(--accent-blue)" }}>{metrics.patched}</span>
          <span className="metric-label">Patched</span>
        </div>
      </div>
      <div className="metric-divider" />
      <div className="metric-status">
        {loading ? (
          <span className="status-badge status-scanning">
            <span className="pulse-dot" /> Scanning...
          </span>
        ) : (
          <span className="status-badge status-live">
            ● Live Graph
            <span className="scan-time">Last update: {metrics.time}</span>
          </span>
        )}
      </div>
      <div style={{ display:"flex", gap:8, marginLeft: "auto" }}>
        <button
          onClick={onScan}
          style={{
            padding:"7px 14px", background:"#10B981",
            color:"#fff", border:"none", borderRadius:6,
            cursor:"pointer", fontSize:12, fontWeight:600,
            display: "flex", alignItems: "center", gap: "6px"
          }}>
          <span>⚡</span> Scan New Project
        </button>
        <button
          onClick={() => downloadReport("html")}
          style={{
            padding:"7px 14px", background:"#1D4ED8",
            color:"#fff", border:"none", borderRadius:6,
            cursor:"pointer", fontSize:12, fontWeight:500
          }}>
          Download report (HTML)
        </button>
        <button
          onClick={() => downloadReport("json")}
          style={{
            padding:"7px 14px", background:"#374151",
            color:"#fff", border:"none", borderRadius:6,
            cursor:"pointer", fontSize:12, fontWeight:500
          }}>
          Export JSON
        </button>
      </div>
    </div>
  );
};

export default MetricsBar;
