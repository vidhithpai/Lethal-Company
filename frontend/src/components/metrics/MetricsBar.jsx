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
    time: "10:01:56 PM",
  });

  useEffect(() => {
    if (graph && graph.nodes) {
      const nodes = graph.nodes;
      const sources = nodes.filter((n) => String(n.type).toLowerCase() === "source").length;
      const sinks = nodes.filter((n) => String(n.type).toLowerCase() === "sink").length;
      const patched = nodes.filter((n) => n.patched).length;

      setMetrics((prev) => ({
        nodes: nodes.length,
        edges: graph.links ? graph.links.length : 0,
        sources,
        sinks,
        patched,
        time: (prev.nodes !== nodes.length || !prev.time) ? new Date().toLocaleTimeString() : prev.time,
      }));
    }
  }, [graph]);

  return (
    <header className="security-command-header">
      {/* ── LEFT SIDE — BRAND ────────────────────────────────────────────── */}
      <div className="command-brand">
        <span className="brand-shield-icon">🛡️</span>
        <div className="brand-title-wrap">
          <div className="brand-header-row">
            <span className="brand-title">VULNGRAPH</span>
          </div>
          <span className="brand-sub-label">SECURITY ANALYSIS</span>
        </div>
      </div>

      <div className="command-divider" />

      {/* ── CENTER — SECURITY METRICS HIERARCHY ────────────────────────────── */}
      <div className="command-metrics-strip">
        <div className="cmd-metric-item">
          <span className="cmd-metric-val nodes">{metrics.nodes || 0}</span>
          <span className="cmd-metric-lbl">NODES</span>
        </div>

        <div className="cmd-metric-item">
          <span className="cmd-metric-val flow">{metrics.edges || 0}</span>
          <span className="cmd-metric-lbl">DATA FLOWS</span>
        </div>

        <div className="cmd-metric-item">
          <span className="cmd-metric-val source">{metrics.sources || 0}</span>
          <span className="cmd-metric-lbl">SOURCES</span>
        </div>

        <div className="cmd-metric-item">
          <span className="cmd-metric-val sink">{metrics.sinks || 0}</span>
          <span className="cmd-metric-lbl">SINKS</span>
        </div>

        <div className="cmd-metric-item">
          <span className="cmd-metric-val patched">{metrics.patched || 0}</span>
          <span className="cmd-metric-lbl">PATCHED</span>
        </div>
      </div>

      <div className="command-divider" />

      {/* ── STATUS INDICATOR ─────────────────────────────────────────────── */}
      <div className="cmd-status-wrap">
        {loading ? (
          <span className="cmd-status-badge scanning">
            <span className="pulse-dot-cyan" /> SCANNING...
          </span>
        ) : (
          <span className="cmd-status-badge live">
            <span className="pulse-dot-green" /> LIVE GRAPH
          </span>
        )}
        <span className="cmd-time-stamp">Last update: {metrics.time || "10:01:56 PM"}</span>
      </div>

      {/* ── RIGHT — ACTION BUTTONS ───────────────────────────────────────── */}
      <div className="command-actions">
        <button className="cmd-btn btn-primary" onClick={onScan}>
          ⚡ Scan New Project
        </button>

        <button className="cmd-btn btn-secondary" onClick={() => downloadReport("html")}>
          📄 Download Report (HTML)
        </button>

        <button className="cmd-btn btn-tertiary" onClick={() => downloadReport("json")}>
          💾 Export JSON
        </button>
      </div>
    </header>
  );
};

export default MetricsBar;
