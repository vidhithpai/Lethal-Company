import { useEffect, useState, useRef } from "react";
import useStore from "../../store/useStore";
import { API_BASE } from "../../services/api";

const MetricsBar = () => {
  const graph = useStore((state) => state.graph);
  const loading = useStore((state) => state.loading);
  const scanProgress = useStore((state) => state.scanProgress);
  const [ragStatus, setRagStatus] = useState("tfidf");
  const [exportMenuOpen, setExportMenuOpen] = useState(false);
  const [showScanComplete, setShowScanComplete] = useState(false);
  const dropdownRef = useRef(null);

  useEffect(() => {
    fetch(`${API_BASE}/api/query/rag-status`)
      .then(r => r.json())
      .then(d => setRagStatus(d.embed_mode))
      .catch(() => setRagStatus("tfidf"));
  }, []);

  // Handle scan completion state transition
  useEffect(() => {
    if (scanProgress?.status === "complete") {
      setShowScanComplete(true);
      const timer = setTimeout(() => {
        setShowScanComplete(false);
      }, 2500);
      return () => clearTimeout(timer);
    } else if (scanProgress?.status === "scanning") {
      setShowScanComplete(false);
    }
  }, [scanProgress?.status]);

  // Click outside and Escape key listener for export dropdown
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setExportMenuOpen(false);
      }
    };
    const handleKeyDown = (event) => {
      if (event.key === "Escape") {
        setExportMenuOpen(false);
      }
    };

    if (exportMenuOpen) {
      document.addEventListener("mousedown", handleClickOutside);
      document.addEventListener("keydown", handleKeyDown);
    }
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [exportMenuOpen]);

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

  const isScanning = scanProgress?.status === "scanning" || (loading && scanProgress?.status !== "complete");

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

      {/* ── STATUS & SCAN PROGRESS INDICATOR ──────────────────────────────── */}
      <div className="cmd-status-wrap">
        {isScanning ? (
          <div className="scan-progress-widget">
            <div className="scan-progress-top">
              <span className="scan-progress-label">
                <span className="pulse-dot-cyan" /> SCANNING PROJECT
              </span>
              <span className="scan-progress-pct">{scanProgress?.percent || 0}%</span>
            </div>
            <div className="scan-progress-track">
              <div
                className="scan-progress-fill"
                style={{ width: `${Math.max(3, scanProgress?.percent || 0)}%` }}
              />
            </div>
            <div className="scan-progress-file" title={scanProgress?.currentFile || "Analyzing..."}>
              {scanProgress?.currentFile ? `Analyzing: ${scanProgress.currentFile}` : "Analyzing repository files..."}
            </div>
          </div>
        ) : showScanComplete ? (
          <div className="scan-progress-widget complete">
            <div className="scan-progress-top">
              <span className="scan-progress-label complete">
                <span className="pulse-dot-green" /> SCAN COMPLETE
              </span>
              <span className="scan-progress-pct complete">100%</span>
            </div>
            <div className="scan-progress-track">
              <div className="scan-progress-fill complete" style={{ width: "100%" }} />
            </div>
            <div className="scan-progress-file">
              Scan complete · Ready
            </div>
          </div>
        ) : (
          <span className="cmd-status-badge live">
            <span className="pulse-dot-green" /> LIVE GRAPH
          </span>
        )}

        <span style={{ fontSize: 9, color: "#3FB950", whiteSpace: "nowrap" }}>
          {ragStatus === "graphcodebert" ? "🔬 GraphCodeBERT"
           : ragStatus === "minilm" ? "📋 MiniLM"
           : "📄 Rule-based"} RAG
        </span>
        <span className="cmd-time-stamp">Last update: {metrics.time || "10:01:56 PM"}</span>
      </div>

      {/* ── RIGHT — ACTION BUTTONS (Single Export Report dropdown) ────────── */}
      <div className="command-actions">
        <div className="export-dropdown-container" ref={dropdownRef}>
          <button
            type="button"
            className="cmd-btn btn-secondary export-trigger-btn"
            onClick={() => setExportMenuOpen(prev => !prev)}
            aria-expanded={exportMenuOpen}
            aria-haspopup="true"
            title="Export Security Analysis Report"
          >
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="7 10 12 15 17 10" />
              <line x1="12" y1="15" x2="12" y2="3" />
            </svg>
            <span>Export Report</span>
            <svg
              viewBox="0 0 24 24"
              width="10"
              height="10"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.2"
              strokeLinecap="round"
              strokeLinejoin="round"
              style={{
                transform: exportMenuOpen ? "rotate(180deg)" : "rotate(0deg)",
                transition: "transform 0.2s ease"
              }}
            >
              <polyline points="6 9 12 15 18 9" />
            </svg>
          </button>

          {exportMenuOpen && (
            <div className="export-menu-dropdown" role="menu">
              <button
                type="button"
                className="export-menu-item"
                role="menuitem"
                onClick={() => {
                  downloadReport("html");
                  setExportMenuOpen(false);
                }}
              >
                <span className="export-menu-icon">📄</span>
                <div className="export-menu-details">
                  <span className="export-menu-title">HTML Report</span>
                  <span className="export-menu-desc">Interactive standalone report</span>
                </div>
              </button>

              <button
                type="button"
                className="export-menu-item"
                role="menuitem"
                onClick={() => {
                  downloadReport("json");
                  setExportMenuOpen(false);
                }}
              >
                <span className="export-menu-icon">💾</span>
                <div className="export-menu-details">
                  <span className="export-menu-title">JSON Report</span>
                  <span className="export-menu-desc">Raw security graph & findings</span>
                </div>
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};

export default MetricsBar;
