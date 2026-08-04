import { useEffect, useState } from "react";
import useStore from "../store/useStore";
import { API_BASE } from "../api";

const MetricsBar = ({ onScan, attackPaths = [], highlightedPathIndex, onHighlightPath }) => {
  const graph = useStore((state) => state.graph);
  const loading = useStore((state) => state.loading);

  // Zustand Layer and Diff states
  const activeLayer = useStore((state) => state.activeLayer);
  const setActiveLayer = useStore((state) => state.setActiveLayer);
  const diffMode = useStore((state) => state.diffMode);
  const setDiffMode = useStore((state) => state.setDiffMode);

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
    criticalSinks: 0,
    guardCoverage: 0,
    overallRisk: "LOW",
    time: null,
  });

  useEffect(() => {
    if (graph && graph.nodes) {
      const nodes = graph.nodes;
      const sources = nodes.filter((n) => n.type === "source").length;
      const sinks = nodes.filter((n) => n.type === "sink").length;
      const criticalSinks = nodes.filter((n) => n.type === "sink" && (n.risk === "CRITICAL" || n.risk === "HIGH")).length;
      const patched = nodes.filter((n) => n.patched).length;
      const guards = nodes.filter((n) => n.type === "sanitizer").length;

      // Calculate Guard Coverage Percentage
      const totalSinksAndIntermediate = nodes.filter(n => n.type === "sink" || n.type === "intermediate").length;
      const guardCoverage = totalSinksAndIntermediate > 0
        ? Math.round((guards / totalSinksAndIntermediate) * 100)
        : 0;

      // Overall risk level calculation
      let overallRisk = "LOW";
      if (criticalSinks > 3) overallRisk = "CRITICAL";
      else if (criticalSinks > 0 || sinks > 5) overallRisk = "HIGH";
      else if (sinks > 2) overallRisk = "MEDIUM";

      setMetrics((prev) => ({
        nodes: nodes.length,
        edges: graph.links ? graph.links.length : 0,
        sources,
        sinks,
        patched,
        criticalSinks,
        guardCoverage,
        overallRisk,
        time: (prev.nodes !== nodes.length || !prev.time) ? new Date().toLocaleTimeString() : prev.time,
      }));
    }
  }, [graph]);

  // Handle timeline scrubber scrub (Modification 10)
  const handleTimelineScrub = (e) => {
    const value = parseInt(e.target.value, 10);
    if (value === -1) {
      onHighlightPath(null); // No path highlighted
    } else if (attackPaths.length > 0) {
      const idx = Math.min(value, attackPaths.length - 1);
      onHighlightPath(idx);
    }
  };

  const getRiskColor = (risk) => {
    if (risk === "CRITICAL") return "var(--color-critical)";
    if (risk === "HIGH") return "var(--color-high)";
    if (risk === "MEDIUM") return "var(--color-medium)";
    return "var(--color-low)";
  };

  if (!graph || !graph.nodes || graph.nodes.length === 0) {
    return null;
  }

  // Define layers for Modification 12
  const layers = [
    { id: "all", label: "Global Topology" },
    { id: "ast", label: "AST Graph" },
    { id: "callgraph", label: "Call Graph" },
    { id: "reachability", label: "Reachability Mode" },
    { id: "differential", label: "Differential Mode" }
  ];

  return (
    <div className="dashboard-metrics-container">
      {/* Modification 16: Modern Metric Dashboard Cards */}
      <div className="metrics-row">

        {/* Metric 1: Overall Risk */}
        <div className="metric-card">
          <div className="metric-card-label">
            Overall Risk
          </div>
          <div className="metric-card-content">
            <span className="metric-card-value" style={{ color: getRiskColor(metrics.overallRisk) }}>
              {metrics.overallRisk}
            </span>
            <span className="metric-card-label">Risk Profile</span>
            <span className="metric-card-trend trend-up">
              {metrics.overallRisk === "CRITICAL" || metrics.overallRisk === "HIGH" ? "▲ HIGH SEV" : "▼ STABLE"}
            </span>
          </div>
        </div>

        {/* Metric 2: Reachable Sinks */}
        <div className="metric-card">

          <div className="metric-card-content">
            <span className="metric-card-value">{metrics.sinks}</span>
            <span className="metric-card-label">Reachable Sinks</span>
            <span className="metric-card-trend trend-up">
              {metrics.criticalSinks} Critical
            </span>
          </div>
        </div>

        {/* Metric 3: Guard Coverage */}
        <div className="metric-card">

          <div className="metric-card-content">
            <span className="metric-card-value">{metrics.guardCoverage}%</span>
            <span className="metric-card-label">Guard Coverage</span>
            <span className="metric-card-trend trend-down">
              {metrics.guardCoverage < 50 ? "▲ VULNERABLE" : "▼ PROTECTED"}
            </span>
          </div>
        </div>

        {/* Metric 4: Attack Paths */}
        <div className="metric-card">

          <div className="metric-card-content">
            <span className="metric-card-value">{attackPaths.length}</span>
            <span className="metric-card-label">Attack Vectors</span>
            <span className="metric-card-trend trend-neutral">
              Active Flows
            </span>
          </div>
        </div>

        {/* Metric 5: Patched Nodes */}
        <div className="metric-card">

          <div className="metric-card-content">
            <span className="metric-card-value">{metrics.patched}</span>
            <span className="metric-card-label">Neutralized Sinks</span>
            <span className="metric-card-trend trend-down">
              {metrics.patched > 0 ? `+${metrics.patched} patches` : "0 Patched"}
            </span>
          </div>
        </div>

      </div>

      {/* Action panel row: Toggles & Timeline */}
      <div className="metrics-action-row">

        {/* Layer Selection Toggle (Modification 12) */}
        <div className="layer-toggles-container">
          {layers.map((layer) => (
            <button
              key={layer.id}
              className={`layer-toggle-btn ${activeLayer === layer.id ? "active" : ""}`}
              onClick={() => {
                setActiveLayer(layer.id);
                // Also toggle differential mode if layer is differential (Modification 7)
                setDiffMode(layer.id === "differential");
              }}
            >
              {layer.label}
            </button>
          ))}
        </div>

        {/* Upload & Reports actions */}
        <div className="action-buttons-wrap">
          <button className="cyber-button green" onClick={onScan}>
            Scan New Codebase
          </button>
          <button className="cyber-button" onClick={() => downloadReport("html")}>
            HTML Report
          </button>
          <button className="cyber-button" onClick={() => downloadReport("json")}>
            JSON Export
          </button>
        </div>

      </div>

      {/* Commit Timeline Scrubber (Modification 10) */}
      <div className="timeline-slider-wrapper">
        <div className="timeline-info-row">
          <span className="timeline-title">Attack Path / Commit Scrubber</span>
          <span className="timeline-details">
            {highlightedPathIndex !== null && attackPaths[highlightedPathIndex]
              ? `Path ${highlightedPathIndex + 1} of ${attackPaths.length} | Severity: ${attackPaths[highlightedPathIndex].classification || attackPaths[highlightedPathIndex].risk || "HIGH"}`
              : "Overview Mode (Scrub to traverse pathways)"}
          </span>
        </div>
        <div className="timeline-input-row">
          <input
            type="range"
            min="-1"
            max={attackPaths.length - 1}
            value={highlightedPathIndex !== null ? highlightedPathIndex : -1}
            onChange={handleTimelineScrub}
            className="timeline-range-input"
          />
          <span className="timeline-step-indicator">
            {highlightedPathIndex !== null ? `Vector #${highlightedPathIndex + 1}` : "NONE SELECTED"}
          </span>
        </div>
      </div>

    </div>
  );
};

export default MetricsBar;
