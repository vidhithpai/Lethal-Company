import { useEffect, useState } from "react";
import useStore from "../store/useStore";
import { endpoints } from "../api";

const RISK_COLORS = {
  critical: "#ff2d55",
  high:     "#ff6b35",
  medium:   "#f4c542",
  low:      "#2fd66f",
  HIGH:     "#ff6b35",
  MEDIUM:   "#f4c542",
  LOW:      "#2fd66f",
};

const TYPE_BADGES = {
  source:       { label: "SOURCE",    color: "#22c55e" },
  sink:         { label: "SINK",      color: "#ef4444" },
  intermediate: { label: "TAINT",     color: "#f59e0b" },
  function:     { label: "FUNC",      color: "#3b82f6" },
  sanitizer:    { label: "SANITIZER", color: "#a78bfa" },
};

const CWE_LINKS = {
  "CWE-89":  "https://cwe.mitre.org/data/definitions/89.html",
  "CWE-78":  "https://cwe.mitre.org/data/definitions/78.html",
  "CWE-22":  "https://cwe.mitre.org/data/definitions/22.html",
  "CWE-95":  "https://cwe.mitre.org/data/definitions/95.html",
  "CWE-502": "https://cwe.mitre.org/data/definitions/502.html",
  "CWE-73":  "https://cwe.mitre.org/data/definitions/73.html",
  "CWE-20":  "https://cwe.mitre.org/data/definitions/20.html",
};

// ─── Sub-component: structured vulnerability analysis card ───────────────────
const VulnAnalysisCard = ({ analysis, loading }) => {
  if (loading) {
    return (
      <div className="vuln-card vuln-loading">
        <span className="pulse-dot" /> Analyzing vulnerability…
      </div>
    );
  }
  if (!analysis) return null;

  const cweHref = CWE_LINKS[analysis.cwe];

  return (
    <div className="vuln-card">
      {/* Header row: vuln type + CWE badge */}
      <div className="vuln-header">
        <span className="vuln-type">{analysis.vuln_type}</span>
        {analysis.cwe && (
          cweHref
            ? <a className="cwe-badge" href={cweHref} target="_blank" rel="noreferrer">{analysis.cwe}</a>
            : <span className="cwe-badge">{analysis.cwe}</span>
        )}
      </div>

      {/* What can an attacker do */}
      <div className="vuln-block">
        <span className="vuln-label">⚠ Impact</span>
        <p className="vuln-text">{analysis.what_it_does}</p>
      </div>

      {/* Root cause */}
      <div className="vuln-block">
        <span className="vuln-label">🔬 Root Cause</span>
        <p className="vuln-text">{analysis.root_cause}</p>
      </div>

      {/* Fix */}
      <div className="vuln-block vuln-fix">
        <span className="vuln-label">✅ Fix</span>
        <p className="vuln-text">{analysis.fix}</p>
      </div>

      {/* Severity reason */}
      {analysis.severity_reason && (
        <div className="vuln-block">
          <span className="vuln-label">📊 Why this rating</span>
          <p className="vuln-text vuln-muted">{analysis.severity_reason}</p>
        </div>
      )}
    </div>
  );
};

// ─── Main SidePanel ───────────────────────────────────────────────────────────
const SidePanel = () => {
  const graph           = useStore((state) => state.graph);
  const path            = useStore((state) => state.path);
  const selectedNode    = useStore((state) => state.selectedNode);
  const explanation     = useStore((state) => state.explanation);
  const patchNodeLocal  = useStore((state) => state.patchNodeLocal);

  const [nodeAnalysis, setNodeAnalysis]   = useState(null);
  const [loadingAnalysis, setLoadingAnalysis] = useState(false);

  // Auto-fetch vulnerability analysis when a sink or source is selected
  useEffect(() => {
    if (!selectedNode || !["sink", "source"].includes(selectedNode.type)) {
      setNodeAnalysis(null);
      return;
    }

    let cancelled = false;
    setLoadingAnalysis(true);
    setNodeAnalysis(null);

    fetch(endpoints.explainNode, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        node_id:   selectedNode.id,
        label:     selectedNode.label,
        node_type: selectedNode.type,
        severity:  selectedNode.severity,
        risk:      selectedNode.risk,
        file:      selectedNode.file,
        line:      selectedNode.line,
      }),
    })
      .then((r) => r.json())
      .then((data) => { if (!cancelled) setNodeAnalysis(data); })
      .catch(() => { if (!cancelled) setNodeAnalysis(null); })
      .finally(() => { if (!cancelled) setLoadingAnalysis(false); });

    return () => { cancelled = true; };
  }, [selectedNode?.id]);

  // Build edge sets for attack path highlighting
  const pathEdges = new Set();
  for (let i = 0; i < path.length - 1; i++) {
    pathEdges.add(`${path[i]}->${path[i + 1]}`);
  }

  const cves = graph.links.filter((link) => {
    const source = link.source?.id || link.source;
    const target = link.target?.id || link.target;
    return pathEdges.has(`${source}->${target}`);
  });

  const patchNode = async () => {
    if (!selectedNode) return;
    patchNodeLocal(selectedNode.id);
    try {
      await fetch(endpoints.patchNode(selectedNode.id), { method: "POST" });
    } catch (_) {}
  };

  const badge     = selectedNode ? TYPE_BADGES[selectedNode.type] : null;
  const riskColor = selectedNode
    ? RISK_COLORS[selectedNode.risk] || RISK_COLORS[selectedNode.type] || "#8a94a7"
    : "#8a94a7";

  return (
    <aside className="side-panel">

      {/* ── AI Query Explanation ─────────────────────────────────── */}
      <div className="panel-section">
        <h2 className="panel-title">
          <span className="title-icon">🤖</span> AI Analysis
        </h2>
        <p className="explanation">{explanation || "Ask a query or click a node to analyze."}</p>
      </div>

      {/* ── Selected Node ────────────────────────────────────────── */}
      {selectedNode && (
        <div className="panel-section">
          <h3 className="section-head">
            <span className="title-icon">🎯</span> Selected Node
          </h3>
          <div className="node-card">
            <div className="node-header">
              {badge && (
                <span
                  className="type-badge"
                  style={{
                    background: badge.color + "22",
                    color: badge.color,
                    border: `1px solid ${badge.color}44`,
                  }}
                >
                  {badge.label}
                </span>
              )}
              {selectedNode.risk && (
                <span className="risk-badge" style={{ color: riskColor }}>
                  ● {(selectedNode.risk || "").toUpperCase()}
                </span>
              )}
            </div>

            <div className="node-label">{selectedNode.label || selectedNode.id}</div>

            {selectedNode.file && (
              <div className="node-meta">
                <span className="meta-key">File:</span>
                <span className="meta-val">{selectedNode.file.split("/").slice(-2).join("/")}</span>
              </div>
            )}
            {selectedNode.line && (
              <div className="node-meta">
                <span className="meta-key">Line:</span>
                <span className="meta-val">{selectedNode.line}</span>
              </div>
            )}
            {selectedNode.severity && (
              <div className="node-meta">
                <span className="meta-key">Severity:</span>
                <span className="meta-val" style={{ color: riskColor }}>
                  {selectedNode.severity}/10
                </span>
              </div>
            )}

            <button
              className="cyber-btn patch-btn"
              onClick={patchNode}
              disabled={selectedNode.patched}
            >
              {selectedNode.patched ? "✓ Patched" : "🔧 Mark as Patched"}
            </button>
          </div>

          {/* ── Vulnerability Analysis (AI) ─────────────────────── */}
          {["sink", "source"].includes(selectedNode.type) && (
            <div className="vuln-section">
              <h4 className="section-head">
                <span className="title-icon">🧠</span> Vulnerability Analysis
              </h4>
              <VulnAnalysisCard analysis={nodeAnalysis} loading={loadingAnalysis} />
            </div>
          )}

          {/* ── Git Blame ────────────────────────────────────────── */}
          {selectedNode.git_blame && (
            <div className="blame-section">
              <h4 className="section-head">
                <span className="title-icon">🔍</span> Commit Attribution
              </h4>
              <div className="blame-card">
                {selectedNode.git_blame.commit && (
                  <div className="blame-row">
                    <span className="label">Commit:</span>
                    <code className="commit-hash">{selectedNode.git_blame.commit}</code>
                  </div>
                )}
                {selectedNode.git_blame.author && (
                  <div className="blame-row">
                    <span className="label">Author:</span>
                    <span>{selectedNode.git_blame.author}</span>
                  </div>
                )}
                {selectedNode.git_blame.date && (
                  <div className="blame-row">
                    <span className="label">Date:</span>
                    <span>{selectedNode.git_blame.date}</span>
                  </div>
                )}
                {selectedNode.git_blame.message && (
                  <div className="blame-row">
                    <span className="label">Message:</span>
                    <span className="commit-msg">{selectedNode.git_blame.message}</span>
                  </div>
                )}
              </div>
              {selectedNode.blast_radius?.length > 0 && (
                <div className="blast-radius">
                  <span className="label">
                    💥 Blast Radius ({selectedNode.blast_radius.length} files):
                  </span>
                  <ul className="blast-list">
                    {selectedNode.blast_radius.slice(0, 5).map((f) => (
                      <li key={f}>{f}</li>
                    ))}
                    {selectedNode.blast_radius.length > 5 && (
                      <li className="muted">+{selectedNode.blast_radius.length - 5} more…</li>
                    )}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Attack Path Edges ────────────────────────────────────── */}
      <div className="panel-section">
        <h3 className="section-head">
          <span className="title-icon">⚡</span> Attack Path Edges
          {cves.length > 0 && <span className="count-badge">{cves.length}</span>}
        </h3>
        <ul className="cve-list">
          {cves.length ? (
            cves.map((item, idx) => (
              <li key={`${item.source}-${item.target}-${idx}`}>
                <span className="edge-type">{item.type || "dataflow"}</span>
                <strong className="edge-reason">{item.reason || ""}</strong>
              </li>
            ))
          ) : (
            <li className="muted">No active attack path selected.</li>
          )}
        </ul>
      </div>
    </aside>
  );
};

export default SidePanel;
