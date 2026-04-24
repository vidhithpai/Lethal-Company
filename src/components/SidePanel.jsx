import { useEffect, useState } from "react";
import useStore from "../store/useStore";
import { endpoints, normalizeGraph } from "../api";

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

// ─── Vulnerability analysis card ─────────────────────────────────────────────
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
      <div className="vuln-header">
        <span className="vuln-type">{analysis.vuln_type}</span>
        {analysis.cwe && (
          cweHref
            ? <a className="cwe-badge" href={cweHref} target="_blank" rel="noreferrer">{analysis.cwe}</a>
            : <span className="cwe-badge">{analysis.cwe}</span>
        )}
      </div>
      <div className="vuln-block">
        <span className="vuln-label">⚠ Impact</span>
        <p className="vuln-text">{analysis.what_it_does}</p>
      </div>
      <div className="vuln-block">
        <span className="vuln-label">🔬 Root Cause</span>
        <p className="vuln-text">{analysis.root_cause}</p>
      </div>
      <div className="vuln-block vuln-fix">
        <span className="vuln-label">✅ Fix</span>
        <p className="vuln-text">{analysis.fix}</p>
      </div>
      {analysis.severity_reason && (
        <div className="vuln-block">
          <span className="vuln-label">📊 Why this rating</span>
          <p className="vuln-text vuln-muted">{analysis.severity_reason}</p>
        </div>
      )}
    </div>
  );
};

// ─── WF1: Time-travel blame callout ──────────────────────────────────────────
const TimeTravelCard = ({ node }) => {
  const blame = node.git_blame;
  const radius = node.blast_radius || [];

  if (!blame || (!blame.author && !blame.commit)) return null;

  const isUncommitted = blame.commit === "uncommitted";

  return (
    <div className="timetravel-card">
      <div className="timetravel-header">
        <span className="timetravel-icon">🕐</span>
        <span className="timetravel-title">Time-Travel Attribution</span>
      </div>

      {isUncommitted ? (
        <p className="timetravel-summary">This vulnerability exists in <strong>uncommitted local changes</strong>.</p>
      ) : (
        <p className="timetravel-summary">
          This {node.type === "sink" ? "vulnerability" : "source"} was introduced by{" "}
          <strong className="timetravel-author">{blame.author || "unknown"}</strong>
          {blame.date && <> on <strong className="timetravel-date">{blame.date}</strong></>}
          {blame.commit && (
            <> in commit <code className="commit-hash">{blame.commit}</code></>
          )}
          {(blame.message || node.commit_message) && (
            <>: <em className="timetravel-msg">"{blame.message || node.commit_message}"</em></>
          )}
        </p>
      )}

      {radius.length > 0 && (
        <div className="blast-callout">
          <span className="blast-callout-label">
            💥 Blast Radius — <strong>{radius.length}</strong> file{radius.length !== 1 ? "s" : ""} touched in the same commit
          </span>
          <ul className="blast-list">
            {radius.slice(0, 5).map((f) => <li key={f}>{f}</li>)}
            {radius.length > 5 && (
              <li className="muted">+{radius.length - 5} more…</li>
            )}
          </ul>
        </div>
      )}
    </div>
  );
};

// ─── Main SidePanel ───────────────────────────────────────────────────────────
const SidePanel = () => {
  const graph           = useStore((s) => s.graph);
  const path            = useStore((s) => s.path);
  const selectedNode    = useStore((s) => s.selectedNode);
  const explanation     = useStore((s) => s.explanation);
  const patchNodeLocal  = useStore((s) => s.patchNodeLocal);
  const setGraph        = useStore((s) => s.setGraph);
  const setPath         = useStore((s) => s.setPath);

  const [nodeAnalysis, setNodeAnalysis]         = useState(null);
  const [loadingAnalysis, setLoadingAnalysis]   = useState(false);
  const [patchSuccess, setPatchSuccess]         = useState(false);

  // ── Auto-fetch vulnerability analysis when sink/source selected ────────────
  useEffect(() => {
    if (!selectedNode || !["sink", "source"].includes(selectedNode.type)) {
      setNodeAnalysis(null);
      return;
    }
    let cancelled = false;
    setLoadingAnalysis(true);
    setNodeAnalysis(null);
    setPatchSuccess(false);

    fetch(endpoints.explainNode, {
      method:  "POST",
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
      .then((d) => { if (!cancelled) setNodeAnalysis(d); })
      .catch(() => {})
      .finally(() => { if (!cancelled) setLoadingAnalysis(false); });

    return () => { cancelled = true; };
  }, [selectedNode?.id]);

  // ── Build active-path edge set ─────────────────────────────────────────────
  const pathEdges = new Set();
  for (let i = 0; i < path.length - 1; i++) {
    pathEdges.add(`${path[i]}->${path[i + 1]}`);
  }
  const cves = graph.links.filter((link) => {
    const s = link.source?.id || link.source;
    const t = link.target?.id || link.target;
    return pathEdges.has(`${s}->${t}`);
  });

  // ── WF3: Patch — update graph from backend response ────────────────────────
  const patchNode = async () => {
    if (!selectedNode || selectedNode.patched) return;

    // Immediate visual feedback
    patchNodeLocal(selectedNode.id);
    setPatchSuccess(false);

    try {
      const res = await fetch(endpoints.patchNode(selectedNode.id), { method: "POST" });
      if (res.ok) {
        const payload = await res.json();
        // Backend returns the new graph — update store so attack paths recompute
        setGraph(normalizeGraph(payload));
        setPath([]);           // old path may now be broken — clear it
        setPatchSuccess(true);
      }
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

            {/* WF3: Patch button + live feedback */}
            <button
              className={`cyber-btn patch-btn ${patchSuccess ? "patch-success" : ""}`}
              onClick={patchNode}
              disabled={selectedNode.patched}
            >
              {selectedNode.patched
                ? "✓ Patched — Attack Surface Reduced"
                : patchSuccess
                  ? "✓ Graph Recomputed"
                  : "🔧 Mark as Patched"}
            </button>
            {patchSuccess && (
              <p className="patch-notice">
                ✅ Attack paths through this node have been eliminated from the graph.
              </p>
            )}
          </div>

          {/* WF2 + WF4: Vulnerability Analysis (AI) */}
          {["sink", "source"].includes(selectedNode.type) && (
            <div className="vuln-section">
              <h4 className="section-head">
                <span className="title-icon">🧠</span> Vulnerability Analysis
              </h4>
              <VulnAnalysisCard analysis={nodeAnalysis} loading={loadingAnalysis} />
            </div>
          )}

          {/* WF1 + WF4: Time-travel blame */}
          <TimeTravelCard node={selectedNode} />
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
