import useStore from "../store/useStore";
import { endpoints } from "../api";

const RISK_COLORS = {
  critical: "#ff2d55",
  high: "#ff6b35",
  medium: "#f4c542",
  low: "#2fd66f",
  HIGH: "#ff6b35",
  MEDIUM: "#f4c542",
  LOW: "#2fd66f",
};

const TYPE_BADGES = {
  source: { label: "SOURCE", color: "#2fd66f" },
  sink: { label: "SINK", color: "#ff4d4f" },
  intermediate: { label: "TAINT", color: "#f4c542" },
  function: { label: "FUNC", color: "#4ea1ff" },
  sanitizer: { label: "SANITIZER", color: "#a78bfa" },
};

const SidePanel = () => {
  const graph = useStore((state) => state.graph);
  const path = useStore((state) => state.path);
  const selectedNode = useStore((state) => state.selectedNode);
  const explanation = useStore((state) => state.explanation);
  const patchNodeLocal = useStore((state) => state.patchNodeLocal);

  const pathEdges = new Set();
  for (let i = 0; i < path.length - 1; i += 1) {
    pathEdges.add(`${path[i]}->${path[i + 1]}`);
  }

  const cves = graph.links.filter((link) => {
    const source = link.source.id || link.source;
    const target = link.target.id || link.target;
    return pathEdges.has(`${source}->${target}`);
  });

  const patchNode = async () => {
    if (!selectedNode) return;
    patchNodeLocal(selectedNode.id);
    try {
      await fetch(endpoints.patchNode(selectedNode.id), { method: "POST" });
    } catch (_) {}
  };

  const badge = selectedNode ? TYPE_BADGES[selectedNode.type] : null;
  const riskColor = selectedNode
    ? RISK_COLORS[selectedNode.risk] || RISK_COLORS[selectedNode.type] || "#8a94a7"
    : "#8a94a7";

  return (
    <aside className="side-panel">
      {/* AI Explanation */}
      <div className="panel-section">
        <h2 className="panel-title">
          <span className="title-icon">🤖</span> AI Analysis
        </h2>
        <p className="explanation">{explanation || "Ask a query to analyze an attack route."}</p>
      </div>

      {/* Selected Node */}
      {selectedNode && (
        <div className="panel-section">
          <h3 className="section-head">
            <span className="title-icon">🎯</span> Selected Node
          </h3>
          <div className="node-card">
            <div className="node-header">
              {badge && (
                <span className="type-badge" style={{ background: badge.color + "22", color: badge.color, border: `1px solid ${badge.color}44` }}>
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
                <span className="meta-val" style={{ color: riskColor }}>{selectedNode.severity}/10</span>
              </div>
            )}
            <button className="cyber-btn patch-btn" onClick={patchNode} disabled={selectedNode.patched}>
              {selectedNode.patched ? "✓ Patched" : "🔧 Mark as Patched"}
            </button>
          </div>

          {/* Git Blame Section */}
          {selectedNode.git_blame && (
            <div className="blame-section">
              <h4 className="section-head"><span className="title-icon">🔍</span> Commit Attribution</h4>
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
                      <li className="muted">+{selectedNode.blast_radius.length - 5} more...</li>
                    )}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Attack Path Edges */}
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
