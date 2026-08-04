import { useState, useRef, useEffect } from "react";
import useStore from "../store/useStore";
import { API_BASE } from "../api";

export default function UnifiedPanel({
  selectedNode, attackPath, attackPaths, onPatch, onHighlightPath, onSelectNode
}) {
  const [activeTab, setActiveTab] = useState("node");
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      text: "I have access to your scan findings. Ask me anything — " +
        "'show SQL injection paths', 'who introduced the file traversal?', " +
        "'which fix has the biggest impact?'"
    }
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [nodeContext, setNodeContext] = useState(null);
  const [nodeAnalysis, setNodeAnalysis] = useState(null);
  const [loadingAnalysis, setLoadingAnalysis] = useState(false);
  const chatEndRef = useRef(null);

  // Auto-switch to node tab when node selected
  useEffect(() => {
    if (selectedNode) {
      setActiveTab("node");
      fetch(`${API_BASE}/api/node/context?node_id=${encodeURIComponent(selectedNode.id)}`)
        .then(r => r.json())
        .then(setNodeContext)
        .catch(() => setNodeContext(null));
    }
  }, [selectedNode?.id]);

  useEffect(() => {
    if (!selectedNode || !["sink", "source"].includes(selectedNode.type)) {
      setNodeAnalysis(null);
      return;
    }
    let cancelled = false;
    setLoadingAnalysis(true);
    setNodeAnalysis(null);

    fetch(`${API_BASE}/api/query/explain-node`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        node_id: selectedNode.id,
        label: selectedNode.label,
        node_type: selectedNode.type,
        severity: selectedNode.severity,
        risk: selectedNode.risk,
        file: selectedNode.file,
        line: selectedNode.line,
      }),
    })
      .then((r) => r.json())
      .then((d) => { if (!cancelled) setNodeAnalysis(d); })
      .catch(() => { })
      .finally(() => { if (!cancelled) setLoadingAnalysis(false); });

    return () => { cancelled = true; };
  }, [selectedNode?.id]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const sendMessage = async () => {
    if (!input.trim() || loading) return;
    const userMsg = input.trim();
    setInput("");
    setMessages(prev => [...prev, { role: "user", text: userMsg }]);
    setLoading(true);

    try {
      const res = await fetch(`${API_BASE}/api/query/ask`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: userMsg })
      });
      const data = await res.json();

      // Handle graph actions from AI
      if (data.action) {
        if (data.action.action === "highlight_path" &&
          data.action.path_index !== undefined) {
          onHighlightPath(data.action.path_index);
        }
        if (data.action.action === "select_node" && data.action.node_id) {
          onSelectNode(data.action.node_id);
        }
      }

      // Show retrieved docs as sources
      const sources = data.retrieved_docs?.slice(0, 2).map(d =>
        d.document.substring(0, 80) + "..."
      ) || [];

      setMessages(prev => [...prev, {
        role: "assistant",
        text: data.explanation || "No response.",
        sources,
        action: data.action
      }]);
    } catch {
      setMessages(prev => [...prev, {
        role: "assistant",
        text: "Connection error. Is the backend running?",
        sources: []
      }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="unified-side-panel">
      {/* Tab headers */}
      <div className="panel-tabs-header">
        <button
          className={`panel-tab-btn ${activeTab === "node" ? "active" : ""}`}
          onClick={() => setActiveTab("node")}
        >
          Inspect Node {selectedNode ? `· ${selectedNode.label?.slice(0, 10)}` : ""}
        </button>
        <button
          className={`panel-tab-btn ${activeTab === "chat" ? "active" : ""}`}
          onClick={() => setActiveTab("chat")}
        >
          AI security Copilot
        </button>
      </div>

      {/* INSPECT TAB */}
      {activeTab === "node" && (
        <div className="panel-tab-content-scroll">
          {!selectedNode ? (
            <div style={{ color: "var(--text-muted)", textAlign: "center", marginTop: "40px" }}>
              Select any sphere on the 3D graph view to analyze AST dataflow.
            </div>
          ) : (
            <>
              {/* Identity Hero Section */}
              <div className="node-hero-section">
                <span className="node-hero-label">{selectedNode.label}</span>
                <div className="node-badge-row">
                  {selectedNode.risk && (
                    <span className={`badge badge-risk-${selectedNode.risk.toLowerCase()}`}>
                      {selectedNode.risk} RISK
                    </span>
                  )}
                  {selectedNode.type && (
                    <span className={`badge badge-type-${selectedNode.type.toLowerCase()}`}>
                      {selectedNode.type}
                    </span>
                  )}
                  {selectedNode.community && (
                    <span className="badge" style={{ background: "rgba(38, 66, 114, 0.25)", color: "var(--text-secondary)" }}>
                      {selectedNode.community.replace(/_/g, " ")}
                    </span>
                  )}
                </div>
              </div>

              {/* Metadata Details Table (Modification 14) */}
              <div className="panel-section-title">Node Structural Metrics</div>
              <div className="details-grid">
                <div className="details-row">
                  <span className="details-key">Component File</span>
                  <span className="details-val">{selectedNode.file || "unknown"}</span>
                </div>
                <div className="details-row">
                  <span className="details-key">Source Line</span>
                  <span className="details-val">#{selectedNode.line || "?"}</span>
                </div>
                {selectedNode.confidence && (
                  <div className="details-row">
                    <span className="details-key">Taint Confidence</span>
                    <span className="details-val">{Math.round(selectedNode.confidence * 100)}%</span>
                  </div>
                )}
                <div className="details-row">
                  <span className="details-key">Reachability</span>
                  <span className="details-val" style={{ color: nodeContext?.attack_paths_through?.length > 0 ? "var(--color-sink)" : "var(--color-source)", fontWeight: 600 }}>
                    {nodeContext?.attack_paths_through?.length > 0 ? "EXPOSED" : "SECURED / NO PATH"}
                  </span>
                </div>
                <div className="details-row">
                  <span className="details-key">Taint In-degree</span>
                  <span className="details-val">{nodeContext?.upstream?.sources?.length || 0} inputs</span>
                </div>
                <div className="details-row">
                  <span className="details-key">Taint Out-degree</span>
                  <span className="details-val">{nodeContext?.downstream?.sinks?.length || 0} sinks</span>
                </div>
              </div>

              {/* AST Code Snippet (Modification 14) */}
              {selectedNode.label && (
                <>
                  <div className="panel-section-title">AST Context Symbol</div>
                  <div style={{
                    background: "rgba(6, 9, 19, 0.4)",
                    border: "1px solid var(--border)",
                    borderRadius: "var(--radius-sm)",
                    padding: "10px",
                    fontFamily: "JetBrains Mono, monospace",
                    fontSize: "11px",
                    color: "var(--accent-cyan)",
                    wordBreak: "break-all"
                  }}>
                    {selectedNode.type === "sink" ? `Sink call: ${selectedNode.label}` : `Input source: ${selectedNode.label}`}
                  </div>
                </>
              )}

              {/* AI Explanation & Analysis Panel (Modification 15) */}
              {["sink", "source"].includes(selectedNode.type) && (
                <>
                  <div className="panel-section-title">AI Vulnerability Analysis</div>
                  {loadingAnalysis ? (
                    <div style={{ color: "var(--text-muted)", fontSize: "12px", fontStyle: "italic" }}>
                      Querying local LLM agent...
                    </div>
                  ) : nodeAnalysis ? (
                    <div className="ai-analysis-card">
                      <div className="ai-card-accent-line" style={{ background: selectedNode.risk ? `var(--color-${selectedNode.risk.toLowerCase()})` : "var(--accent-blue)" }} />
                      <div className="ai-card-body">
                        <div className="ai-vuln-title-row">
                          <span className="ai-vuln-title">{nodeAnalysis.vuln_type}</span>
                          {nodeAnalysis.cwe && <span className="cwe-badge">{nodeAnalysis.cwe}</span>}
                        </div>

                        {/* Modification 15 explanation points */}
                        <div className="ai-block">
                          <span className="ai-label">Root Cause Explanation</span>
                          <p className="ai-text">{nodeAnalysis.root_cause}</p>
                        </div>

                        <div className="ai-block">
                          <span className="ai-label">Impact Radius</span>
                          <p className="ai-text">{nodeAnalysis.what_it_does}</p>
                        </div>

                        <div className="ai-recommendation-box">
                          <div className="ai-rec-title">Suggested Remediation</div>
                          <p className="ai-text" style={{ color: "var(--text-primary)" }}>{nodeAnalysis.fix}</p>
                        </div>

                        {/* Modification 15: Confidence indicator */}
                        <div className="ai-confidence-container">
                          <div className="ai-confidence-label-row">
                            <span style={{ color: "var(--text-muted)" }}>Confidence Score</span>
                            <span style={{ color: "var(--accent-cyan)", fontWeight: 700 }}>
                              {selectedNode.severity ? `${Math.round(selectedNode.severity * 10)}%` : "85%"}
                            </span>
                          </div>
                          <div className="ai-confidence-bar-outer">
                            <div
                              className="ai-confidence-bar-inner"
                              style={{ width: selectedNode.severity ? `${selectedNode.severity * 10}%` : "85%" }}
                            />
                          </div>
                        </div>

                      </div>
                    </div>
                  ) : (
                    <div style={{ color: "var(--text-muted)", fontSize: "12px" }}>No context generated for this node class.</div>
                  )}
                </>
              )}

              {/* Attack Vector List through Node */}
              {nodeContext?.attack_paths_through?.length > 0 && (
                <>
                  <div className="panel-section-title">Active Attack Vectors ({nodeContext.attack_paths_through.length})</div>
                  <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "6px" }}>
                    Select a path vector to animate data flows on 3D view.
                  </div>
                  {nodeContext.attack_paths_through.slice(0, 3).map((p, i) => {
                    const isHoverable = attackPaths && attackPaths.length > 0;
                    return (
                      <div
                        key={i}
                        className="path-selector-item"
                        onClick={() => {
                          if (!attackPaths) return;
                          const globalIdx = attackPaths.findIndex(ap => ap.path && p.path && ap.path.join(',') === p.path.join(','));
                          if (globalIdx >= 0) {
                            onHighlightPath(globalIdx);
                          }
                        }}
                      >
                        <div className="path-selector-header">
                          <span className="path-selector-title" style={{ color: p.risk === "CRITICAL" || p.risk === "HIGH" ? "var(--color-critical)" : "var(--color-intermediate)" }}>
                            {p.risk || p.classification || "Attack Path"}
                          </span>
                          {isHoverable && <span className="path-selector-action">Animate path</span>}
                        </div>
                        <div className="path-selector-meta">
                          Length: {p.path?.length || 0} nodes · Risk score: {p.score || p.risk_score || "N/A"}/10
                        </div>
                      </div>
                    );
                  })}
                </>
              )}

              {/* Patch Impact Preview */}
              {nodeContext?.patch_impact && (
                <>
                  <div className="panel-section-title">Patch Simulation Impact</div>
                  <div style={{
                    background: "rgba(16, 185, 129, 0.05)",
                    border: "1px solid rgba(16, 185, 129, 0.3)",
                    borderRadius: "var(--radius-sm)",
                    padding: "12px",
                    display: "flex",
                    flexDirection: "column",
                    gap: "4px"
                  }}>
                    <span style={{ color: "var(--color-source)", fontWeight: 700, fontSize: "12px" }}>
                      {nodeContext.patch_impact.recommendation}
                    </span>
                    <span style={{ color: "var(--text-secondary)", fontSize: "11.5px" }}>
                      Eliminates {nodeContext.patch_impact.eliminated_paths} active path vectors.
                    </span>
                    <span style={{ color: "var(--text-muted)", fontSize: "11px" }}>
                      Mitigation impact score: {nodeContext.patch_impact.impact_score}/10
                    </span>
                  </div>
                </>
              )}

              {/* Git Blame / Commit attribution (Modification 14) */}
              {selectedNode.git_blame?.commit && (
                <>
                  <div className="panel-section-title">Version Control Origin</div>
                  <div className="commit-card">
                    <div className="commit-card-row">
                      <span className="commit-card-key">Author</span>
                      <span className="commit-card-val" style={{ fontWeight: 600 }}>{selectedNode.git_blame.author}</span>
                    </div>
                    <div className="commit-card-row">
                      <span className="commit-card-key">Commit</span>
                      <span className="commit-card-val"><code className="commit-card-hash">{selectedNode.git_blame.commit.slice(0, 8)}</code></span>
                    </div>
                    <div className="commit-card-row">
                      <span className="commit-card-key">Date</span>
                      <span className="commit-card-val">{selectedNode.git_blame.date}</span>
                    </div>
                    <div className="commit-card-row">
                      <span className="commit-card-key">Summary</span>
                      <span className="commit-card-val commit-card-message">"{selectedNode.git_blame.message}"</span>
                    </div>

                    {/* Blast radius info */}
                    {selectedNode.blast_radius?.length > 0 && (
                      <div style={{ marginTop: "6px", borderTop: "1px dashed var(--border)", paddingTop: "8px" }}>
                        <span className="ai-label"> Blast Radius ({selectedNode.blast_radius.length} files)</span>
                        <div style={{ display: "flex", flexDirection: "column", gap: "2px", marginTop: "4px" }}>
                          {selectedNode.blast_radius.slice(0, 3).map((f, idx) => (
                            <span key={idx} style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10.5px", color: "var(--text-muted)" }}>
                              • {f}
                            </span>
                          ))}
                          {selectedNode.blast_radius.length > 3 && (
                            <span style={{ fontSize: "10px", color: "var(--text-muted)", fontStyle: "italic", marginLeft: "8px" }}>
                              + {selectedNode.blast_radius.length - 3} more files
                            </span>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </>
              )}

              {/* Action buttons */}
              {!selectedNode.patched ? (
                <button className="action-patch-button" onClick={() => onPatch(selectedNode.id)}>
                  Simulate Remediation Patch
                </button>
              ) : (
                <div className="action-patch-success">
                  Symbol patched & path traces severed
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* AI CHAT TAB */}
      {activeTab === "chat" && (
        <div className="chat-tab-container">
          <div className="chat-messages-area">
            {messages.map((msg, i) => (
              <div key={i} className={`chat-bubble-wrap ${msg.role}`}>
                <span className="chat-bubble-header">{msg.role === "user" ? "Reviewer" : "Copilot LLM"}</span>
                <div className="chat-bubble-body">{msg.text}</div>
                {msg.sources?.length > 0 && (
                  <div className="chat-sources-container">
                    {msg.sources.map((s, idx) => (
                      <span key={idx} className="chat-source-badge">{s}</span>
                    ))}
                  </div>
                )}
                {/* Active path traces highlighted from AI responses */}
                {msg.action && msg.action.action === "highlight_path" && attackPaths && attackPaths[msg.action.path_index] && (
                  <div style={{
                    marginTop: "8px",
                    background: "rgba(239, 68, 68, 0.05)",
                    border: "1px solid rgba(239, 68, 68, 0.25)",
                    borderRadius: "6px",
                    padding: "10px"
                  }}>
                    <div style={{ fontSize: "10.5px", color: "var(--color-critical)", fontWeight: 700, textTransform: "uppercase", marginBottom: "4px" }}>
                      Animate Action Suggested
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-secondary)" }}>
                      <strong>Trace:</strong> {attackPaths[msg.action.path_index].source_label} ➔ {attackPaths[msg.action.path_index].sink_label}
                    </div>
                  </div>
                )}
              </div>
            ))}
            {loading && (
              <div style={{ color: "var(--text-muted)", fontStyle: "italic", fontSize: "12px" }}>
                Scanning codebase embeddings...
              </div>
            )}
            <div ref={chatEndRef} />
          </div>

          {/* Chat input box */}
          <div className="chat-input-row">
            <input
              type="text"
              className="chat-text-input"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === "Enter" && sendMessage()}
              placeholder="Ask security assistant..."
            />
            <button className="chat-send-btn" onClick={sendMessage} disabled={loading}>
              Send
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
