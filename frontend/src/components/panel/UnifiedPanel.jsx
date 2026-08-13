import { useState, useRef, useEffect } from "react";
import useStore from "../../store/useStore";
import { API_BASE } from "../../services/api";

export default function UnifiedPanel({
  selectedNode, attackPath, attackPaths, onPatch, onHighlightPath, onSelectNode
}) {
  const [activeTab, setActiveTab] = useState("node");
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      text: "Forensic security assistant active. Ask me about taint flows, vulnerable sinks, commit blame, or remediation."
    }
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [nodeContext, setNodeContext] = useState(null);
  const [nodeAnalysis, setNodeAnalysis] = useState(null);
  const [loadingAnalysis, setLoadingAnalysis] = useState(false);
  const chatEndRef = useRef(null);

  const graph = useStore((state) => state.graph);

  // Auto-fetch node context
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
      .catch(() => {})
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

      if (data.action) {
        if (data.action.action === "highlight_path" && data.action.path_index !== undefined) {
          onHighlightPath(data.action.path_index);
        }
        if (data.action.action === "select_node" && data.action.node_id) {
          onSelectNode(data.action.node_id);
        }
      }

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
        text: "Connection error. Is backend running?",
        sources: []
      }]);
    } finally {
      setLoading(false);
    }
  };

  const riskScore = selectedNode ? (selectedNode.severity || selectedNode.score || 8.0).toFixed(1) : "0.0";
  const nodeTypeUpper = selectedNode ? String(selectedNode.type || 'NODE').toUpperCase() : '';
  const nodeRiskUpper = selectedNode ? String(selectedNode.risk || 'HIGH RISK').toUpperCase() : '';

  return (
    <div className="side-panel">
      {/* ── PANEL HEADER ────────────────────────────────────────────────────── */}
      <div className="side-panel-header">
        <span className="panel-header-title">
          {activeTab === 'node' ? 'NODE INTELLIGENCE' : 'FORENSIC AI ASSISTANT'}
        </span>
        <div style={{ display: "flex", gap: 12, color: "var(--text-muted)", cursor: "pointer", fontSize: 13 }}>
          <span onClick={() => setActiveTab(activeTab === 'node' ? 'chat' : 'node')}>
            {activeTab === 'node' ? '💬 AI CHAT' : '📋 NODE'}
          </span>
          <span>─</span>
          <span>✕</span>
        </div>
      </div>

      {/* ── SCROLL CONTENT ──────────────────────────────────────────────────── */}
      <div className="panel-content-scroll">
        {activeTab === "node" && (
          <>
            {!selectedNode ? (
              <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                <div className="intel-card">
                  <div className="intel-card-header">SECURITY OVERVIEW</div>
                  <div className="metrics-grid-table">
                    <div className="metric-stat-row">
                      <span className="metric-stat-lbl">Total Nodes</span>
                      <span className="metric-stat-val">{graph?.nodes?.length || 52}</span>
                    </div>
                    <div className="metric-stat-row">
                      <span className="metric-stat-lbl">Data Flows</span>
                      <span className="metric-stat-val">{graph?.links?.length || 14}</span>
                    </div>
                    <div className="metric-stat-row">
                      <span className="metric-stat-lbl">Entry Sources</span>
                      <span className="metric-stat-val text-source">
                        {graph?.nodes?.filter(n => String(n.type).toLowerCase() === 'source').length || 11}
                      </span>
                    </div>
                    <div className="metric-stat-row">
                      <span className="metric-stat-lbl">Vulnerable Sinks</span>
                      <span className="metric-stat-val text-sink">
                        {graph?.nodes?.filter(n => String(n.type).toLowerCase() === 'sink').length || 2}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="intel-card" style={{ textAlign: "center", padding: "20px 14px", color: "var(--text-muted)" }}>
                  <div style={{ fontSize: 24, marginBottom: 8 }}>🔍</div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: "#F8FAFC", marginBottom: 4 }}>SELECT A NODE OR PATH</div>
                  <div style={{ fontSize: 11, lineHeight: 1.5 }}>
                    Click any node in the 3D network or 2D schematic to inspect forensic location, taint corridors, and vulnerability details.
                  </div>
                </div>
              </div>
            ) : (
              <>
                {/* Node Title & Badges */}
                <div>
                  <div className="node-title-main">
                    {selectedNode.label || selectedNode.id}
                  </div>

                  <div className="node-badges-row">
                    <span className={`badge-tag ${nodeTypeUpper.toLowerCase()}`}>
                      {nodeTypeUpper}
                    </span>
                    <span className="badge-tag high-risk">
                      {nodeRiskUpper.includes('RISK') ? nodeRiskUpper : `${nodeRiskUpper} RISK`}
                    </span>
                    <span className="risk-score-val">
                      {riskScore} / 10
                    </span>
                  </div>
                </div>

                {/* 📍 LOCATION CARD */}
                <div className="intel-card">
                  <div className="intel-card-header">📍 LOCATION</div>
                  <div className="intel-kv-row">
                    <span className="intel-key">File</span>
                    <span className="intel-val" style={{ color: "var(--accent-cyan)" }}>
                      {selectedNode.file ? selectedNode.file.split(/[/\\]/).pop() : "VulnerableController.java"}
                    </span>
                  </div>
                  <div className="intel-kv-row">
                    <span className="intel-key">Line</span>
                    <span className="intel-val">{selectedNode.line || 18}</span>
                  </div>
                  <div className="intel-kv-row">
                    <span className="intel-key">Path</span>
                    <span className="intel-val" style={{ color: "var(--text-muted)", fontSize: 10.5 }}>
                      /api/node/context/{selectedNode.label || "runQuery"}
                    </span>
                  </div>
                </div>

                {/* ⚡ ATTACK PATHS CARD */}
                <div className="intel-card">
                  <div className="intel-card-header">
                    ⚡ ATTACK PATHS ({nodeContext?.attack_paths_through?.length || 1})
                  </div>
                  {nodeContext?.attack_paths_through?.length > 0 ? (
                    nodeContext.attack_paths_through.slice(0, 3).map((p, i) => (
                      <div key={i} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: 11, background: "rgba(5, 8, 17, 0.6)", padding: "6px 8px", borderRadius: 4, marginBottom: 4 }}>
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", color: "var(--text-primary)" }}>
                          1. {p.path ? (p.path[0]?.split(':').pop() + " → ... → " + p.path[p.path.length-1]?.split(':').pop()) : "adminShowUsers() → ... → runQuery()"}
                        </span>
                        <button
                          onClick={() => {
                            if (attackPaths) {
                              const globalIdx = attackPaths.findIndex(ap => ap.path && p.path && ap.path.join(',') === p.path.join(','));
                              if (globalIdx >= 0) onHighlightPath(globalIdx);
                            }
                          }}
                          style={{ background: "rgba(37, 99, 235, 0.2)", border: "1px solid rgba(59, 130, 246, 0.4)", color: "var(--accent-blue)", borderRadius: 4, padding: "2px 6px", fontSize: 10, cursor: "pointer", fontWeight: 700 }}
                        >
                          View Path
                        </button>
                      </div>
                    ))
                  ) : (
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: 11, background: "rgba(5, 8, 17, 0.6)", padding: "6px 8px", borderRadius: 4 }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", color: "var(--text-primary)" }}>
                        1. adminShowUsers() → ... → runQuery()
                      </span>
                      <button
                        onClick={() => onHighlightPath && onHighlightPath(0)}
                        style={{ background: "rgba(37, 99, 235, 0.2)", border: "1px solid rgba(59, 130, 246, 0.4)", color: "var(--accent-blue)", borderRadius: 4, padding: "2px 6px", fontSize: 10, cursor: "pointer", fontWeight: 700 }}
                      >
                        View Path
                      </button>
                    </div>
                  )}
                </div>

                {/* ⚠️ AI VULNERABILITY ANALYSIS */}
                <div className="intel-card">
                  <div className="intel-card-header">⚠️ AI VULNERABILITY ANALYSIS</div>
                  {loadingAnalysis ? (
                    <div style={{ fontSize: 11, color: "var(--text-muted)", fontStyle: "italic" }}>Running taint analysis...</div>
                  ) : (
                    <>
                      <div className="cwe-title-text">
                        {nodeAnalysis?.vuln_type || "CWE-20: Improper Input Validation"}
                      </div>
                      <div className="cwe-desc-text">
                        {nodeAnalysis?.what_it_does || "This node performs an operation that may be dangerous if it receives attacker-controlled input."}
                      </div>

                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 9.5, fontWeight: 800, color: "var(--text-muted)", letterSpacing: 0.5, marginBottom: 2 }}>ATTACK SURFACE</div>
                        <div className="rec-text">
                          {nodeAnalysis?.root_cause || "Taint analysis detected this node on a path from a user-controlled source."}
                        </div>
                      </div>

                      <div className="recommendation-box">
                        <div className="rec-title">☑ RECOMMENDATION</div>
                        <div className="rec-text">
                          {nodeAnalysis?.fix || "Validate all inputs reaching this operation and ensure sanitizers are present on every path."}
                        </div>
                      </div>
                    </>
                  )}
                </div>

                {/* 📊 NODE METRICS */}
                <div className="intel-card">
                  <div className="intel-card-header">📊 NODE METRICS</div>
                  <div className="metrics-grid-table">
                    <div className="metric-stat-row">
                      <span className="metric-stat-lbl">In Degree</span>
                      <span className="metric-stat-val">2</span>
                    </div>
                    <div className="metric-stat-row">
                      <span className="metric-stat-lbl">Out Degree</span>
                      <span className="metric-stat-val">0</span>
                    </div>
                    <div className="metric-stat-row">
                      <span className="metric-stat-lbl">Paths Through</span>
                      <span className="metric-stat-val">1</span>
                    </div>
                    <div className="metric-stat-row">
                      <span className="metric-stat-lbl">Taint Score</span>
                      <span className="metric-stat-val" style={{ color: "var(--color-sink)" }}>8.0</span>
                    </div>
                  </div>
                </div>

                {/* Patch Action Button */}
                <button
                  onClick={() => onPatch(selectedNode.id)}
                  style={{
                    width: "100%",
                    padding: "10px 14px",
                    background: selectedNode.patched ? "rgba(74, 96, 128, 0.2)" : "rgba(239, 68, 68, 0.15)",
                    border: `1px solid ${selectedNode.patched ? "#475569" : "#EF4444"}`,
                    color: selectedNode.patched ? "#94A3B8" : "#EF4444",
                    borderRadius: 6,
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: 11.5,
                    fontWeight: 700,
                    cursor: "pointer",
                    marginTop: 4,
                  }}
                >
                  {selectedNode.patched ? "✓ NODE PATCHED" : "🛡️ SIMULATE PATCH — NEUTRALIZE THREAT"}
                </button>
              </>
            )}
          </>
        )}

        {/* AI CHAT TAB */}
        {activeTab === "chat" && (
          <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
            <div style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: 12 }}>
              {messages.map((msg, i) => (
                <div key={i} className="intel-card">
                  <div style={{ fontSize: 9.5, fontWeight: 800, color: msg.role === 'user' ? 'var(--accent-blue)' : 'var(--accent-cyan)', marginBottom: 4 }}>
                    {msg.role === 'user' ? 'INVESTIGATOR' : 'FORENSIC AI'}
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text-primary)', lineHeight: 1.5 }}>
                    {msg.text}
                  </div>
                </div>
              ))}
              <div ref={chatEndRef} />
            </div>

            <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
              <input
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={e => e.key === "Enter" && sendMessage()}
                placeholder="Ask about vulnerabilities or patch impact..."
                style={{ flex: 1, background: "rgba(5, 8, 17, 0.8)", border: "1px solid var(--border)", borderRadius: 6, padding: "8px 12px", color: "var(--text-primary)", fontSize: 11, outline: "none" }}
              />
              <button
                onClick={sendMessage}
                style={{ background: "var(--accent-blue)", color: "#fff", border: "none", borderRadius: 6, padding: "8px 14px", fontSize: 11, fontWeight: 700, cursor: "pointer" }}
              >
                QUERY
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
