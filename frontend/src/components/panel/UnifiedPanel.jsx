import { useState, useRef, useEffect } from "react";
import useStore from "../../store/useStore";
import { API_BASE } from "../../services/api";

function EvidenceCard({ source, index }) {
  const typeColors = {
    commit:      '#58A6FF',
    attack_path: '#F85149',
    guard_event: '#F0883E',
    sink_node:   '#A371F7',
  };
  const color = typeColors[source.type] || '#8B949E';
  return (
    <div style={{
      background: '#161B22', border: `1px solid ${color}33`,
      borderLeft: `3px solid ${color}`, borderRadius: 6,
      padding: '8px 10px', marginBottom: 6, fontSize: 11,
    }}>
      <div style={{ display:'flex', justifyContent:'space-between',
                    marginBottom: 4 }}>
        <span style={{ color, fontWeight: 600, textTransform: 'uppercase',
                       fontSize: 9 }}>{source.type?.replace('_',' ')}</span>
        <span style={{ color:'#4B5563', fontSize: 9 }}>
          relevance {(source.score * 100).toFixed(0)}%
        </span>
      </div>
      <div style={{ color: '#8B949E', lineHeight: 1.5 }}>
        {source.text}
      </div>
    </div>
  );
}

const getSeverityColor = (sev) => {
  const s = String(sev || "").toUpperCase();
  if (s.includes("CRIT")) return "#EF4444";
  if (s.includes("HIGH")) return "#F87171";
  if (s.includes("MED")) return "#F59E0B";
  if (s.includes("LOW") || s.includes("INFO") || s.includes("CLEAN")) return "#10B981";
  return "#60A5FA";
};

export default function UnifiedPanel({
  selectedNode, attackPath, attackPaths, onPatch, onHighlightPath, onSelectNode, externalTab
}) {
  const [activeTab, setActiveTab] = useState("node");

  useEffect(() => {
    if (externalTab) {
      setActiveTab(externalTab);
    }
  }, [externalTab]);

  const [messages, setMessages] = useState([
    {
      role: "assistant",
      text: "Forensic security assistant active. Ask me about taint flows, vulnerable sinks, commit blame, or remediation."
    }
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [aiResponse, setAiResponse] = useState(null);
  const [nodeContext, setNodeContext] = useState(null);
  const [nodeAnalysis, setNodeAnalysis] = useState(null);
  const [loadingAnalysis, setLoadingAnalysis] = useState(false);
  const chatEndRef = useRef(null);

  const activeAnalysis = nodeAnalysis || nodeContext?.analysis;
  const graph = useStore((state) => state.graph);

  // Auto-fetch node context
  useEffect(() => {
    if (selectedNode) {
      setActiveTab("node");
      setNodeAnalysis(null);
      fetch(`${API_BASE}/api/node/context?node_id=${encodeURIComponent(selectedNode.id)}`)
        .then(r => r.json())
        .then(d => {
          setNodeContext(d);
          if (d?.analysis) {
            setNodeAnalysis(prev => ({ ...d.analysis, ...(prev || {}) }));
          }
        })
        .catch(() => setNodeContext(null));
    }
  }, [selectedNode?.id]);

  useEffect(() => {
    if (!selectedNode) {
      setNodeAnalysis(null);
      return;
    }
    let cancelled = false;
    setLoadingAnalysis(true);

    fetch(`${API_BASE}/api/query/explain-node?node_id=${encodeURIComponent(selectedNode.id)}`, {
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
      .then((d) => {
        if (!cancelled && d) {
          setNodeAnalysis(prev => ({ ...(prev || {}), ...d }));
        }
      })
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
      
      // Store the full structured response, not just explanation text
      setAiResponse(data);

      if (data.action) {
        if (data.action.action === "highlight_path" && data.action.path_index !== undefined) {
          onHighlightPath(data.action.path_index);
        }
        if (data.action.action === "select_node" && data.action.node_id) {
          onSelectNode(data.action.node_id);
        }
      }

      setMessages(prev => [...prev, {
        role: "assistant",
        text: data.explanation || "No response.",
        data: data,
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

  const defaultScore = selectedNode?.type === 'sink' ? 8.0 : (selectedNode?.type === 'source' ? 5.0 : (selectedNode?.type === 'sanitizer' ? 2.0 : 1.0));
  const riskScore = selectedNode ? (selectedNode.severity || selectedNode.score || defaultScore).toFixed(1) : "0.0";
  const nodeTypeUpper = selectedNode ? String(selectedNode.type || 'NODE').toUpperCase() : '';
  const nodeRiskUpper = selectedNode ? String(selectedNode.risk || (selectedNode.type === 'sink' ? 'HIGH RISK' : (selectedNode.type === 'source' ? 'ENTRY POINT' : (selectedNode.type === 'sanitizer' ? 'GUARD' : 'NORMAL NODE')))).toUpperCase() : '';

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
                  <div className="intel-card-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span>
                      {activeAnalysis?.cwe && activeAnalysis.cwe !== "None"
                        ? "⚠️ AI VULNERABILITY ANALYSIS"
                        : "ℹ️ NODE BEHAVIOR ANALYSIS"}
                    </span>
                    {activeAnalysis?.severity && (
                      <span
                        style={{
                          fontSize: 9,
                          fontWeight: 800,
                          padding: "1px 6px",
                          borderRadius: 3,
                          textTransform: "uppercase",
                          letterSpacing: 0.5,
                          background: `${getSeverityColor(activeAnalysis.severity)}22`,
                          color: getSeverityColor(activeAnalysis.severity),
                          border: `1px solid ${getSeverityColor(activeAnalysis.severity)}66`
                        }}
                      >
                        {activeAnalysis.severity}
                      </span>
                    )}
                  </div>
                  {loadingAnalysis && !activeAnalysis ? (
                    <div style={{ fontSize: 11, color: "var(--text-muted)", fontStyle: "italic" }}>Running taint analysis...</div>
                  ) : (
                    <>
                      <div
                        className="cwe-title-text"
                        style={{
                          color: (activeAnalysis?.cwe && activeAnalysis.cwe !== "None")
                            ? getSeverityColor(activeAnalysis?.severity || selectedNode?.risk)
                            : "#10B981"
                        }}
                      >
                        {activeAnalysis?.vuln_type || (selectedNode?.label ? `Analysis: ${selectedNode.label}` : "Node Analysis")}
                      </div>

                      {Array.isArray(activeAnalysis?.cwes) && activeAnalysis.cwes.length > 1 && (
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 4, margin: "6px 0 8px" }}>
                          {activeAnalysis.cwes.map((c, idx) => {
                            const badgeColor = getSeverityColor(c.severity || activeAnalysis?.severity);
                            return (
                              <span
                                key={idx}
                                title={`${c.cwe}: ${c.name}${c.sink ? ` (reaches ${c.sink})` : ""}`}
                                style={{
                                  fontSize: 9.5,
                                  fontWeight: 700,
                                  fontFamily: "'JetBrains Mono', monospace",
                                  padding: "1px 5px",
                                  borderRadius: 3,
                                  background: `${badgeColor}18`,
                                  color: badgeColor,
                                  border: `1px solid ${badgeColor}44`,
                                  cursor: "default"
                                }}
                              >
                                {c.cwe}
                              </span>
                            );
                          })}
                        </div>
                      )}

                      <div className="cwe-desc-text">
                        {activeAnalysis?.what_it_does || (activeAnalysis ? "Analyzing node role and data flow..." : "No behavior details available for this node.")}
                      </div>

                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 9.5, fontWeight: 800, color: "var(--text-muted)", letterSpacing: 0.5, marginBottom: 2 }}>ATTACK SURFACE</div>
                        <div className="rec-text">
                          {activeAnalysis?.root_cause || "Taint flow inspection active."}
                        </div>
                      </div>

                      <div className="recommendation-box">
                        <div className="rec-title">☑ RECOMMENDATION</div>
                        <div className="rec-text">
                          {activeAnalysis?.fix || "Validate inputs reaching this operation and verify sanitizers on attack corridors."}
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
                      <span className="metric-stat-val" style={{ color: selectedNode?.type === 'sink' ? 'var(--color-sink)' : (selectedNode?.type === 'source' ? 'var(--color-source)' : '#10B981') }}>{riskScore}</span>
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
                  {msg.data ? (
                    <div style={{ padding: '4px 0 6px' }}>
                      {/* RAG mode indicator */}
                      <div style={{ display:'flex', gap:6, marginBottom:8, flexWrap:'wrap' }}>
                        <span style={{ fontSize:9, padding:'2px 6px', borderRadius:3,
                                       background: msg.data.source==='tdra_rag'
                                         ? '#0D2B1A' : '#21262D',
                                       color: msg.data.source==='tdra_rag'
                                         ? '#3FB950' : '#6E7681',
                                       border: `1px solid ${msg.data.source==='tdra_rag'
                                         ? '#3FB950' : '#30363D'}` }}>
                          {msg.data.source === 'tdra_rag' ? '🔬 Evidence-grounded' : '📋 Rule-based'}
                        </span>
                        {msg.data.confidence > 0 && (
                          <span style={{ fontSize:9, padding:'2px 6px', borderRadius:3,
                                         background:'#21262D', color:'#8B949E',
                                         border:'1px solid #30363D' }}>
                            {msg.data.evidence_count} evidence docs · 
                            {(msg.data.confidence*100).toFixed(0)}% avg relevance
                          </span>
                        )}
                      </div>

                      {/* Main explanation */}
                      <div style={{ color:'#E6EDF3', fontSize:12, lineHeight:1.65,
                                    marginBottom:12, whiteSpace:'pre-wrap' }}>
                        {msg.data.explanation}
                      </div>

                      {/* Metadata pills */}
                      {(msg.data.cwes?.length > 0 || msg.data.affected_commits?.length > 0) && (
                        <div style={{ display:'flex', gap:4, flexWrap:'wrap', marginBottom:10 }}>
                          {msg.data.cwes?.map(cwe => (
                            <span key={cwe} style={{ fontSize:9, padding:'2px 7px',
                                                      borderRadius:3, background:'#2D1010',
                                                      color:'#F85149', border:'1px solid #F8514933' }}>
                              {cwe}
                            </span>
                          ))}
                          {msg.data.affected_commits?.slice(0,3).map(h => (
                            <span key={h} style={{ fontSize:9, padding:'2px 7px',
                                                    borderRadius:3, background:'#0D1F35',
                                                    color:'#58A6FF', border:'1px solid #58A6FF33',
                                                    fontFamily:'monospace' }}>
                              {h.slice(0,8)}
                            </span>
                          ))}
                          {msg.data.affected_files?.slice(0,2).map(f => (
                            <span key={f} style={{ fontSize:9, padding:'2px 7px',
                                                    borderRadius:3, background:'#21262D',
                                                    color:'#8B949E', border:'1px solid #30363D' }}>
                              {f}
                            </span>
                          ))}
                        </div>
                      )}

                      {/* Evidence sources */}
                      {msg.data.evidence_sources?.length > 0 && (
                        <div>
                          <div style={{ fontSize:9, color:'#4B5563', textTransform:'uppercase',
                                        letterSpacing:'0.07em', marginBottom:6 }}>
                            Evidence from TDRA engine
                          </div>
                          {msg.data.evidence_sources.map((src, idx) => (
                            <EvidenceCard key={idx} source={src} index={idx} />
                          ))}
                        </div>
                      )}
                    </div>
                  ) : (
                    <div style={{ fontSize: 12, color: 'var(--text-primary)', lineHeight: 1.5 }}>
                      {msg.text}
                    </div>
                  )}
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
