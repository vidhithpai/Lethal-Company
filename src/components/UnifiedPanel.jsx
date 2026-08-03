import { useState, useRef, useEffect } from "react";
import useStore from "../store/useStore";
import { API_BASE } from "../api";
import ValidationPanel from "./ValidationPanel";

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
  const [aiMode, setAiMode] = useState("groq");
  const chatEndRef = useRef(null);

  const [tdraRepoPath, setTdraRepoPath] = useState("/app");
  const [tdraLimit, setTdraLimit] = useState(20);
  const [tdraCommits, setTdraCommits] = useState([]);
  const [tdraLoading, setTdraLoading] = useState(false);
  const [tdraError, setTdraError] = useState("");
  const [expandedCommit, setExpandedCommit] = useState(null);

  const fetchTdraTimeline = async () => {
    if (!tdraRepoPath.trim()) {
      setTdraError("Repository path is required");
      return;
    }
    setTdraLoading(true);
    setTdraError("");
    setTdraCommits([]);
    try {
      const res = await fetch(`${API_BASE}/api/tdra/timeline?repo_path=${encodeURIComponent(tdraRepoPath.trim())}&limit=${tdraLimit}`);
      if (res.ok) {
        const data = await res.json();
        setTdraCommits(data);
      } else {
        const err = await res.json();
        setTdraError(err.detail || err.error || "Failed to fetch timeline");
      }
    } catch (e) {
      setTdraError("Connection error. Is the backend running?");
    } finally {
      setTdraLoading(false);
    }
  };

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
      setAiMode(data.mode || "groq");

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

  const panelStyle = {
    width: "100%", height: "100%",
    background: "#111827",
    border: "1px solid #1F2937",
    borderRadius: 8,
    display: "flex", flexDirection: "column",
    fontFamily: "system-ui, sans-serif",
    color: "#F9FAFB", fontSize: 13,
    overflow: "hidden"
  };

  const tabStyle = (active) => ({
    flex: 1, padding: "10px 0", textAlign: "center",
    cursor: "pointer", fontSize: 13, fontWeight: 500,
    color: active ? "#3B82F6" : "#6B7280",
    background: "none", border: "none",
    borderBottom: active ? "2px solid #3B82F6" : "2px solid #1F2937"
  });

  return (
    <div style={panelStyle}>
      {/* Tab header */}
      <div style={{ display:"flex", borderBottom:"1px solid #1F2937" }}>
        <button style={tabStyle(activeTab==="node")}
                onClick={() => setActiveTab("node")}>
          Node info {selectedNode ? `· ${selectedNode.label?.slice(0,12)}` : ""}
        </button>
        <button style={tabStyle(activeTab==="chat")}
                onClick={() => setActiveTab("chat")}>
          AI chat
        </button>
        <button style={tabStyle(activeTab==="tdra")}
                onClick={() => setActiveTab("tdra")}>
          TDRA Risk
        </button>
        <button style={tabStyle(activeTab==="validate")}
                onClick={() => setActiveTab("validate")}>
          📊 Validate
        </button>
      </div>

      {/* NODE INFO TAB */}
      {activeTab === "node" && (
        <div style={{ flex:1, overflowY:"auto", padding:14 }}>
          {!selectedNode ? (
            <div style={{ color:"#6B7280", textAlign:"center", marginTop:40 }}>
              Click any node on the graph to inspect it
            </div>
          ) : (
            <>
              {/* Identity */}
              <div style={{ marginBottom:14 }}>
                <div style={{ fontSize:15, fontWeight:600, marginBottom:6 }}>
                  {selectedNode.label}
                </div>
                <div style={{ display:"flex", gap:6, flexWrap:"wrap", alignItems:"center" }}>
                  <RiskBadge risk={selectedNode.risk} />
                  {selectedNode.severity && (
                    <span style={{ fontSize:11, color:"#9CA3AF" }}>
                      Score: {selectedNode.severity.toFixed(1)}/10
                    </span>
                  )}
                  <TypeBadge type={selectedNode.type} />
                  {selectedNode.community && (
                    <span style={{
                      padding:"2px 8px", borderRadius:10,
                      background:"#1F2937", color:"#9CA3AF", fontSize:11
                    }}>
                      {selectedNode.community.replace(/_/g," ")}
                    </span>
                  )}
                </div>
              </div>

              {/* Location */}
              <InfoRow label="File" value={selectedNode.file || "unknown"} />
              <InfoRow label="Line" value={selectedNode.line || "?"} />
              {selectedNode.confidence && (
                <InfoRow label="Taint confidence"
                         value={`${Math.round(selectedNode.confidence*100)}%`} />
              )}

              {/* Attack paths through this node */}
              {nodeContext?.attack_paths_through?.length > 0 && (
                <Section title={`Attack paths (${nodeContext.attack_paths_through.length})`}>
                  <div style={{ fontSize:11, color:"#9CA3AF", marginBottom:8, fontStyle:"italic" }}>
                    Click a path below to simulate the attack trace on the graph
                  </div>
                  {nodeContext.attack_paths_through.slice(0,3).map((p, i) => {
                    const isHoverable = attackPaths && attackPaths.length > 0;
                    return (
                      <div key={i} 
                        onClick={() => {
                          if (!attackPaths) return;
                          const globalIdx = attackPaths.findIndex(ap => ap.path && p.path && ap.path.join(',') === p.path.join(','));
                          if (globalIdx >= 0) {
                            onHighlightPath(globalIdx);
                          }
                        }}
                        style={{
                          background:"#1F2937", borderRadius:6,
                          padding:"8px 10px", marginBottom:6,
                          cursor: isHoverable ? "pointer" : "default",
                          border: "1px solid transparent"
                        }}
                        onMouseEnter={(e) => { if(isHoverable) e.currentTarget.style.border = "1px solid #3B82F6"; }}
                        onMouseLeave={(e) => { e.currentTarget.style.border = "1px solid transparent"; }}
                      >
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <div>
                            <span style={{ color: riskColor(p.risk || p.classification), fontWeight:500 }}>
                              {p.risk || p.classification}
                            </span>
                            <span style={{ color:"#6B7280", marginLeft:8 }}>
                              score {p.score || p.risk_score}
                            </span>
                          </div>
                          {isHoverable && (
                            <span style={{ color:"#3B82F6", fontSize:11, fontWeight:500 }}>
                              ▶ Animate
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </Section>
              )}

              {/* AI Analysis Card */}
              {["sink", "source"].includes(selectedNode.type) && (
                <Section title="AI Vulnerability Analysis">
                  {loadingAnalysis ? (
                    <div style={{ color:"#9CA3AF", fontSize:12, fontStyle:"italic" }}>Analyzing node...</div>
                  ) : nodeAnalysis ? (
                    <div style={{
                      background:"#1F2937", borderRadius:6, padding:"10px 12px",
                      borderLeft:`3px solid ${riskColor(selectedNode.risk)}`
                    }}>
                      <div style={{ fontWeight:600, color:"#F9FAFB", marginBottom:6 }}>
                        {nodeAnalysis.vuln_type}
                        {nodeAnalysis.cwe && <span style={{marginLeft:8, fontSize:10, background:"#374151", padding:"2px 6px", borderRadius:4}}>{nodeAnalysis.cwe}</span>}
                      </div>
                      
                      <div style={{ marginBottom:8 }}>
                        <div style={{ fontSize:10, color:"#9CA3AF", textTransform:"uppercase", marginBottom:2 }}>⚠ Impact</div>
                        <div style={{ fontSize:12, color:"#E5E7EB" }}>{nodeAnalysis.what_it_does}</div>
                      </div>

                      <div style={{ marginBottom:8 }}>
                        <div style={{ fontSize:10, color:"#9CA3AF", textTransform:"uppercase", marginBottom:2 }}>🔬 Attack Surface / Root Cause</div>
                        <div style={{ fontSize:12, color:"#E5E7EB" }}>{nodeAnalysis.root_cause}</div>
                      </div>

                      <div>
                        <div style={{ fontSize:10, color:"#10B981", textTransform:"uppercase", marginBottom:2 }}>✅ Recommendation</div>
                        <div style={{ fontSize:12, color:"#E5E7EB" }}>{nodeAnalysis.fix}</div>
                      </div>
                    </div>
                  ) : (
                    <div style={{ color:"#6B7280", fontSize:12 }}>No analysis available.</div>
                  )}
                </Section>
              )}

              {/* Patch impact */}
              {nodeContext?.patch_impact && (
                <Section title="Patch impact">
                  <div style={{
                    background:"#1F2937", borderRadius:6, padding:"8px 10px"
                  }}>
                    <div style={{ color:"#F59E0B", fontWeight:500, marginBottom:4 }}>
                      {nodeContext.patch_impact.recommendation}
                    </div>
                    <div style={{ color:"#9CA3AF", fontSize:12 }}>
                      Eliminates {nodeContext.patch_impact.eliminated_paths} paths ·
                      Impact score: {nodeContext.patch_impact.impact_score}/10
                    </div>
                  </div>
                </Section>
              )}

              {/* Git blame / Commit attribution */}
              {["sink", "source"].includes(selectedNode.type) && (
                <Section title="Commit attribution">
                  {selectedNode.git_blame?.commit ? (
                    <>
                      <div style={{
                        background:"#1F2937", borderRadius:6,
                        padding:"8px 10px", fontSize:12
                      }}>
                        <div><span style={{color:"#6B7280"}}>Author: </span>
                          {selectedNode.git_blame.author}</div>
                        <div><span style={{color:"#6B7280"}}>Date: </span>
                          {selectedNode.git_blame.date}</div>
                        <div><span style={{color:"#6B7280"}}>Commit: </span>
                          <code style={{color:"#60A5FA"}}>
                            {selectedNode.git_blame.commit}
                          </code>
                        </div>
                        {selectedNode.git_blame.message && (
                          <div style={{color:"#9CA3AF", marginTop:4, fontStyle:"italic"}}>
                            "{selectedNode.git_blame.message}"
                          </div>
                        )}
                      </div>
                      {selectedNode.blast_radius?.length > 0 && (
                        <div style={{ marginTop:6, fontSize:11, color:"#9CA3AF" }}>
                          Blast radius: {selectedNode.blast_radius.length} files —&nbsp;
                          {selectedNode.blast_radius.slice(0,3).join(", ")}
                          {selectedNode.blast_radius.length > 3 &&
                            ` +${selectedNode.blast_radius.length - 3} more`}
                        </div>
                      )}
                    </>
                  ) : (
                    <div style={{
                      background:"#1F2937", borderRadius:6,
                      padding:"8px 10px", fontSize:12, color:"#9CA3AF", fontStyle:"italic"
                    }}>
                      No git history available
                    </div>
                  )}
                </Section>
              )}

              {/* Patch button */}
              {!selectedNode.patched && (
                <button
                  onClick={() => onPatch(selectedNode.id)}
                  style={{
                    width:"100%", marginTop:14, padding:"10px 0",
                    background:"#1D4ED8", color:"#fff",
                    border:"none", borderRadius:6,
                    cursor:"pointer", fontWeight:500, fontSize:13
                  }}>
                  Simulate patch — remove from attack paths
                </button>
              )}
              {selectedNode.patched && (
                <div style={{
                  textAlign:"center", marginTop:14, color:"#6B7280",
                  fontSize:12, padding:"8px 0",
                  border:"1px solid #374151", borderRadius:6
                }}>
                  Node patched — excluded from analysis
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* AI CHAT TAB */}
      {activeTab === "chat" && (
        <div style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden" }}>
          {/* ── AI Mode Badge ── */}
          {(() => {
            const modeMap = {
              groq:       { icon: "🌐", label: "Groq Cloud",  color: "#3B82F6", tip: "Queries sent to Groq Cloud API" },
              local_llm:  { icon: "🤖", label: "Local LLM",   color: "#10B981", tip: "Local mode — your code never leaves this machine" },
              codebert:   { icon: "📚", label: "CodeBERT",    color: "#8B5CF6", tip: "Local mode — your code never leaves this machine" },
              rule_based: { icon: "📋", label: "Rule-Based",  color: "#F59E0B", tip: "Local mode — your code never leaves this machine" },
              rag_only:   { icon: "🔍", label: "RAG Only",    color: "#6B7280", tip: "No AI model — retrieval only" },
            };
            const m = modeMap[aiMode] || modeMap.groq;
            const isLocal = ["local_llm","codebert","rule_based"].includes(aiMode);
            return (
              <div title={m.tip} style={{
                display:"flex", alignItems:"center", gap:6,
                padding:"5px 14px", background:"#111827",
                borderBottom:"1px solid #1F2937", flexShrink:0
              }}>
                <span style={{ fontSize:11 }}>{m.icon}</span>
                <span style={{
                  fontSize:11, fontWeight:600, color: m.color,
                  letterSpacing:"0.04em"
                }}>{m.label}</span>
                {isLocal && (
                  <span style={{
                    fontSize:9, color:"#10B981", background:"#10B98115",
                    border:"1px solid #10B98130", borderRadius:10,
                    padding:"1px 6px", marginLeft:2
                  }}>LOCAL · PRIVATE</span>
                )}
              </div>
            );
          })()}
          <div style={{ flex:1, overflowY:"auto", padding:14 }}>
            {messages.map((msg, i) => (
              <div key={i} style={{ marginBottom:14 }}>
                <div style={{
                  fontSize:11, color:"#6B7280", marginBottom:3,
                  textTransform:"uppercase", letterSpacing:"0.05em"
                }}>
                  {msg.role === "user" ? "You" : "VulnGraph AI"}
                </div>
                <div style={{
                  background: msg.role === "user" ? "#1D4ED8" : "#1F2937",
                  borderRadius: msg.role === "user"
                    ? "12px 12px 4px 12px" : "4px 12px 12px 12px",
                  padding:"10px 12px", fontSize:13, lineHeight:1.6,
                  color: msg.role === "user" ? "#EFF6FF" : "#E5E7EB"
                }}>
                  {msg.text}
                </div>
                {msg.sources?.length > 0 && (
                  <div style={{ marginTop:6 }}>
                    <div style={{ fontSize:10, color:"#6B7280", marginBottom:3 }}>
                      Sources from scan:
                    </div>
                    {msg.sources.map((s, si) => (
                      <div key={si} style={{
                        fontSize:10, color:"#9CA3AF",
                        background:"#111827", borderRadius:4,
                        padding:"4px 8px", marginBottom:2,
                        border:"1px solid #1F2937"
                      }}>
                        {s}
                      </div>
                    ))}
                  </div>
                )}
                {msg.action && msg.action.action === "highlight_path" && attackPaths && attackPaths[msg.action.path_index] && (
                  <div style={{
                    marginTop:10, background:"#111827", border:"1px solid #374151",
                    borderRadius:6, padding:"10px 12px"
                  }}>
                    <div style={{ fontSize:10, color:"#34D399", textTransform:"uppercase", letterSpacing:"0.05em", marginBottom:6 }}>
                      ▶ Live Simulation Active
                    </div>
                    <div style={{ fontSize:12, color:"#E5E7EB", marginBottom:8 }}>
                      <strong>Technical Path Trace:</strong><br/>
                      {attackPaths[msg.action.path_index].source_label} → {attackPaths[msg.action.path_index].sink_label}
                    </div>
                    <div style={{ display:"flex", flexDirection:"column", gap:4 }}>
                      {attackPaths[msg.action.path_index].path.slice(0, 4).map((nodeId, idx) => (
                        <div key={idx} style={{ display:"flex", alignItems:"center", gap:6, fontSize:11, color:"#9CA3AF" }}>
                          <span style={{ color:"#6B7280" }}>{idx+1}.</span>
                          <span style={{ fontFamily:"monospace" }}>{nodeId.split(':').pop()}</span>
                        </div>
                      ))}
                      {attackPaths[msg.action.path_index].path.length > 4 && (
                        <div style={{ fontSize:10, color:"#6B7280", fontStyle:"italic", marginLeft:16 }}>
                          + {attackPaths[msg.action.path_index].path.length - 4} more hops
                        </div>
                      )}
                    </div>
                    <div style={{ marginTop:8, paddingTop:8, borderTop:"1px dashed #374151", fontSize:11, color:"#9CA3AF" }}>
                      Risk Score: {attackPaths[msg.action.path_index].score} | View the 3D graph to see the visual trace.
                    </div>
                  </div>
                )}
                {msg.action && msg.action.action === "select_node" && (
                  <div style={{
                    fontSize:10, color:"#3B82F6", marginTop:4
                  }}>
                    ▶ Highlighted node on graph
                  </div>
                )}
              </div>
            ))}
            {loading && (
              <div style={{ color:"#6B7280", fontStyle:"italic", fontSize:12 }}>
                Searching scan findings...
              </div>
            )}
            <div ref={chatEndRef} />
          </div>

          {/* Chat input */}
          <div style={{
            padding:"10px 14px", borderTop:"1px solid #1F2937",
            display:"flex", gap:8
          }}>
            <input
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === "Enter" && sendMessage()}
              placeholder="Ask about your scan findings..."
              style={{
                flex:1, background:"#1F2937", border:"1px solid #374151",
                borderRadius:6, padding:"8px 12px", color:"#F9FAFB",
                fontSize:13, outline:"none"
              }}
            />
            <button
              onClick={sendMessage}
              disabled={loading}
              style={{
                padding:"8px 16px", background:"#1D4ED8",
                color:"#fff", border:"none", borderRadius:6,
                cursor: loading ? "not-allowed" : "pointer",
                fontSize:13, fontWeight:500
              }}>
              Ask
            </button>
          </div>
        </div>
      )}

      {/* TDRA TIMELINE TAB */}
      {activeTab === "tdra" && (
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          {/* Header controls */}
          <div style={{ padding: 14, borderBottom: "1px solid #1F2937", background: "#1F293750" }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8, color: "#3B82F6" }}>
              TDRA Commit Risk Timeline
            </div>
            <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
              <input
                type="text"
                value={tdraRepoPath}
                onChange={e => setTdraRepoPath(e.target.value)}
                placeholder="Repository Path (e.g. /app)"
                style={{
                  flex: 1, background: "#111827", border: "1px solid #374151",
                  borderRadius: 6, padding: "6px 10px", color: "#F9FAFB",
                  fontSize: 12, outline: "none"
                }}
              />
              <select
                value={tdraLimit}
                onChange={e => setTdraLimit(Number(e.target.value))}
                style={{
                  background: "#111827", border: "1px solid #374151",
                  borderRadius: 6, padding: "6px 6px", color: "#F9FAFB",
                  fontSize: 12, outline: "none"
                }}
              >
                <option value={10}>10</option>
                <option value={20}>20</option>
                <option value={50}>50</option>
              </select>
            </div>
            <button
              onClick={fetchTdraTimeline}
              disabled={tdraLoading}
              style={{
                width: "100%", padding: "8px 0", background: "#1D4ED8",
                color: "#fff", border: "none", borderRadius: 6,
                cursor: tdraLoading ? "not-allowed" : "pointer",
                fontSize: 12, fontWeight: 500
              }}
            >
              {tdraLoading ? "Analyzing repository commits..." : "Analyze Repository"}
            </button>
          </div>

          {/* Timeline content */}
          <div style={{ flex: 1, overflowY: "auto", padding: 14 }}>
            {tdraError && (
              <div style={{ color: "#EF4444", background: "#EF444410", padding: 10, borderRadius: 6, fontSize: 12, marginBottom: 12 }}>
                {tdraError}
              </div>
            )}

            {!tdraLoading && tdraCommits.length === 0 && !tdraError && (
              <div style={{ color: "#6B7280", textAlign: "center", marginTop: 40, fontSize: 12 }}>
                Click "Analyze Repository" to load commit risk factor timeline
              </div>
            )}

            {tdraCommits.map((commit) => {
              const isExpanded = expandedCommit === commit.commit_hash;
              const sevColor = {
                Critical: "#EF4444", High: "#F97316",
                Medium: "#F59E0B", Low: "#10B981"
              }[commit.severity] || "#6B7280";

              return (
                <div key={commit.commit_hash} style={{
                  borderLeft: `2px solid ${sevColor}`,
                  paddingLeft: 12,
                  marginBottom: 16,
                  position: "relative"
                }}>
                  {/* Small circle indicator on the timeline */}
                  <div style={{
                    position: "absolute",
                    left: -5,
                    top: 4,
                    width: 8,
                    height: 8,
                    borderRadius: "50%",
                    background: sevColor,
                    boxShadow: `0 0 6px ${sevColor}`
                  }} />

                  {/* Commit info header */}
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 4 }}>
                    <code style={{ fontSize: 11, color: "#60A5FA", fontWeight: 600 }}>
                      {commit.commit_hash.slice(0, 7)}
                    </code>
                    <span style={{
                      fontSize: 10,
                      fontWeight: 600,
                      color: sevColor,
                      background: `${sevColor}15`,
                      padding: "1px 6px",
                      borderRadius: 4
                    }}>
                      {commit.severity} (RF: {commit.risk_factor})
                    </span>
                  </div>

                  <div style={{ fontSize: 12, color: "#E5E7EB", fontWeight: 500, marginBottom: 2 }}>
                    {commit.message.split("\n")[0]}
                  </div>

                  <div style={{ fontSize: 10, color: "#6B7280", marginBottom: 6 }}>
                    by {commit.author} on {new Date(commit.date).toLocaleDateString()}
                  </div>

                  <div style={{ display: "flex", gap: 12, fontSize: 11, color: "#9CA3AF" }}>
                    <div>
                      <span style={{ color: commit.new_attack_paths > 0 ? "#EF4444" : "#9CA3AF" }}>
                        +{commit.new_attack_paths}
                      </span> new paths
                    </div>
                    <div>
                      <span style={{ color: commit.guard_weakening_events > 0 ? "#F97316" : "#9CA3AF" }}>
                        {commit.guard_weakening_events}
                      </span> weakenings
                    </div>
                  </div>

                  {/* Expand button for paths detail */}
                  {commit.new_attack_paths > 0 && (
                    <div style={{ marginTop: 8 }}>
                      <button
                        onClick={() => setExpandedCommit(isExpanded ? null : commit.commit_hash)}
                        style={{
                          background: "none", border: "none", color: "#3B82F6",
                          padding: 0, cursor: "pointer", fontSize: 11, display: "flex",
                          alignItems: "center", gap: 4
                        }}
                      >
                        {isExpanded ? "▼ Hide introduced paths" : "▶ View introduced paths"}
                      </button>

                      {isExpanded && commit.new_paths_detail && (
                        <div style={{
                          marginTop: 6, background: "#111827", borderRadius: 6,
                          padding: 8, border: "1px solid #1F2937", display: "flex",
                          flexDirection: "column", gap: 6
                        }}>
                          {commit.new_paths_detail.map((pathNodes, pIdx) => (
                            <div key={pIdx} style={{
                              padding: "4px 6px", borderBottom: pIdx < commit.new_paths_detail.length - 1 ? "1px dashed #1F2937" : "none"
                            }}>
                              <div style={{ fontSize: 10, color: "#3B82F6", marginBottom: 2, fontWeight: 600 }}>
                                Path #{pIdx + 1}:
                              </div>
                              <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                                {pathNodes.map((nodeId, nIdx) => (
                                  <div key={nIdx} style={{
                                    fontFamily: "monospace", fontSize: 10, color: "#9CA3AF",
                                    paddingLeft: 8, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis"
                                  }}>
                                    ↳ {nodeId.split(':').pop()}
                                  </div>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* STATISTICAL VALIDATION TAB */}
      {activeTab === "validate" && (
        <div style={{ flex: 1, overflowY: "auto", padding: 14 }}>
          <ValidationPanel />
        </div>
      )}
    </div>
  );
}

// Helper components
const riskColor = (risk) => ({
  CRITICAL: "#EF4444", HIGH: "#F97316",
  MEDIUM: "#F59E0B", LOW: "#10B981"
}[risk] || "#6B7280");

const RiskBadge = ({ risk }) => (
  <span style={{
    padding:"2px 8px", borderRadius:10, fontSize:11, fontWeight:600,
    background: `${riskColor(risk)}20`, color: riskColor(risk)
  }}>{risk || "UNKNOWN"}</span>
);

const TypeBadge = ({ type }) => {
  const colors = {
    source:"#10B981", sink:"#EF4444",
    intermediate:"#F59E0B", sanitizer:"#6366F1", function:"#3B82F6"
  };
  return (
    <span style={{
      padding:"2px 8px", borderRadius:10, fontSize:11,
      background:`${colors[type] || "#6B7280"}20`,
      color: colors[type] || "#6B7280"
    }}>{type}</span>
  );
};

const InfoRow = ({ label, value }) => (
  <div style={{ display:"flex", justifyContent:"space-between",
                padding:"4px 0", borderBottom:"1px solid #1F2937",
                fontSize:12, marginBottom:2 }}>
    <span style={{ color:"#6B7280" }}>{label}</span>
    <span style={{ color:"#E5E7EB", maxWidth:"60%",
                   textAlign:"right", wordBreak:"break-all" }}>
      {value}
    </span>
  </div>
);

const Section = ({ title, children }) => (
  <div style={{ marginTop:14 }}>
    <div style={{ fontSize:11, fontWeight:600, color:"#6B7280",
                  textTransform:"uppercase", letterSpacing:"0.05em",
                  marginBottom:6 }}>
      {title}
    </div>
    {children}
  </div>
);
