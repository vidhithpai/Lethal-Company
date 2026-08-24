import React from "react";
import useStore from "../../store/useStore";

const RF_COLOR = (rf) => {
  if (rf >= 0.7) return { bg: "#3D1212", border: "#FF4444", text: "#FF4444" };
  if (rf >= 0.45) return { bg: "#3D2A0A", border: "#FF9500", text: "#FF9500" };
  if (rf >= 0.2) return { bg: "#3D3400", border: "#FFD700", text: "#FFD700" };
  return { bg: "#0D2B1A", border: "#1D9E75", text: "#1D9E75" };
};

const SEVERITY_LABEL = (rf) => {
  if (rf >= 0.7) return "CRITICAL";
  if (rf >= 0.45) return "HIGH";
  if (rf >= 0.2) return "MEDIUM";
  return "LOW";
};

export default function CommitTimeline({ repoPath }) {
  const commitTimeline = useStore((s) => s.commitTimeline);
  const setCommitTimeline = useStore((s) => s.setCommitTimeline);
  const diffMode = useStore((s) => s.diffMode);
  const setDiffMode = useStore((s) => s.setDiffMode);
  const setSelectedCommit = useStore((s) => s.setSelectedCommit);
  const setNewPaths = useStore((s) => s.setNewPaths);
  const selectedCommit = useStore((s) => s.selectedCommit);

  // Load timeline on mount
  React.useEffect(() => {
    if (!repoPath) return;
    fetch(`/api/tdra/timeline?repo_path=${encodeURIComponent(repoPath)}&limit=50`)
      .then(r => r.json())
      .then(d => setCommitTimeline(d.timeline || []))
      .catch(() => {});
  }, [repoPath]);

  const handleSelectCommit = async (commit) => {
    setSelectedCommit(commit);
    setDiffMode(true);
    setNewPaths(commit.new_paths_detail || []);
  };

  return (
    <div style={{
      width: 280, height: "100%", overflowY: "auto",
      background: "#0D1117", borderLeft: "1px solid #21262D",
      display: "flex", flexDirection: "column",
    }}>
      {/* Header */}
      <div style={{
        padding: "12px 14px", borderBottom: "1px solid #21262D",
        display: "flex", justifyContent: "space-between", alignItems: "center",
        position: "sticky", top: 0, background: "#0D1117", zIndex: 10,
      }}>
        <span style={{ color: "#E6EDF3", fontSize: 13, fontWeight: 500 }}>
          Commit Risk Timeline
        </span>
        {diffMode && (
          <button onClick={() => { setDiffMode(false); setSelectedCommit(null); setNewPaths([]); }}
            style={{
              fontSize: 11, padding: "2px 8px", borderRadius: 4, cursor: "pointer",
              background: "#21262D", border: "1px solid #444", color: "#CCC",
            }}>
            ✕ Exit Diff
          </button>
        )}
      </div>

      {/* Commits */}
      <div style={{ flex: 1, overflowY: "auto" }}>
        {commitTimeline.length === 0 && (
          <div style={{ padding: 16, color: "#666", fontSize: 12 }}>
            No commits loaded. Scan a git repository first.
          </div>
        )}
        {[...commitTimeline].reverse().map((commit) => {
          const rf = commit.risk_factor || 0;
          const col = RF_COLOR(rf);
          const isSelected = selectedCommit?.commit_hash === commit.commit_hash;
          return (
            <div key={commit.commit_hash}
              onClick={() => handleSelectCommit(commit)}
              style={{
                padding: "10px 14px", borderBottom: "1px solid #21262D",
                cursor: "pointer", transition: "background 0.15s",
                background: isSelected ? col.bg : "transparent",
                borderLeft: isSelected ? `3px solid ${col.border}` : "3px solid transparent",
              }}
            >
              {/* Hash + author */}
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                <span style={{ color: "#58A6FF", fontSize: 11, fontFamily: "monospace" }}>
                  {commit.commit_hash?.slice(0, 7)}
                </span>
                <span style={{
                  fontSize: 10, padding: "1px 6px", borderRadius: 3,
                  background: col.bg, border: `1px solid ${col.border}`,
                  color: col.text, fontWeight: 600,
                }}>
                  {SEVERITY_LABEL(rf)}
                </span>
              </div>

              {/* Message */}
              <div style={{ color: "#E6EDF3", fontSize: 12, marginBottom: 4,
                whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                {commit.message?.slice(0, 45) || "(no message)"}
              </div>

              {/* RF bar */}
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <div style={{ flex: 1, height: 3, background: "#21262D", borderRadius: 2 }}>
                  <div style={{
                    width: `${Math.min(rf * 100, 100)}%`, height: 3,
                    background: col.border, borderRadius: 2,
                    transition: "width 0.3s",
                  }} />
                </div>
                <span style={{ color: col.text, fontSize: 10, fontFamily: "monospace",
                  minWidth: 32, textAlign: "right" }}>
                  {rf.toFixed(3)}
                </span>
              </div>

              {/* Meta */}
              <div style={{ color: "#666", fontSize: 10, marginTop: 3 }}>
                {commit.author} · {commit.new_attack_paths || 0} new paths
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
