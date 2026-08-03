import { useState } from "react";
import useStore from "../store/useStore";
import { API_BASE } from "../api";

export default function CommitTimeline() {
  const commitTimeline = useStore((state) => state.commitTimeline);
  const diffMode = useStore((state) => state.diffMode);
  const selectedCommit = useStore((state) => state.selectedCommit);
  
  const setDiffMode = useStore((state) => state.setDiffMode);
  const setSelectedCommit = useStore((state) => state.setSelectedCommit);
  const setNewPaths = useStore((state) => state.setNewPaths);
  const setRemovedGuards = useStore((state) => state.setRemovedGuards);

  const [repoPath, setRepoPath] = useState("/app");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleCommitClick = async (commit) => {
    setSelectedCommit(commit);
    setDiffMode(true);
    setLoading(true);
    setError("");
    try {
      const res = await fetch(
        `${API_BASE}/api/tdra/commit/${commit.commit_hash}?repo_path=${encodeURIComponent(repoPath)}`
      );
      if (res.ok) {
        const data = await res.json();
        setNewPaths(data.new_paths_detail || []);
        // Save the list of removed guards to show them in the 3D graph
        setRemovedGuards(data.removed_guards || []);
      } else {
        const err = await res.json();
        setError(err.detail || err.error || "Failed to load commit details");
      }
    } catch (e) {
      setError("Network error connecting to backend");
    } finally {
      setLoading(false);
    }
  };

  const getRfColor = (rf) => {
    if (rf < 0.2) return "#10B981"; // green
    if (rf < 0.45) return "#F59E0B"; // yellow
    if (rf < 0.7) return "#F97316"; // orange
    return "#EF4444"; // red
  };

  const getSeverityLabel = (rf) => {
    if (rf < 0.2) return "Low";
    if (rf < 0.45) return "Medium";
    if (rf < 0.7) return "High";
    return "Critical";
  };

  return (
    <div
      style={{
        width: 280,
        height: "100%",
        background: "#0d1321",
        borderLeft: "1px solid #1e2d45",
        display: "flex",
        flexDirection: "column",
        color: "#e2e8f5",
        fontFamily: "system-ui, sans-serif",
        fontSize: 13,
        overflow: "hidden",
      }}
    >
      <div style={{ padding: 14, borderBottom: "1px solid #1e2d45" }}>
        <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 8 }}>
          Commit Risk Timeline
        </div>
        
        {/* Repo path configuration */}
        <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
          <input
            type="text"
            value={repoPath}
            onChange={(e) => setRepoPath(e.target.value)}
            placeholder="Repo Path (e.g. /app)"
            style={{
              flex: 1,
              background: "#080c14",
              border: "1px solid #1e2d45",
              borderRadius: 4,
              padding: "4px 8px",
              color: "#e2e8f5",
              fontSize: 11,
              outline: "none",
            }}
          />
        </div>

        {diffMode && (
          <button
            onClick={() => {
              setDiffMode(false);
              setSelectedCommit(null);
              setNewPaths([]);
              setRemovedGuards([]);
            }}
            style={{
              width: "100%",
              padding: "6px 0",
              background: "#EF444420",
              color: "#EF4444",
              border: "1px solid #EF444440",
              borderRadius: 6,
              cursor: "pointer",
              fontWeight: 600,
              fontSize: 11,
            }}
          >
            Exit Diff Mode
          </button>
        )}
      </div>

      <div style={{ flex: 1, overflowY: "auto", padding: 12 }}>
        {loading && (
          <div style={{ textAlign: "center", color: "#8fa3bf", padding: 10, fontStyle: "italic" }}>
            Loading commit details...
          </div>
        )}
        
        {error && (
          <div style={{ color: "#EF4444", background: "#EF444410", padding: 8, borderRadius: 4, marginBottom: 10, fontSize: 11 }}>
            {error}
          </div>
        )}

        {!loading && commitTimeline.length === 0 && (
          <div style={{ color: "#4a6080", textAlign: "center", marginTop: 40 }}>
            No commit timeline data found
          </div>
        )}

        {commitTimeline.map((commit) => {
          const isSelected = selectedCommit?.commit_hash === commit.commit_hash;
          const rf = commit.risk_factor;
          const rfColor = getRfColor(rf);

          return (
            <div
              key={commit.commit_hash}
              onClick={() => handleCommitClick(commit)}
              style={{
                background: isSelected ? "#121929" : "transparent",
                border: isSelected ? "1px solid #3b82f6" : "1px solid transparent",
                borderRadius: 6,
                padding: 10,
                marginBottom: 8,
                cursor: "pointer",
                transition: "background 0.2s",
              }}
              onMouseEnter={(e) => {
                if (!isSelected) e.currentTarget.style.background = "#161e30";
              }}
              onMouseLeave={(e) => {
                if (!isSelected) e.currentTarget.style.background = "transparent";
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                <span style={{ fontFamily: "monospace", color: "#3b82f6", fontWeight: 600 }}>
                  {commit.commit_hash.slice(0, 7)}
                </span>
                <span
                  style={{
                    fontSize: 10,
                    fontWeight: 600,
                    color: rfColor,
                    background: `${rfColor}20`,
                    padding: "1px 6px",
                    borderRadius: 4,
                  }}
                >
                  {getSeverityLabel(rf)} ({rf.toFixed(2)})
                </span>
              </div>

              <div
                style={{
                  fontSize: 12,
                  color: "#e2e8f5",
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  marginBottom: 2,
                }}
              >
                {commit.message.substring(0, 40)}
              </div>

              <div style={{ fontSize: 10, color: "#8fa3bf", marginBottom: 6 }}>
                by {commit.author}
              </div>

              {/* Visual RF Bar */}
              <div style={{ width: "100%", height: 4, background: "#1e2d45", borderRadius: 2, overflow: "hidden" }}>
                <div style={{ width: `${rf * 100}%`, height: "100%", background: rfColor }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
