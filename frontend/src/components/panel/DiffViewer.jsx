import React, { useState, useEffect } from "react";
import { endpoints } from "../../services/api";

const BADGE_CONFIG = {
  entry: { label: "ENTRY", color: "#3FB950", bg: "rgba(63, 185, 80, 0.2)", border: "#3FB950" },
  sink: { label: "SINK", color: "#F85149", bg: "rgba(248, 81, 73, 0.2)", border: "#F85149" },
  guard: { label: "GUARD", color: "#A371F7", bg: "rgba(163, 113, 247, 0.2)", border: "#A371F7" },
  new_path: { label: "NEW PATH", color: "#FF9500", bg: "rgba(255, 149, 0, 0.2)", border: "#FF9500" },
  guard_removed: { label: "GUARD REMOVED", color: "#FF9500", bg: "rgba(255, 149, 0, 0.2)", border: "#FF9500" },
};

const STATUS_CONFIG = {
  modified: { label: "MODIFIED", color: "#58A6FF", bg: "rgba(88, 166, 255, 0.15)", border: "#58A6FF" },
  added: { label: "ADDED", color: "#3FB950", bg: "rgba(63, 185, 80, 0.15)", border: "#3FB950" },
  deleted: { label: "DELETED", color: "#F85149", bg: "rgba(248, 81, 73, 0.15)", border: "#F85149" },
  renamed: { label: "RENAMED", color: "#D29922", bg: "rgba(210, 153, 34, 0.15)", border: "#D29922" },
  binary: { label: "BINARY", color: "#8B949E", bg: "rgba(139, 148, 158, 0.15)", border: "#8B949E" },
};

export default function DiffViewer({ repoPath, commitHash, onClose }) {
  const [diffData, setDiffData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [collapsedFiles, setCollapsedFiles] = useState({});
  const [showOnlyChanged, setShowOnlyChanged] = useState(false);
  const [showOnlySecurity, setShowOnlySecurity] = useState(false);

  useEffect(() => {
    if (!commitHash) return;

    let isMounted = true;
    setLoading(true);
    setError(null);

    const effectiveRepo = repoPath || localStorage.getItem("repo_path") || "./demo_project";
    const url = endpoints.commitDiff(commitHash, effectiveRepo);

    fetch(url)
      .then((res) => {
        if (!res.ok) {
          return res.json().then(
            (err) => {
              throw new Error(err.detail || `Server error (HTTP ${res.status})`);
            },
            () => {
              throw new Error(`Failed to load diff (HTTP ${res.status})`);
            }
          );
        }
        return res.json();
      })
      .then((data) => {
        if (!isMounted) return;
        setDiffData(data);
        setCollapsedFiles({});
      })
      .catch((err) => {
        if (!isMounted) return;
        setError(err.message);
      })
      .finally(() => {
        if (isMounted) setLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, [commitHash, repoPath]);

  const toggleFileCollapse = (path) => {
    setCollapsedFiles((prev) => ({
      ...prev,
      [path]: !prev[path],
    }));
  };

  const shortHash = commitHash ? commitHash.slice(0, 7) : "commit";

  if (loading) {
    return (
      <div style={{ padding: 24, color: "#8B949E", fontSize: 13, textAlign: "center" }}>
        <div style={{ marginBottom: 8, fontSize: 16 }}>⏳ Loading commit diff...</div>
        <div style={{ fontSize: 11, fontFamily: "monospace", color: "#58A6FF" }}>{shortHash}</div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ padding: 16, background: "rgba(248,81,73,0.1)", border: "1px solid #F85149", borderRadius: 6, margin: 12 }}>
        <div style={{ color: "#F85149", fontWeight: 600, fontSize: 13, marginBottom: 4 }}>
          Error loading commit diff
        </div>
        <div style={{ color: "#E6EDF3", fontSize: 12, wordBreak: "break-word" }}>{error}</div>
      </div>
    );
  }

  if (!diffData || !diffData.files) {
    return (
      <div style={{ padding: 20, color: "#8B949E", fontSize: 12, textAlign: "center" }}>
        No diff information available for commit {shortHash}.
      </div>
    );
  }

  const files = diffData.files;
  const totalAdditions = files.reduce((acc, f) => acc + (f.additions || 0), 0);
  const totalDeletions = files.reduce((acc, f) => acc + (f.deletions || 0), 0);

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        background: "#0D1117",
        color: "#E6EDF3",
        fontSize: 12,
        fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
      }}
    >
      {/* ── Top Header ────────────────────────────────────────────── */}
      <div
        style={{
          padding: "10px 14px",
          borderBottom: "1px solid #21262D",
          background: "#161B22",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 8,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontFamily: "monospace", color: "#58A6FF", fontWeight: 700, fontSize: 12 }}>
            {shortHash}
          </span>
          <span style={{ color: "#8B949E", fontSize: 11 }}>
            {files.length} {files.length === 1 ? "file" : "files"} changed
          </span>
          <div style={{ display: "flex", gap: 6, fontSize: 11, fontWeight: 600 }}>
            <span style={{ color: "#3FB950" }}>+{totalAdditions}</span>
            <span style={{ color: "#F85149" }}>-{totalDeletions}</span>
          </div>
        </div>

        {onClose && (
          <button
            onClick={onClose}
            style={{
              background: "#21262D",
              border: "1px solid #30363D",
              color: "#8B949E",
              padding: "2px 8px",
              borderRadius: 4,
              cursor: "pointer",
              fontSize: 11,
            }}
          >
            ✕ Close
          </button>
        )}
      </div>

      {/* ── Truncation Notice ─────────────────────────────────────── */}
      {diffData.truncated && (
        <div
          style={{
            padding: "8px 14px",
            background: "rgba(210,153,34,0.15)",
            borderBottom: "1px solid rgba(210,153,34,0.3)",
            color: "#D29922",
            fontSize: 11,
            display: "flex",
            alignItems: "center",
            gap: 6,
          }}
        >
          <span>⚠️</span>
          <span>Diff output capped at 2,000 lines. Remaining lines truncated.</span>
        </div>
      )}

      {/* ── Legend & Controls ─────────────────────────────────────── */}
      <div
        style={{
          padding: "8px 14px",
          borderBottom: "1px solid #21262D",
          background: "#0D1117",
          display: "flex",
          flexDirection: "column",
          gap: 8,
        }}
      >
        {/* Badges Legend */}
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6, alignItems: "center", fontSize: 10 }}>
          <span style={{ color: "#8B949E", fontWeight: 600, marginRight: 2 }}>LEGEND:</span>
          <span style={{ color: "#3FB950", background: "rgba(63,185,80,0.15)", padding: "1px 6px", borderRadius: 3, border: "1px solid rgba(63,185,80,0.3)" }}>
            + Added
          </span>
          <span style={{ color: "#F85149", background: "rgba(248,81,73,0.15)", padding: "1px 6px", borderRadius: 3, border: "1px solid rgba(248,81,73,0.3)" }}>
            - Deleted
          </span>
          {Object.entries(BADGE_CONFIG).map(([key, cfg]) => (
            <span
              key={key}
              style={{
                color: cfg.color,
                background: cfg.bg,
                border: `1px solid ${cfg.border}`,
                padding: "1px 6px",
                borderRadius: 3,
                fontWeight: 600,
              }}
            >
              {cfg.label}
            </span>
          ))}
        </div>

        {/* Filter Toggles */}
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
          <label style={{ display: "flex", alignItems: "center", gap: 5, cursor: "pointer", fontSize: 11, color: "#C9D1D9" }}>
            <input
              type="checkbox"
              checked={showOnlyChanged}
              onChange={(e) => setShowOnlyChanged(e.target.checked)}
              style={{ accentColor: "#58A6FF", cursor: "pointer" }}
            />
            Show only changed lines
          </label>
          <label style={{ display: "flex", alignItems: "center", gap: 5, cursor: "pointer", fontSize: 11, color: "#C9D1D9" }}>
            <input
              type="checkbox"
              checked={showOnlySecurity}
              onChange={(e) => setShowOnlySecurity(e.target.checked)}
              style={{ accentColor: "#FF9500", cursor: "pointer" }}
            />
            Show only security-marked lines
          </label>
        </div>
      </div>

      {/* ── Files & Hunks Diff View ───────────────────────────────── */}
      <div style={{ flex: 1, overflowY: "auto", overflowX: "auto" }}>
        {files.length === 0 ? (
          <div style={{ padding: 24, textAlign: "center", color: "#8B949E" }}>
            No file changes in this commit.
          </div>
        ) : (
          files.map((file) => {
            const isCollapsed = !!collapsedFiles[file.path];
            const statusCfg = STATUS_CONFIG[file.status] || STATUS_CONFIG.modified;

            return (
              <div key={file.path} style={{ borderBottom: "1px solid #21262D" }}>
                {/* File Header */}
                <div
                  onClick={() => toggleFileCollapse(file.path)}
                  style={{
                    padding: "8px 12px",
                    background: "#161B22",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    cursor: "pointer",
                    userSelect: "none",
                    borderTop: "1px solid #21262D",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
                    <span style={{ fontSize: 10, color: "#8B949E", width: 12 }}>
                      {isCollapsed ? "▶" : "▼"}
                    </span>
                    <span
                      style={{
                        fontFamily: "monospace",
                        fontWeight: 600,
                        color: "#E6EDF3",
                        fontSize: 12,
                        wordBreak: "break-all",
                      }}
                      title={file.path}
                    >
                      {file.path}
                    </span>
                    <span
                      style={{
                        fontSize: 9.5,
                        fontWeight: 700,
                        padding: "1px 5px",
                        borderRadius: 3,
                        color: statusCfg.color,
                        background: statusCfg.bg,
                        border: `1px solid ${statusCfg.border}`,
                      }}
                    >
                      {statusCfg.label}
                    </span>
                  </div>

                  {file.status !== "binary" && (
                    <div style={{ display: "flex", gap: 6, fontSize: 11, fontFamily: "monospace", flexShrink: 0, marginLeft: 8 }}>
                      <span style={{ color: "#3FB950" }}>+{file.additions}</span>
                      <span style={{ color: "#F85149" }}>-{file.deletions}</span>
                    </div>
                  )}
                </div>

                {/* File Body */}
                {!isCollapsed && (
                  <div>
                    {file.status === "binary" ? (
                      <div style={{ padding: "12px 20px", color: "#8B949E", fontStyle: "italic", fontSize: 11 }}>
                        Binary file — changes not shown
                      </div>
                    ) : (
                      file.hunks.map((hunk, hIdx) => {
                        // Filter lines based on active toggles
                        const visibleLines = hunk.lines.filter((line) => {
                          if (showOnlyChanged && line.type === "context") return false;
                          if (showOnlySecurity && (!line.marks || line.marks.length === 0)) return false;
                          return true;
                        });

                        if (visibleLines.length === 0 && (showOnlyChanged || showOnlySecurity)) {
                          return null;
                        }

                        return (
                          <div key={hIdx} style={{ borderTop: "1px solid #21262D" }}>
                            {/* Hunk Header */}
                            <div
                              style={{
                                padding: "4px 12px",
                                background: "#13161C",
                                color: "#8B949E",
                                fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace",
                                fontSize: 11,
                                borderBottom: "1px solid #21262D",
                              }}
                            >
                              {hunk.header}
                            </div>

                            {/* Lines */}
                            <div style={{ overflowX: "auto" }}>
                              {visibleLines.map((line, lIdx) => {
                                const isAdd = line.type === "add";
                                const isDel = line.type === "del";

                                const bg = isAdd
                                  ? "rgba(63, 185, 80, 0.15)"
                                  : isDel
                                  ? "rgba(248, 81, 73, 0.15)"
                                  : "transparent";

                                const borderLeft = isAdd
                                  ? "3px solid #3FB950"
                                  : isDel
                                  ? "3px solid #F85149"
                                  : "3px solid transparent";

                                const prefix = isAdd ? "+" : isDel ? "-" : " ";
                                const textColor = isAdd ? "#E6EDF3" : isDel ? "#FFA198" : "#8B949E";

                                return (
                                  <div
                                    key={lIdx}
                                    style={{
                                      display: "flex",
                                      alignItems: "stretch",
                                      background: bg,
                                      borderLeft,
                                      lineHeight: "20px",
                                      fontSize: 11.5,
                                      fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace",
                                      whiteSpace: "pre",
                                      minWidth: "max-content",
                                    }}
                                  >
                                    {/* Old Line Gutter */}
                                    <div
                                      style={{
                                        width: 40,
                                        textAlign: "right",
                                        paddingRight: 6,
                                        color: "#6E7681",
                                        userSelect: "none",
                                        flexShrink: 0,
                                      }}
                                    >
                                      {line.old_no != null ? line.old_no : ""}
                                    </div>

                                    {/* New Line Gutter */}
                                    <div
                                      style={{
                                        width: 40,
                                        textAlign: "right",
                                        paddingRight: 8,
                                        color: "#6E7681",
                                        userSelect: "none",
                                        flexShrink: 0,
                                        borderRight: "1px solid #21262D",
                                      }}
                                    >
                                      {line.new_no != null ? line.new_no : ""}
                                    </div>

                                    {/* Prefix Symbol */}
                                    <div
                                      style={{
                                        width: 18,
                                        textAlign: "center",
                                        color: isAdd ? "#3FB950" : isDel ? "#F85149" : "transparent",
                                        userSelect: "none",
                                        flexShrink: 0,
                                        fontWeight: 600,
                                      }}
                                    >
                                      {prefix}
                                    </div>

                                    {/* Code Content */}
                                    <div
                                      style={{
                                        paddingRight: 16,
                                        color: textColor,
                                        flexGrow: 1,
                                      }}
                                    >
                                      {line.text}
                                    </div>

                                    {/* Security Badges */}
                                    {line.marks && line.marks.length > 0 && (
                                      <div
                                        style={{
                                          marginLeft: "auto",
                                          paddingRight: 12,
                                          display: "flex",
                                          alignItems: "center",
                                          gap: 4,
                                          flexShrink: 0,
                                        }}
                                      >
                                        {line.marks.map((mark, mIdx) => {
                                          const cfg = BADGE_CONFIG[mark] || {
                                            label: mark.toUpperCase(),
                                            color: "#FF9500",
                                            bg: "rgba(255,149,0,0.2)",
                                            border: "#FF9500",
                                          };
                                          return (
                                            <span
                                              key={mIdx}
                                              style={{
                                                fontSize: 9,
                                                fontWeight: 800,
                                                color: cfg.color,
                                                background: cfg.bg,
                                                border: `1px solid ${cfg.border}`,
                                                padding: "0 5px",
                                                borderRadius: 3,
                                                lineHeight: "15px",
                                                display: "inline-block",
                                              }}
                                            >
                                              {cfg.label}
                                            </span>
                                          );
                                        })}
                                      </div>
                                    )}
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        );
                      })
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

