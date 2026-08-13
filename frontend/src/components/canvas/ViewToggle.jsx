import React from "react";

/**
 * ViewToggle — segmented 3D / 2D pill matching mockup
 * Positioned in top-right HUD of graph canvas.
 */
const ViewToggle = ({ mode, onChange }) => {
  return (
    <div
      aria-label="Graph view mode"
      role="group"
      style={{
        display: "inline-flex",
        background: "rgba(11, 19, 36, 0.92)",
        border: "1px solid rgba(30, 45, 69, 0.8)",
        borderRadius: 6,
        padding: 3,
        backdropFilter: "blur(12px)",
        boxShadow: "0 4px 16px rgba(0, 0, 0, 0.4)",
        fontFamily: "'JetBrains Mono', monospace",
        zIndex: 30,
      }}
    >
      <button
        onClick={() => onChange("3d")}
        aria-pressed={mode === "3d"}
        style={{
          padding: "5px 14px",
          fontSize: 11,
          fontFamily: "'JetBrains Mono', monospace",
          fontWeight: 800,
          letterSpacing: "0.05em",
          cursor: "pointer",
          border: "none",
          borderRadius: 4,
          outline: "none",
          transition: "all 0.2s ease",
          background: mode === "3d" ? "linear-gradient(135deg, #2563EB 0%, #06B6D4 100%)" : "transparent",
          color: mode === "3d" ? "#FFFFFF" : "#64748B",
          boxShadow: mode === "3d" ? "0 2px 8px rgba(6, 182, 212, 0.35)" : "none",
        }}
      >
        3D
      </button>

      <button
        onClick={() => onChange("2d")}
        aria-pressed={mode === "2d"}
        style={{
          padding: "5px 14px",
          fontSize: 11,
          fontFamily: "'JetBrains Mono', monospace",
          fontWeight: 800,
          letterSpacing: "0.05em",
          cursor: "pointer",
          border: "none",
          borderRadius: 4,
          outline: "none",
          transition: "all 0.2s ease",
          background: mode === "2d" ? "linear-gradient(135deg, #2563EB 0%, #06B6D4 100%)" : "transparent",
          color: mode === "2d" ? "#FFFFFF" : "#64748B",
          boxShadow: mode === "2d" ? "0 2px 8px rgba(6, 182, 212, 0.35)" : "none",
        }}
      >
        2D
      </button>
    </div>
  );
};

export default ViewToggle;
