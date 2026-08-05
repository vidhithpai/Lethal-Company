import React from "react";

const T = {
  bg:      "#0B1D26",
  border:  "#1C3D4B",
  trace:   "#49C7C0",
  inkDim:  "#7FA0AC",
  ink:     "#E7EEF0",
};

/**
 * ViewToggle — segmented 3D / 2D pill
 * Positioned absolute by the parent (GraphCanvas); parent must have position:relative.
 *
 * Props:
 *   mode     : '3d' | '2d'
 *   onChange : (mode: '3d' | '2d') => void
 */
const ViewToggle = ({ mode, onChange }) => {
  const options = ["3d", "2d"];

  return (
    <div
      aria-label="Graph view mode"
      role="group"
      style={{
        position: "absolute",
        top: 16,
        right: 16,
        zIndex: 20,
        display: "flex",
        border: `1px solid ${T.border}`,
        borderRadius: 4,
        overflow: "hidden",
        fontFamily: "'IBM Plex Mono', monospace",
      }}
    >
      {options.map((opt) => {
        const active = mode === opt;
        return (
          <button
            key={opt}
            onClick={() => onChange(opt)}
            aria-pressed={active}
            style={{
              padding: "6px 14px",
              fontSize: 11,
              fontFamily: "'IBM Plex Mono', monospace",
              fontWeight: 600,
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              cursor: "pointer",
              border: "none",
              outline: "none",
              transition: "background 0.15s, color 0.15s",
              background: active ? T.trace : "rgba(11,29,38,0.88)",
              color:      active ? "#080c14" : T.inkDim,
              borderRight: opt === "3d" ? `1px solid ${T.border}` : "none",
            }}
            onMouseEnter={(e) => {
              if (!active) {
                e.currentTarget.style.color = T.ink;
              }
            }}
            onMouseLeave={(e) => {
              if (!active) {
                e.currentTarget.style.color = T.inkDim;
              }
            }}
          >
            {opt.toUpperCase()}
          </button>
        );
      })}
    </div>
  );
};

export default ViewToggle;
