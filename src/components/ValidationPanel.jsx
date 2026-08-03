import { useState } from "react";
import { API_BASE } from "../api";
import useStore from "../store/useStore";

// ── Inline SVG grouped bar chart ─────────────────────────────────────────────
function RFBarChart({ vccMean, nonVccMean, vccMedian, nonVccMedian }) {
  const W = 240, H = 120, pad = 36, barW = 26, gap = 14;
  const maxVal = Math.max(vccMean, nonVccMean, vccMedian, nonVccMedian, 0.01);
  const scale = (v) => H - pad - (v / maxVal) * (H - pad - 8);
  const bars = [
    { label: "VCC\nMean",     value: vccMean,    color: "#EF4444" },
    { label: "non-VCC\nMean", value: nonVccMean, color: "#10B981" },
    { label: "VCC\nMed",      value: vccMedian,  color: "#F97316" },
    { label: "non-VCC\nMed",  value: nonVccMedian, color: "#06B6D4" },
  ];
  return (
    <svg width={W} height={H + 20} style={{ overflow: "visible" }}>
      {/* Y axis */}
      <line x1={pad} y1={8} x2={pad} y2={H - pad + 4} stroke="#374151" strokeWidth={1} />
      {/* X baseline */}
      <line x1={pad} y1={H - pad + 4} x2={W} y2={H - pad + 4} stroke="#374151" strokeWidth={1} />
      {/* Y ticks */}
      {[0, 0.25, 0.5, 0.75, 1.0].map((t) => (
        <g key={t}>
          <line x1={pad - 3} y1={scale(t)} x2={pad} y2={scale(t)} stroke="#4B5563" strokeWidth={1} />
          <text x={pad - 5} y={scale(t) + 3} textAnchor="end" fill="#6B7280" fontSize={8}>{t.toFixed(2)}</text>
        </g>
      ))}
      {bars.map(({ label, value, color }, i) => {
        const x = pad + gap + i * (barW + gap);
        const y = scale(value);
        const barH = H - pad + 4 - y;
        return (
          <g key={label}>
            <rect x={x} y={y} width={barW} height={barH} fill={color} rx={3} opacity={0.85} />
            <text x={x + barW / 2} y={y - 3} textAnchor="middle" fill={color} fontSize={8} fontWeight="600">
              {value.toFixed(3)}
            </text>
            {label.split("\n").map((ln, li) => (
              <text key={li} x={x + barW / 2} y={H - pad + 16 + li * 9} textAnchor="middle" fill="#9CA3AF" fontSize={7.5}>
                {ln}
              </text>
            ))}
          </g>
        );
      })}
    </svg>
  );
}

// ── Stat row helper ───────────────────────────────────────────────────────────
function StatRow({ label, value, highlight }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", padding: "5px 0", borderBottom: "1px solid #1e2d45" }}>
      <span style={{ color: "#8fa3bf", fontSize: 12 }}>{label}</span>
      <span style={{ color: highlight || "#e2e8f5", fontSize: 12, fontWeight: 600, fontFamily: "monospace" }}>{value}</span>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function ValidationPanel() {
  const [repoPath, setRepoPath] = useState("/app");
  const [vccInput, setVccInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");

  const handleRun = async () => {
    setLoading(true);
    setError("");
    setReport(null);
    try {
      const vccList = vccInput
        .split(/[\n,\s]+/)
        .map((s) => s.trim())
        .filter(Boolean);

      const res = await fetch(`${API_BASE}/api/validation/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repo_path: repoPath,
          known_vcc_commits: vccList,
          use_bundled_vcc: true,
          limit: 50,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Validation failed");
      setReport(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const v = report?.validation;
  const significant = v?.statistically_significant;

  return (
    <div style={{
      background: "#0d1321",
      border: "1px solid #1e2d45",
      borderRadius: 10,
      padding: 16,
      color: "#e2e8f5",
      fontFamily: "system-ui, sans-serif",
      maxWidth: 380,
    }}>
      <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 12, display: "flex", alignItems: "center", gap: 8 }}>
        <span>📊</span> Statistical Validation (RQ1)
      </div>

      {/* Config */}
      <div style={{ marginBottom: 10 }}>
        <label style={{ display: "block", fontSize: 11, color: "#8fa3bf", marginBottom: 4 }}>
          Repo path inside container
        </label>
        <input
          value={repoPath}
          onChange={(e) => setRepoPath(e.target.value)}
          style={{ width: "100%", boxSizing: "border-box", background: "#080c14", border: "1px solid #1e2d45",
            borderRadius: 4, padding: "5px 8px", color: "#e2e8f5", fontSize: 12, outline: "none" }}
        />
      </div>
      <div style={{ marginBottom: 12 }}>
        <label style={{ display: "block", fontSize: 11, color: "#8fa3bf", marginBottom: 4 }}>
          Known VCC hashes (optional, comma/newline separated)
        </label>
        <textarea
          rows={3}
          value={vccInput}
          onChange={(e) => setVccInput(e.target.value)}
          placeholder="e.g. a1b2c3d, deadbeef ..."
          style={{ width: "100%", boxSizing: "border-box", background: "#080c14", border: "1px solid #1e2d45",
            borderRadius: 4, padding: "5px 8px", color: "#e2e8f5", fontSize: 11, outline: "none",
            resize: "vertical", fontFamily: "monospace" }}
        />
      </div>

      <button
        onClick={handleRun}
        disabled={loading}
        style={{
          width: "100%", padding: "8px 0", background: loading ? "#1e2d45" : "#3b82f6",
          color: loading ? "#6B7280" : "#fff", border: "none", borderRadius: 6,
          fontWeight: 600, fontSize: 13, cursor: loading ? "not-allowed" : "pointer",
          marginBottom: 14, transition: "background 0.2s",
        }}
      >
        {loading ? "Running validation…" : "Run Statistical Validation"}
      </button>

      {error && (
        <div style={{ background: "#EF444415", border: "1px solid #EF444430", borderRadius: 6,
          padding: "8px 10px", color: "#EF4444", fontSize: 12, marginBottom: 12 }}>
          {error}
        </div>
      )}

      {v && (
        <>
          {/* Verdict */}
          <div style={{
            background: significant ? "#10B98115" : "#EF444415",
            border: `1px solid ${significant ? "#10B98140" : "#EF444440"}`,
            borderRadius: 8, padding: "10px 14px", marginBottom: 14, textAlign: "center",
          }}>
            <div style={{ fontSize: 22, marginBottom: 4 }}>{significant ? "✅" : "❌"}</div>
            <div style={{ fontWeight: 700, fontSize: 14, color: significant ? "#10B981" : "#EF4444" }}>
              {significant ? "TDRA Validated" : "Not Statistically Significant"}
            </div>
            <div style={{ fontSize: 11, color: "#9CA3AF", marginTop: 4, lineHeight: 1.5 }}>
              {v.interpretation}
            </div>
          </div>

          {/* Stats */}
          <div style={{ marginBottom: 14 }}>
            <StatRow label="Mann-Whitney U" value={v.mann_whitney_u_statistic} />
            <StatRow
              label="p-value"
              value={v.p_value < 0.001 ? "< 0.001" : v.p_value.toFixed(6)}
              highlight={v.p_value < 0.05 ? "#10B981" : "#EF4444"}
            />
            <StatRow label="Cliff's δ" value={v.cliffs_delta} />
            <StatRow
              label="Effect size"
              value={v.effect_size_label.toUpperCase()}
              highlight={
                { large: "#10B981", medium: "#F59E0B", small: "#F97316", negligible: "#EF4444" }[v.effect_size_label]
              }
            />
            <StatRow label="VCC samples" value={v.sample_sizes.vcc} />
            <StatRow label="non-VCC samples" value={v.sample_sizes.non_vcc} />
          </div>

          {/* Bar chart */}
          <div style={{ marginBottom: 6 }}>
            <div style={{ fontSize: 11, color: "#8fa3bf", marginBottom: 8 }}>RF Score Comparison</div>
            <RFBarChart
              vccMean={v.vcc_mean_rf}
              nonVccMean={v.non_vcc_mean_rf}
              vccMedian={v.vcc_median_rf}
              nonVccMedian={v.non_vcc_median_rf}
            />
          </div>

          {/* Sample counts */}
          <div style={{ fontSize: 11, color: "#4a6080", marginTop: 10, borderTop: "1px solid #1e2d45", paddingTop: 8 }}>
            Total commits analysed: <strong style={{ color: "#6B7280" }}>{report.total_commits_analysed}</strong>
            &ensp;|&ensp; VCC: <strong style={{ color: "#EF4444" }}>{report.vcc_commits?.length ?? 0}</strong>
            &ensp;|&ensp; non-VCC: <strong style={{ color: "#10B981" }}>{report.non_vcc_commits?.length ?? 0}</strong>
          </div>
        </>
      )}
    </div>
  );
}
