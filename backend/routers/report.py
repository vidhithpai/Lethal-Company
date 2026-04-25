from fastapi import APIRouter
from fastapi.responses import JSONResponse, HTMLResponse
from datetime import datetime
import json

router = APIRouter()

# Import these from your existing services:
from backend.services.code_security_graph import (
    get_current_graph, get_current_attack_paths,
    get_current_high_risk_paths
)

@router.get("/api/report/json")
def download_json_report():
    graph = get_current_graph()
    paths = get_current_attack_paths()
    high_risk = get_current_high_risk_paths()

    nodes = graph.get("nodes", [])
    sources = [n for n in nodes if n.get("type") == "source"]
    sinks = [n for n in nodes if n.get("type") == "sink"]

    report = {
        "report_metadata": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "tool": "VulnGraph",
            "version": "1.0.0",
            "project": graph.get("meta", {}).get("scanned_project", "unknown")
        },
        "executive_summary": {
            "total_vulnerabilities": len(sinks),
            "total_attack_paths": len(paths),
            "high_risk_paths": sum(
                1 for p in paths if p.get("classification") in ("HIGH", "CRITICAL") or p.get("risk") in ("HIGH", "CRITICAL", "high", "critical")
            ),
            "critical_paths": sum(
                1 for p in paths if p.get("classification") == "CRITICAL" or p.get("risk") in ("CRITICAL", "critical")
            ),
            "entry_points_exposed": len(sources),
            "files_affected": len(set(
                n.get("file") for n in nodes if n.get("file")
            ))
        },
        "attack_surface": [
            {
                "id": n.get("id"),
                "label": n.get("label"),
                "file": n.get("file"),
                "line": n.get("line"),
                "source_kind": n.get("source_kind"),
                "community": n.get("community")
            }
            for n in sources
        ],
        "vulnerabilities": [
            {
                "id": n.get("id"),
                "label": n.get("label"),
                "file": n.get("file"),
                "line": n.get("line"),
                "risk": n.get("risk"),
                "sink_kind": n.get("sink_kind"),
                "community": n.get("community"),
                "confidence": n.get("confidence"),
                "git_blame": n.get("git_blame"),
                "blast_radius_files": n.get("blast_radius", [])
            }
            for n in sinks
        ],
        "attack_paths": [
            {
                "rank": i + 1,
                "classification": p.get("classification") or p.get("risk"),
                "risk_score": p.get("risk_score") or p.get("score"),
                "source": p.get("source"),
                "sink": p.get("sink"),
                "path": p.get("path"),
                "hops": len(p.get("path", [])),
                "avg_confidence": p.get("avg_confidence")
            }
            for i, p in enumerate(high_risk)
        ],
        "remediation_priorities": _build_remediation_list(sinks, paths)
    }

    return JSONResponse(
        content=report,
        headers={
            "Content-Disposition":
                f'attachment; filename="vulngraph_report_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json"'
        }
    )

def _build_remediation_list(sinks, paths):
    """Rank sinks by how many paths they appear in."""
    from collections import Counter
    sink_path_count = Counter()
    for path in paths:
        for node_id in path.get("path", []):
            sink_path_count[node_id] += 1

    priorities = []
    for sink in sinks:
        node_id = sink.get("id")
        path_count = sink_path_count.get(node_id, 0)
        priorities.append({
            "priority": len(priorities) + 1,
            "node": sink.get("label"),
            "file": sink.get("file"),
            "line": sink.get("line"),
            "risk": sink.get("risk"),
            "paths_eliminated_if_patched": path_count,
            "action": f"Sanitize input before {sink.get('label')} at {sink.get('file')}:{sink.get('line')}"
        })

    priorities.sort(key=lambda x: x["paths_eliminated_if_patched"], reverse=True)
    for i, p in enumerate(priorities):
        p["priority"] = i + 1

    return priorities

@router.get("/api/report/html")
def download_html_report():
    graph = get_current_graph()
    paths = get_current_attack_paths()
    nodes = graph.get("nodes", [])
    sinks = [n for n in nodes if n.get("type") == "sink"]
    sources = [n for n in nodes if n.get("type") == "source"]
    high = [p for p in paths if p.get("classification") in ("HIGH","CRITICAL") or p.get("risk") in ("HIGH", "CRITICAL", "high", "critical", "CRITICAL FIX")]
    project = graph.get("meta", {}).get("scanned_project", "unknown")
    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    def risk_color(risk):
        if not risk: return "#6B7280"
        risk_upper = str(risk).upper()
        if "CRITICAL" in risk_upper: return "#DC2626"
        if "HIGH" in risk_upper: return "#EA580C"
        if "MEDIUM" in risk_upper: return "#D97706"
        if "LOW" in risk_upper: return "#16A34A"
        return "#6B7280"

    sink_rows = ""
    for s in sinks:
        blame = s.get("git_blame") or {}
        sink_rows += f"""
        <tr>
          <td><span style="color:{risk_color(s.get('risk'))};font-weight:600">
            {s.get('risk','?')}</span></td>
          <td><code>{s.get('label','?')}</code></td>
          <td>{s.get('file','?')}:{s.get('line','?')}</td>
          <td>{s.get('sink_kind','?').replace('_',' ')}</td>
          <td>{blame.get('author','unknown')}</td>
          <td>{blame.get('date','unknown')}</td>
        </tr>"""

    path_rows = ""
    for i, p in enumerate(high[:10]):
        path_str = " &rarr; ".join(str(n)[:20] for n in p.get("path",[]))
        risk_class = p.get('classification') or p.get('risk') or 'HIGH'
        score = p.get('risk_score') or p.get('score') or 0
        path_rows += f"""
        <tr>
          <td>{i+1}</td>
          <td><span style="color:{risk_color(risk_class)};font-weight:600">
            {risk_class}</span></td>
          <td>{score:.1f}</td>
          <td style="font-family:monospace;font-size:11px">{path_str}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VulnGraph Security Report — {project}</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
       margin:0;padding:40px;background:#F9FAFB;color:#111827}}
  .header{{background:#111827;color:#fff;padding:32px 40px;
           border-radius:12px;margin-bottom:32px}}
  .header h1{{margin:0;font-size:24px;font-weight:700}}
  .header p{{margin:8px 0 0;color:#9CA3AF;font-size:14px}}
  .summary{{display:grid;grid-template-columns:repeat(4,1fr);
            gap:16px;margin-bottom:32px}}
  .stat{{background:#fff;border:1px solid #E5E7EB;border-radius:8px;
         padding:20px;text-align:center}}
  .stat-num{{font-size:32px;font-weight:700;color:#111827}}
  .stat-lbl{{font-size:13px;color:#6B7280;margin-top:4px}}
  .section{{background:#fff;border:1px solid #E5E7EB;border-radius:8px;
            padding:24px;margin-bottom:24px}}
  .section h2{{margin:0 0 16px;font-size:16px;font-weight:600;
               border-bottom:1px solid #E5E7EB;padding-bottom:12px}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th{{text-align:left;padding:8px 12px;background:#F3F4F6;
      border-bottom:2px solid #E5E7EB;font-weight:600;color:#374151}}
  td{{padding:8px 12px;border-bottom:1px solid #F3F4F6;vertical-align:top}}
  tr:last-child td{{border-bottom:none}}
  code{{background:#F3F4F6;padding:2px 6px;border-radius:4px;
        font-size:12px;font-family:monospace}}
  .footer{{text-align:center;color:#9CA3AF;font-size:12px;
           margin-top:40px;padding-top:20px;
           border-top:1px solid #E5E7EB}}
</style>
</head>
<body>
<div class="header">
  <h1>VulnGraph Security Report</h1>
  <p>Project: {project} · Generated: {generated}</p>
</div>
<div class="summary">
  <div class="stat">
    <div class="stat-num" style="color:#DC2626">{len(sinks)}</div>
    <div class="stat-lbl">Vulnerabilities found</div>
  </div>
  <div class="stat">
    <div class="stat-num" style="color:#EA580C">{len(high)}</div>
    <div class="stat-lbl">High/Critical paths</div>
  </div>
  <div class="stat">
    <div class="stat-num" style="color:#D97706">{len(sources)}</div>
    <div class="stat-lbl">Entry points exposed</div>
  </div>
  <div class="stat">
    <div class="stat-num" style="color:#16A34A">
      {len(set(n.get("file") for n in nodes if n.get("file")))}
    </div>
    <div class="stat-lbl">Files analyzed</div>
  </div>
</div>
<div class="section">
  <h2>Vulnerabilities — sorted by risk</h2>
  <table>
    <thead><tr>
      <th>Risk</th><th>Sink</th><th>Location</th>
      <th>Type</th><th>Introduced by</th><th>Date</th>
    </tr></thead>
    <tbody>{sink_rows}</tbody>
  </table>
</div>
<div class="section">
  <h2>High-risk attack paths (top 10)</h2>
  <table>
    <thead><tr>
      <th>#</th><th>Classification</th><th>Score</th><th>Path</th>
    </tr></thead>
    <tbody>{path_rows}</tbody>
  </table>
</div>
<div class="footer">
  Generated by VulnGraph · AST taint analysis · FusionX Hackathon 2026
</div>
</body>
</html>"""

    return HTMLResponse(
        content=html,
        headers={
            "Content-Disposition":
                f'attachment; filename="vulngraph_report_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.html"'
        }
    )
