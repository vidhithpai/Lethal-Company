from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse, HTMLResponse
from datetime import datetime
import json
import html as html_module

router = APIRouter()

from backend.services.code_security_graph import (
    get_current_graph, get_current_attack_paths,
    get_current_high_risk_paths
)
from backend.routers.query import _groq_client, AI_AVAILABLE, _cache as ai_query_cache


# ── Helpers ──────────────────────────────────────────────────────────────────

def _generate_ai_summary(project, sinks_len, high_len, sources_len, files_len):
    if not AI_AVAILABLE or not _groq_client:
        return (
            f"Scan completed for <b>{project}</b>. Found <b>{sinks_len}</b> vulnerabilities "
            f"across <b>{files_len}</b> files, with <b>{high_len}</b> high-risk attack paths "
            f"originating from <b>{sources_len}</b> entry points."
        )
    prompt = (
        f"Write a 2-sentence executive security summary for a project named '{project}'. "
        f"The scan found {sinks_len} vulnerabilities, {high_len} high/critical attack paths, "
        f"and {sources_len} exposed entry points across {files_len} files. "
        "Be professional and concise."
    )
    try:
        response = _groq_client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.3-70b-versatile",
            temperature=0.3,
            max_tokens=150
        )
        return response.choices[0].message.content.strip()
    except Exception:
        return (
            f"Scan completed for <b>{project}</b>. Found <b>{sinks_len}</b> vulnerabilities "
            f"across <b>{files_len}</b> files, with <b>{high_len}</b> high-risk attack paths "
            f"originating from <b>{sources_len}</b> entry points."
        )


def _risk_badge(risk: str) -> str:
    r = (risk or "").upper()
    if "CRITICAL" in r:
        return f'<span class="badge crit">{risk}</span>'
    if "HIGH" in r:
        return f'<span class="badge high">{risk}</span>'
    if "MEDIUM" in r:
        return f'<span class="badge med">{risk}</span>'
    return f'<span class="badge low">{risk or "LOW"}</span>'


def _sink_recommendation(sink_kind: str) -> str:
    k = (sink_kind or "").lower()
    if "sql" in k:
        return "Use parameterized queries (PreparedStatement / cursor.execute with placeholders)"
    if "os" in k or "command" in k or "exec" in k or "shell" in k:
        return "Use ProcessBuilder with argument array — never pass user input to shell=True"
    if "file" in k or "path" in k or "read" in k or "write" in k:
        return "Validate and canonicalize paths; reject directory-traversal sequences (..)"
    if "eval" in k or "dynamic" in k or "code" in k:
        return "Eliminate dynamic code execution; replace eval() with safe data-driven alternatives"
    if "xss" in k or "html" in k or "render" in k:
        return "HTML-encode all user-supplied output; apply Content-Security-Policy headers"
    if "deserializ" in k or "pickle" in k:
        return "Never deserialize untrusted data; use JSON with schema validation instead"
    return "Sanitize and validate all user-controlled input before use in this operation"


def _build_remediation_list(sinks, paths):
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
            "action": f"Sanitize input before {sink.get('label')} at {sink.get('file')}:{sink.get('line')}",
        })
    priorities.sort(key=lambda x: x["paths_eliminated_if_patched"], reverse=True)
    for i, p in enumerate(priorities):
        p["priority"] = i + 1
    return priorities


def _svg_rf_histogram(commits: list) -> str:
    """Render an inline SVG bar chart of RF scores for up to 20 commits."""
    if not commits:
        return "<p style='color:#4a5568;font-style:italic'>No commit data available.</p>"

    data = commits[:20]
    n = len(data)
    W, H, pad = 560, 120, 30
    bar_w = max(1, (W - pad * 2) // n - 2)

    def bar_color(rf):
        if rf < 0.2: return "#00C864"
        if rf < 0.45: return "#F59E0B"
        if rf < 0.7: return "#F97316"
        return "#FF4444"

    bars = ""
    for i, c in enumerate(data):
        rf = c.get("risk_factor", 0)
        bh = int(rf * (H - pad))
        x = pad + i * (bar_w + 2)
        y = H - bh
        msg = html_module.escape(c.get("message", "")[:40])
        bars += (
            f'<rect x="{x}" y="{y}" width="{bar_w}" height="{bh}" '
            f'fill="{bar_color(rf)}" rx="2">'
            f'<title>{msg}\nRF={rf}</title></rect>'
        )

    # Y-axis labels
    axes = (
        f'<line x1="{pad}" y1="0" x2="{pad}" y2="{H}" stroke="#2d3748" stroke-width="1"/>'
        f'<line x1="{pad}" y1="{H}" x2="{W}" y2="{H}" stroke="#2d3748" stroke-width="1"/>'
        f'<text x="{pad-4}" y="10" fill="#718096" font-size="9" text-anchor="end">1.0</text>'
        f'<text x="{pad-4}" y="{H//2}" fill="#718096" font-size="9" text-anchor="end">0.5</text>'
        f'<text x="{pad-4}" y="{H}" fill="#718096" font-size="9" text-anchor="end">0.0</text>'
        f'<line x1="{pad}" y1="{H//2}" x2="{W}" y2="{H//2}" stroke="#2d3748" stroke-width="1" stroke-dasharray="4"/>'
    )

    return (
        f'<svg viewBox="0 0 {W} {H+10}" width="100%" style="max-width:560px">'
        f'{axes}{bars}</svg>'
    )


# ── JSON report ───────────────────────────────────────────────────────────────

@router.get("/api/report/json")
def download_json_report():
    graph = get_current_graph()
    paths = get_current_attack_paths()
    high_risk = get_current_high_risk_paths()

    nodes = graph.get("nodes", [])
    edges = graph.get("links", [])
    sources = [n for n in nodes if n.get("type") == "source"]
    sinks   = [n for n in nodes if n.get("type") == "sink"]

    ai_history = []
    for key, val in ai_query_cache.items():
        if "node:" not in key:
            ai_history.append({"query": key.split(":")[0], "explanation": val.get("explanation", "")})

    high_count = sum(
        1 for p in paths
        if p.get("classification") in ("HIGH", "CRITICAL") or p.get("risk") in ("HIGH", "CRITICAL", "high", "critical")
    )

    report = {
        "report_metadata": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "tool": "VulnGraph",
            "version": "1.0.0",
            "project": graph.get("meta", {}).get("scanned_project", "unknown"),
        },
        "executive_summary": {
            "ai_summary": _generate_ai_summary(
                graph.get("meta", {}).get("scanned_project", "unknown"),
                len(sinks), high_count, len(sources),
                len(set(n.get("file") for n in nodes if n.get("file")))
            ),
            "total_nodes_analyzed": len(nodes),
            "total_data_flows": len(edges),
            "total_vulnerabilities": len(sinks),
            "total_attack_paths": len(paths),
            "high_risk_paths": high_count,
            "critical_paths": sum(
                1 for p in paths
                if p.get("classification") == "CRITICAL" or p.get("risk") in ("CRITICAL", "critical")
            ),
            "entry_points_exposed": len(sources),
            "files_affected": len(set(n.get("file") for n in nodes if n.get("file"))),
        },
        "ai_conversations": ai_history,
        "attack_surface": [
            {"id": n.get("id"), "label": n.get("label"), "file": n.get("file"),
             "line": n.get("line"), "source_kind": n.get("source_kind"), "community": n.get("community")}
            for n in sources
        ],
        "vulnerabilities": [
            {"id": n.get("id"), "label": n.get("label"), "file": n.get("file"),
             "line": n.get("line"), "risk": n.get("risk"), "sink_kind": n.get("sink_kind"),
             "community": n.get("community"), "confidence": n.get("confidence"),
             "git_blame": n.get("git_blame"), "blast_radius_files": n.get("blast_radius", [])}
            for n in sinks
        ],
        "attack_paths": [
            {"rank": i + 1, "classification": p.get("classification") or p.get("risk"),
             "risk_score": p.get("risk_score") or p.get("score"),
             "source": p.get("source"), "sink": p.get("sink"),
             "path": p.get("path"), "hops": len(p.get("path", [])),
             "avg_confidence": p.get("avg_confidence")}
            for i, p in enumerate(high_risk)
        ],
        "remediation_priorities": _build_remediation_list(sinks, paths),
    }

    return JSONResponse(
        content=report,
        headers={"Content-Disposition": f'attachment; filename="vulngraph_report_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json"'},
    )


# ── HTML report ───────────────────────────────────────────────────────────────

@router.get("/api/report/html")
def download_html_report(repo_path: str = Query(default="", alias="repo_path")):
    graph   = get_current_graph()
    paths   = get_current_attack_paths()
    nodes   = graph.get("nodes", [])
    edges   = graph.get("links", [])
    sinks   = [n for n in nodes if n.get("type") == "sink"]
    sources = [n for n in nodes if n.get("type") == "source"]
    guards  = [n for n in nodes if n.get("type") in ("sanitizer", "guard")]
    entries = [n for n in nodes if n.get("type") == "source"]

    high_paths = [p for p in paths if str(p.get("classification") or p.get("risk") or "").upper() in ("HIGH", "CRITICAL")]
    med_paths  = [p for p in paths if str(p.get("classification") or p.get("risk") or "").upper() == "MEDIUM"]
    low_paths  = [p for p in paths if str(p.get("classification") or p.get("risk") or "").upper() == "LOW"]

    project  = graph.get("meta", {}).get("scanned_project", "demo_project")
    language = graph.get("meta", {}).get("language", "Python")
    files_scanned = len(set(n.get("file") for n in nodes if n.get("file")))
    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    scan_date = datetime.utcnow().strftime("%B %d, %Y")

    overall_risk = "LOW"
    if any(str(p.get("classification") or p.get("risk") or "").upper() == "CRITICAL" for p in paths):
        overall_risk = "CRITICAL"
    elif any(str(p.get("classification") or p.get("risk") or "").upper() == "HIGH" for p in paths):
        overall_risk = "HIGH"
    elif any(str(p.get("classification") or p.get("risk") or "").upper() == "MEDIUM" for p in paths):
        overall_risk = "MEDIUM"

    ai_nl_summary = _generate_ai_summary(project, len(sinks), len(high_paths), len(sources), files_scanned)

    # ── TDRA data ─────────────────────────────────────────────────────────────
    tdra_commits = []
    tdra_summary = {}
    validation   = {}
    try:
        from backend.routers.tdra import _has_git
        from backend.services.mock_tdra_data import get_mock_tdra_commits, get_mock_risk_summary
        effective_path = (repo_path or "").strip() or "/app/demo_project"
        if _has_git(effective_path):
            from backend.services.differential_engine import DifferentialEngine
            engine = DifferentialEngine(effective_path)
            pairs  = engine.get_commit_pairs(limit=30)
            for ph, ch in pairs:
                try:
                    tdra_commits.append(engine.analyze_commit(ph, ch))
                except Exception:
                    pass
        else:
            tdra_commits = get_mock_tdra_commits()

        tdra_commits_sorted = sorted(tdra_commits, key=lambda c: c.get("risk_factor", 0), reverse=True)
        total_new_paths = sum(c.get("new_attack_paths", 0) for c in tdra_commits)
        total_weakenings = sum(c.get("guard_weakening_events", 0) for c in tdra_commits)
        rf_scores = [c.get("risk_factor", 0) for c in tdra_commits]
        avg_rf = round(sum(rf_scores) / len(rf_scores), 4) if rf_scores else 0.0
        tdra_summary = {
            "total": len(tdra_commits),
            "total_new_paths": total_new_paths,
            "total_weakenings": total_weakenings,
            "avg_rf": avg_rf,
            "top3": tdra_commits_sorted[:3],
        }
    except Exception as _te:
        print(f"[Report] TDRA section error: {_te}")

    try:
        from backend.routers.validation import _cache as _val_cache, _cache_lock as _val_lock
        with _val_lock:
            # grab the most recently added validation report from any repo path
            all_reports = list(_val_cache.values())
        if all_reports:
            latest = all_reports[-1]
            validation = latest.get("validation", {})
    except Exception:
        pass

    # ── Build HTML sections ───────────────────────────────────────────────────
    overall_color = {"CRITICAL": "#FF4444", "HIGH": "#F97316", "MEDIUM": "#F59E0B", "LOW": "#00C864"}.get(overall_risk, "#00C864")

    # Section 2: top-5 attack path table
    top5_paths_rows = ""
    for i, p in enumerate(sorted(paths, key=lambda x: float(x.get("risk_score") or x.get("score") or 0), reverse=True)[:5]):
        path_nodes = p.get("path", [])
        source_node = path_nodes[0] if path_nodes else "?"
        guards_on_path = [n for n in path_nodes if n in {nd.get("id") for nd in guards}]
        risk_score = round(float(p.get("risk_score") or p.get("score") or 0), 2)
        cls = str(p.get("classification") or p.get("risk") or "?")
        top5_paths_rows += f"""
        <tr>
          <td><code style="color:#90cdf4;font-size:11px">{html_module.escape(str(source_node)[:40])}</code></td>
          <td style="text-align:center">{len(path_nodes)}</td>
          <td style="text-align:center">{len(guards_on_path)}</td>
          <td style="text-align:center">{risk_score}</td>
          <td>{_risk_badge(cls)}</td>
        </tr>"""

    # Section 3: TDRA commit table (top 3)
    tdra_commit_rows = ""
    for c in tdra_summary.get("top3", []):
        rf = c.get("risk_factor", 0)
        sev = c.get("severity", "Low")
        sev_color = {"Critical": "#FF4444", "High": "#F97316", "Medium": "#F59E0B", "Low": "#00C864"}.get(sev, "#00C864")
        tdra_commit_rows += f"""
        <tr>
          <td><code style="color:#90cdf4;font-size:11px">{html_module.escape(c.get('commit_hash','')[:7])}</code></td>
          <td style="color:#a0aec0">{html_module.escape(c.get('author','?'))}</td>
          <td style="color:#718096;font-size:11px">{html_module.escape(str(c.get('date',''))[:10])}</td>
          <td style="font-size:12px;max-width:200px">{html_module.escape(c.get('message','')[:60])}</td>
          <td style="text-align:center;font-weight:700;color:{sev_color}">{rf:.4f}</td>
          <td><span class="badge {'crit' if sev=='Critical' else 'high' if sev=='High' else 'med' if sev=='Medium' else 'low'}">{sev}</span></td>
        </tr>"""

    svg_chart = _svg_rf_histogram(tdra_commits)

    # Section 4: statistical validation
    if validation:
        sig = validation.get("statistically_significant", False)
        verdict_color = "#00C864" if sig else "#F59E0B"
        verdict_text  = "✓ TDRA RF formula statistically validated" if sig else "⚠ Pending validation (insufficient data)"
        section4 = f"""
        <div class="section">
          <h2>§4 Statistical Validation</h2>
          <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:16px">
            <div class="mini-stat"><div class="ms-val">{validation.get('mann_whitney_u_statistic','—')}</div><div class="ms-lbl">Mann-Whitney U</div></div>
            <div class="mini-stat"><div class="ms-val">{validation.get('p_value','—')}</div><div class="ms-lbl">p-value</div></div>
            <div class="mini-stat"><div class="ms-val">{validation.get('cliffs_delta','—')}</div><div class="ms-lbl">Cliff's δ</div></div>
            <div class="mini-stat"><div class="ms-val" style="text-transform:capitalize">{validation.get('effect_size_label','—')}</div><div class="ms-lbl">Effect Size</div></div>
          </div>
          <div style="padding:12px 16px;border-radius:8px;border:1px solid {verdict_color}40;background:{verdict_color}10;color:{verdict_color};font-weight:700;font-size:14px">
            {verdict_text}
          </div>
        </div>"""
    else:
        section4 = """
        <div class="section">
          <h2>§4 Statistical Validation</h2>
          <div style="color:#4a5568;font-style:italic;padding:10px">
            Run the Statistical Validation from the 📊 Validate tab to populate this section.
          </div>
        </div>"""

    # Section 5: sink details table
    sink_rows = ""
    for s in sorted(sinks, key=lambda x: str(x.get("risk", "LOW")), reverse=True):
        blame = s.get("git_blame") or {}
        sk = (s.get("sink_kind") or "unknown").replace("_", " ").title()
        sink_rows += f"""
        <tr>
          <td>{_risk_badge(s.get('risk','LOW'))}</td>
          <td><code style="font-size:11px;color:#90cdf4">{html_module.escape(s.get('label','?'))}</code></td>
          <td style="font-size:11px;color:#a0aec0">{html_module.escape(s.get('file','?'))}:{s.get('line','?')}</td>
          <td style="font-size:11px">{html_module.escape(sk)}</td>
          <td style="font-size:11px;color:#718096">{html_module.escape(blame.get('author','unknown'))}</td>
          <td style="font-size:11px;color:#718096">{html_module.escape(str(blame.get('date','unknown'))[:10])}</td>
        </tr>"""

    # Section 6: remediation
    remed_rows = ""
    high_sinks = [s for s in sinks if str(s.get("risk","")).upper() in ("HIGH","CRITICAL")]
    for s in high_sinks:
        rec = _sink_recommendation(s.get("sink_kind", ""))
        remed_rows += f"""
        <tr>
          <td>{_risk_badge(s.get('risk',''))}</td>
          <td><code style="font-size:11px;color:#90cdf4">{html_module.escape(s.get('label','?'))}</code></td>
          <td style="font-size:11px;color:#a0aec0">{html_module.escape(s.get('file','?'))}:{s.get('line','?')}</td>
          <td style="font-size:12px;color:#c6f6d5">{html_module.escape(rec)}</td>
        </tr>"""
    if not remed_rows:
        remed_rows = '<tr><td colspan="4" style="color:#4a5568;font-style:italic">No HIGH/CRITICAL sinks found — good posture!</td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VulnGraph Security Report — {html_module.escape(project)}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Inter,sans-serif;
       background:#0d1117;color:#c9d1d9;padding:40px 5%;min-width:700px}}
  a{{color:#58a6ff}}
  .header{{background:linear-gradient(135deg,#161b22 0%,#0d1117 100%);
           border:1px solid #30363d;border-radius:12px;padding:32px 36px;
           margin-bottom:28px;display:flex;justify-content:space-between;align-items:flex-start}}
  .header-left h1{{font-size:22px;font-weight:700;color:#f0f6fc;margin-bottom:6px}}
  .header-left p{{font-size:13px;color:#8b949e}}
  .overall-risk{{padding:8px 20px;border-radius:8px;font-weight:800;font-size:15px;
                 background:{overall_color}20;color:{overall_color};border:1px solid {overall_color}40}}
  .stats-bar{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:24px}}
  .stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;
         padding:16px 12px;text-align:center}}
  .stat-num{{font-size:26px;font-weight:700;color:#f0f6fc}}
  .stat-lbl{{font-size:11px;color:#8b949e;margin-top:4px}}
  .section{{background:#161b22;border:1px solid #30363d;border-radius:10px;
            padding:24px;margin-bottom:20px}}
  .section h2{{font-size:14px;font-weight:700;color:#58a6ff;
               border-bottom:1px solid #30363d;padding-bottom:10px;margin-bottom:16px}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th{{text-align:left;padding:9px 12px;background:#0d1117;color:#8b949e;
      font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em;
      border-bottom:1px solid #30363d}}
  td{{padding:9px 12px;border-bottom:1px solid #21262d;vertical-align:middle}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:#1c2128}}
  code{{background:#21262d;padding:2px 6px;border-radius:4px;font-family:'Fira Code',monospace;font-size:11px}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:20px;
          font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em}}
  .badge.crit{{background:#FF444420;color:#FF4444;border:1px solid #FF444440}}
  .badge.high{{background:#F9731620;color:#F97316;border:1px solid #F9731640}}
  .badge.med{{background:#F59E0B20;color:#F59E0B;border:1px solid #F59E0B40}}
  .badge.low{{background:#00C86420;color:#00C864;border:1px solid #00C86440}}
  .mini-stat{{background:#0d1117;border:1px solid #30363d;border-radius:8px;
              padding:12px;text-align:center}}
  .ms-val{{font-size:20px;font-weight:700;color:#f0f6fc}}
  .ms-lbl{{font-size:10px;color:#8b949e;margin-top:3px}}
  .footer{{text-align:center;color:#4a5568;font-size:11px;
           margin-top:40px;padding-top:20px;border-top:1px solid #21262d}}
  .ai-box{{background:#0d1117;border:1px solid #1f6feb40;border-radius:8px;
           padding:14px 18px;font-size:13px;line-height:1.7;color:#79c0ff}}
</style>
</head>
<body>

<!-- HEADER -->
<div class="header">
  <div class="header-left">
    <h1>🔍 VulnGraph Security Report</h1>
    <p>Project: <strong style="color:#f0f6fc">{html_module.escape(project)}</strong>
       &nbsp;·&nbsp; Language: {html_module.escape(language)}
       &nbsp;·&nbsp; Scan date: {scan_date}
       &nbsp;·&nbsp; Generated: {generated}</p>
  </div>
  <div class="overall-risk">Overall Risk: {overall_risk}</div>
</div>

<!-- KPI BAR -->
<div class="stats-bar">
  <div class="stat"><div class="stat-num" style="color:#FF4444">{len(sinks)}</div><div class="stat-lbl">Vulnerabilities</div></div>
  <div class="stat"><div class="stat-num" style="color:#F97316">{len(entries)}</div><div class="stat-lbl">Entry Points</div></div>
  <div class="stat"><div class="stat-num" style="color:#F59E0B">{len(paths)}</div><div class="stat-lbl">Attack Paths</div></div>
  <div class="stat"><div class="stat-num" style="color:#00C864">{len(guards)}</div><div class="stat-lbl">Guards / Sanitizers</div></div>
  <div class="stat"><div class="stat-num" style="color:#58a6ff">{len(nodes)}</div><div class="stat-lbl">Total AST Nodes</div></div>
  <div class="stat"><div class="stat-num" style="color:#8b949e">{files_scanned}</div><div class="stat-lbl">Files Scanned</div></div>
</div>

<!-- §1 EXECUTIVE SUMMARY -->
<div class="section">
  <h2>§1 Executive Summary</h2>
  <div class="ai-box">{ai_nl_summary}</div>
</div>

<!-- §2 ATTACK SURFACE ANALYSIS -->
<div class="section">
  <h2>§2 Attack Surface Analysis</h2>
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:18px">
    <div class="mini-stat"><div class="ms-val" style="color:#FF4444">{len(high_paths)}</div><div class="ms-lbl">HIGH / CRITICAL Paths</div></div>
    <div class="mini-stat"><div class="ms-val" style="color:#F59E0B">{len(med_paths)}</div><div class="ms-lbl">MEDIUM Paths</div></div>
    <div class="mini-stat"><div class="ms-val" style="color:#00C864">{len(low_paths)}</div><div class="ms-lbl">LOW Paths</div></div>
  </div>
  <table>
    <thead><tr>
      <th>Source Node</th><th style="text-align:center">Path Length</th>
      <th style="text-align:center">Guards on Path</th>
      <th style="text-align:center">Risk Score</th><th>Severity</th>
    </tr></thead>
    <tbody>{top5_paths_rows or '<tr><td colspan="5" style="color:#4a5568;font-style:italic">No attack paths detected.</td></tr>'}</tbody>
  </table>
</div>

<!-- §3 TDRA DIFFERENTIAL ANALYSIS -->
<div class="section">
  <h2>§3 TDRA Differential Analysis</h2>
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px">
    <div class="mini-stat"><div class="ms-val" style="color:#58a6ff">{tdra_summary.get('total', 0)}</div><div class="ms-lbl">Commits Analyzed</div></div>
    <div class="mini-stat"><div class="ms-val" style="color:#F97316">{tdra_summary.get('total_new_paths', 0)}</div><div class="ms-lbl">New Attack Paths Introduced</div></div>
    <div class="mini-stat"><div class="ms-val" style="color:#FF4444">{tdra_summary.get('total_weakenings', 0)}</div><div class="ms-lbl">Guard Weakening Events</div></div>
    <div class="mini-stat"><div class="ms-val" style="color:#F59E0B">{tdra_summary.get('avg_rf', 0):.4f}</div><div class="ms-lbl">Average RF Score</div></div>
  </div>
  <div style="margin-bottom:18px">
    <div style="font-size:11px;color:#8b949e;margin-bottom:6px;text-transform:uppercase;letter-spacing:.05em">RF Score Distribution</div>
    {svg_chart}
  </div>
  <table>
    <thead><tr>
      <th>Commit</th><th>Author</th><th>Date</th><th>Message</th>
      <th style="text-align:center">RF Score</th><th>Severity</th>
    </tr></thead>
    <tbody>{tdra_commit_rows or '<tr><td colspan="6" style="color:#4a5568;font-style:italic">No commit data.</td></tr>'}</tbody>
  </table>
</div>

{section4}

<!-- §5 VULNERABILITY DETAILS -->
<div class="section">
  <h2>§5 Vulnerability Details</h2>
  <table>
    <thead><tr>
      <th>Risk</th><th>Sink</th><th>Location</th>
      <th>Type</th><th>Introduced By</th><th>Date</th>
    </tr></thead>
    <tbody>{sink_rows or '<tr><td colspan="6" style="color:#4a5568;font-style:italic">No sink nodes found.</td></tr>'}</tbody>
  </table>
</div>

<!-- §6 REMEDIATION RECOMMENDATIONS -->
<div class="section">
  <h2>§6 Remediation Recommendations</h2>
  <table>
    <thead><tr>
      <th>Risk</th><th>Sink</th><th>Location</th><th>Recommended Fix</th>
    </tr></thead>
    <tbody>{remed_rows}</tbody>
  </table>
</div>

<div class="footer">
  Generated by <strong>VulnGraph</strong> · TDRA Framework · AST Taint Analysis
  &nbsp;·&nbsp; {generated}
</div>
</body>
</html>"""

    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f'attachment; filename="vulngraph_report_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.html"'},
    )
