/**
 * VulnGraph IDE Extension — Full Feature Build
 * All TDRA features except 3D visualization.
 * All analysis is LOCAL — no code leaves the machine.
 * Requires VulnGraph backend running at localhost:8002 (configurable).
 */

const vscode = require('vscode');
const path   = require('path');
const fs     = require('fs');

// ── Decoration types ──────────────────────────────────────────────────────────
const DECORATIONS = {
  source: vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(0,200,100,0.12)',
    borderLeft: '3px solid #00C864',
    after: { contentText: ' ⬤ ENTRY', color: '#00C864', margin: '0 0 0 10px',
             fontWeight: '500', fontSize: '11px' }
  }),
  sink: vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(255,80,80,0.12)',
    borderLeft: '3px solid #FF5050',
    after: { contentText: ' ⬤ SINK', color: '#FF5050', margin: '0 0 0 10px',
             fontWeight: '500', fontSize: '11px' }
  }),
  sanitizer: vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(180,100,255,0.12)',
    borderLeft: '3px solid #B464FF',
    after: { contentText: ' ⬤ GUARD', color: '#B464FF', margin: '0 0 0 10px',
             fontWeight: '500', fontSize: '11px' }
  }),
  critical_sink: vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(255,30,30,0.18)',
    borderLeft: '4px solid #FF0000',
    after: { contentText: ' 🔴 CRITICAL SINK', color: '#FF0000', margin: '0 0 0 10px',
             fontWeight: '700', fontSize: '11px' }
  }),
  new_path: vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(255,165,0,0.15)',
    borderLeft: '3px solid #FFA500',
    after: { contentText: ' ⚠ NEW PATH (this commit)', color: '#FFA500',
             margin: '0 0 0 10px', fontWeight: '600', fontSize: '11px' }
  }),
};

// ── State ─────────────────────────────────────────────────────────────────────
let _lastScanData   = null;   // result of /api/cve/scan
let _lastGraph      = null;   // result of /api/graph
let _lastTimeline   = null;   // result of /api/tdra/timeline
let _riskPanel      = null;   // WebviewPanel for TDRA risk dashboard
let _statusBarItem  = null;
let _saveDebounce   = null;
let _currentRepoPath = null;

// ── Helpers ───────────────────────────────────────────────────────────────────
function getConfig() {
  const cfg = vscode.workspace.getConfiguration('vulngraph');
  return {
    backendUrl: cfg.get('backendUrl', 'http://localhost:8002'),
    autoAnalyze: cfg.get('autoAnalyzeOnSave', true),
    showGuards:  cfg.get('showGuardDecorations', true),
  };
}

function getWorkspacePath(document) {
  const wf = vscode.workspace.getWorkspaceFolder(document.uri)
          || vscode.workspace.workspaceFolders?.[0];
  if (!wf) return null;
  let dir = path.dirname(document.uri.fsPath);
  const wsRoot = wf.uri.fsPath;
  while (dir && dir.startsWith(wsRoot)) {
    const files = fs.existsSync(dir) ? fs.readdirSync(dir) : [];
    if (files.some(f => ['requirements.txt','pom.xml','build.gradle'].includes(f))) {
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return wsRoot;
}

async function apiFetch(url, opts = {}) {
  const resp = await fetch(url, { timeout: 30000, ...opts });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

function setStatus(text, tooltip) {
  if (_statusBarItem) {
    _statusBarItem.text = text;
    _statusBarItem.tooltip = tooltip || text;
  }
}

// ── Core Analysis ─────────────────────────────────────────────────────────────
async function analyzeProject(projectPath, backendUrl) {
  setStatus('$(sync~spin) VulnGraph scanning...', 'Scanning project...');
  _currentRepoPath = projectPath;

  // 1. Scan
  const scanData = await apiFetch(`${backendUrl}/api/cve/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ project_path: projectPath }),
  });
  _lastScanData = scanData;

  // 2. Graph
  const graphData = await apiFetch(`${backendUrl}/api/graph`);
  _lastGraph = graphData;

  // 3. TDRA timeline (non-blocking)
  apiFetch(`${backendUrl}/api/tdra/timeline?repo_path=${encodeURIComponent(projectPath)}&limit=30`)
    .then(d => { _lastTimeline = d; refreshRiskPanel(); })
    .catch(() => {});

  return { scanData, graphData };
}

async function analyzeFile(document) {
  const ext = path.extname(document.fileName).toLowerCase();
  if (!['.py','.java'].includes(ext) && !['python','java'].includes(document.languageId)) return;

  const { backendUrl } = getConfig();
  const projectPath = getWorkspacePath(document);
  if (!projectPath) return;

  try {
    const { graphData } = await analyzeProject(projectPath, backendUrl);
    applyDecorations(document, graphData);
    setStatus(`$(shield) VulnGraph: ${_lastScanData?.sinks || 0} sinks · ${_lastScanData?.sources || 0} entry`,
              'VulnGraph analysis complete');
    if (_riskPanel) refreshRiskPanel();
  } catch (err) {
    setStatus('$(warning) VulnGraph: backend offline', 'Start backend: uvicorn backend.main:app --port 8002');
    vscode.window.setStatusBarMessage('VulnGraph: backend not reachable', 5000);
  }
}

// ── Decorations ───────────────────────────────────────────────────────────────
function applyDecorations(document, graphData) {
  const editor = vscode.window.visibleTextEditors.find(
    e => e.document.uri.toString() === document.uri.toString()
  );
  if (!editor) return;

  const { showGuards } = getConfig();
  const nodes = graphData?.nodes || [];
  const docFile = document.uri.fsPath;

  const ranges = { source: [], sink: [], sanitizer: [], critical_sink: [], new_path: [] };

  // Get new paths from last TDRA commit (if available)
  const latestCommit = _lastTimeline?.timeline?.slice(-1)[0];
  const newPathNodes = new Set(
    (latestCommit?.new_paths_detail || []).flat()
  );

  for (const node of nodes) {
    const nodeFile = node.file || '';
    if (!docFile.endsWith(nodeFile) && !nodeFile.endsWith(path.basename(docFile))) continue;

    const lineNo = (node.line || 1) - 1;
    if (lineNo < 0 || lineNo >= document.lineCount) continue;

    const lineRange = document.lineAt(Math.min(lineNo, document.lineCount - 1)).range;
    const isNewPath = newPathNodes.has(node.id);
    const isCritical = node.type === 'sink' && (node.risk === 'HIGH' || node.severity === 'Critical'
                        || (node.residual_risk && node.residual_risk > 0.7));

    const hoverMsg = new vscode.MarkdownString(
      `**VulnGraph — ${node.type?.toUpperCase()}**\n\n` +
      `- **Label:** \`${node.label || node.id}\`\n` +
      `- **File:** ${node.file || 'unknown'}:${node.line || '?'}\n` +
      (node.cwe ? `- **CWE:** ${node.cwe}\n` : '') +
      (node.residual_risk != null ? `- **Residual risk:** ${node.residual_risk.toFixed(3)}\n` : '') +
      (node.effective_guard_strength != null
        ? `- **Guard strength:** ${(node.effective_guard_strength * 100).toFixed(1)}%\n` : '') +
      (node.git_blame ? `- **Introduced by:** ${node.git_blame.author} (${node.git_blame.date?.split('T')[0]})\n` : '') +
      (isNewPath ? '\n⚠ **This node appears in a NEW attack path introduced by the latest commit.**' : '')
    );
    hoverMsg.isTrusted = true;

    const rangeEntry = { range: lineRange, hoverMessage: hoverMsg };

    if (isNewPath) {
      ranges.new_path.push(rangeEntry);
    } else if (isCritical) {
      ranges.critical_sink.push(rangeEntry);
    } else if (node.type === 'source') {
      ranges.source.push(rangeEntry);
    } else if (node.type === 'sink') {
      ranges.sink.push(rangeEntry);
    } else if (node.type === 'sanitizer' && showGuards) {
      ranges.sanitizer.push(rangeEntry);
    }
  }

  Object.entries(DECORATIONS).forEach(([key, dec]) => {
    editor.setDecorations(dec, ranges[key] || []);
  });
}

// ── Risk Dashboard Webview ────────────────────────────────────────────────────
function openRiskPanel(context) {
  if (_riskPanel) {
    _riskPanel.reveal(vscode.ViewColumn.Beside);
    return;
  }

  _riskPanel = vscode.window.createWebviewPanel(
    'vulngraphRisk', 'VulnGraph Risk Dashboard',
    vscode.ViewColumn.Beside,
    { enableScripts: true, retainContextWhenHidden: true }
  );

  _riskPanel.onDidDispose(() => { _riskPanel = null; }, null, context.subscriptions);

  _riskPanel.webview.onDidReceiveMessage(async msg => {
    const { backendUrl } = getConfig();
    if (msg.command === 'getAttackPaths') {
      try {
        const data = await apiFetch(`${backendUrl}/api/attack-paths`);
        _riskPanel.webview.postMessage({ type: 'attackPaths', data });
      } catch (e) {}
    }
    if (msg.command === 'validate' && _currentRepoPath && msg.hashes) {
      try {
        const data = await apiFetch(`${backendUrl}/api/tdra/validate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            repo_path: _currentRepoPath,
            known_vcc_hashes: msg.hashes,
            limit: 100,
          }),
        });
        _riskPanel.webview.postMessage({ type: 'validationResult', data });
      } catch (e) {}
    }
    if (msg.command === 'exportReport') {
      try {
        const resp = await fetch(`${backendUrl}/api/report/html`);
        const html = await resp.text();
        const uri = await vscode.window.showSaveDialog({
          defaultUri: vscode.Uri.file(path.join(_currentRepoPath || '', 'vulngraph_report.html')),
          filters: { 'HTML Report': ['html'] },
        });
        if (uri) {
          fs.writeFileSync(uri.fsPath, html, 'utf8');
          vscode.window.showInformationMessage(`Report saved: ${uri.fsPath}`);
          vscode.env.openExternal(uri);
        }
      } catch (e) {
        vscode.window.showErrorMessage('Failed to export report: ' + e.message);
      }
    }
  });

  refreshRiskPanel();
}

function refreshRiskPanel() {
  if (!_riskPanel) return;
  const timeline = _lastTimeline?.timeline || [];
  const scanData = _lastScanData || {};
  const graph    = _lastGraph || {};
  const nodes    = graph.nodes || [];
  const paths    = (graph.attack_paths || []);

  const RF_COLOR = rf =>
    rf >= 0.7 ? '#FF4444' : rf >= 0.45 ? '#FF9500' : rf >= 0.2 ? '#FFD700' : '#00C864';
  const SEV_LABEL = rf =>
    rf >= 0.7 ? 'CRITICAL' : rf >= 0.45 ? 'HIGH' : rf >= 0.2 ? 'MEDIUM' : 'LOW';

  const commitRows = timeline.slice().reverse().map(c => {
    const rf = c.risk_factor || 0;
    const col = RF_COLOR(rf);
    return `
      <tr class="commit-row" data-rf="${rf}">
        <td><code style="color:#58A6FF">${(c.commit_hash||'').slice(0,7)}</code></td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
          ${(c.message||'').slice(0,50)}</td>
        <td>${c.author||'?'}</td>
        <td><span style="color:${col};font-weight:700">${SEV_LABEL(rf)}</span></td>
        <td>
          <div style="display:flex;align-items:center;gap:6px">
            <div style="width:${Math.round(rf*60)}px;height:4px;background:${col};border-radius:2px"></div>
            <span style="color:${col};font-family:monospace;font-size:11px">${rf.toFixed(3)}</span>
          </div>
        </td>
        <td style="color:#8B949E;font-size:11px">${c.new_attack_paths||0} paths · ${c.guard_weakening_events||0} guards</td>
      </tr>`;
  }).join('');

  const sinks = nodes.filter(n => n.type === 'sink');
  const sources = nodes.filter(n => n.type === 'source');
  const guards = nodes.filter(n => n.type === 'sanitizer');
  const critical = sinks.filter(n => n.risk === 'HIGH' || (n.residual_risk || 0) > 0.7);

  const sinkRows = sinks.slice(0, 15).map(n => {
    const rr = n.residual_risk != null ? n.residual_risk.toFixed(3) : 'N/A';
    const gs = n.effective_guard_strength != null
      ? (n.effective_guard_strength * 100).toFixed(0) + '%' : 'N/A';
    return `
      <tr>
        <td><code style="font-size:11px">${(n.label||n.id||'?').slice(0,35)}</code></td>
        <td style="color:#8B949E;font-size:11px">${n.file||'?'}:${n.line||'?'}</td>
        <td><code style="color:#7EE787">${n.cwe||'?'}</code></td>
        <td style="color:${RF_COLOR(n.residual_risk||0)};font-family:monospace">${rr}</td>
        <td style="color:#1D9E75;font-family:monospace">${gs}</td>
      </tr>`;
  }).join('');

  const criticalCount  = timeline.filter(c => (c.risk_factor||0) >= 0.7).length;
  const newPathsTotal  = timeline.reduce((a,c) => a + (c.new_attack_paths||0), 0);
  const guardEvents    = timeline.reduce((a,c) => a + (c.guard_weakening_events||0), 0);
  const avgRF          = timeline.length
    ? (timeline.reduce((a,c) => a + (c.risk_factor||0), 0) / timeline.length).toFixed(3) : '—';
  const srcLabel       = _lastTimeline?.source === 'live' ? '🟢 LIVE' : '🟡 DEMO';

  _riskPanel.webview.html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0D1117; color: #E6EDF3; font-size: 13px; }
  .header { padding: 16px 20px; border-bottom: 1px solid #21262D;
             display: flex; justify-content: space-between; align-items: center; }
  .header h1 { font-size: 15px; font-weight: 600; color: #E6EDF3; }
  .header .src { font-size: 11px; color: #6E7681; }
  .stats { display: grid; grid-template-columns: repeat(5,1fr); gap: 1px;
            background: #21262D; border-bottom: 1px solid #21262D; }
  .stat { background: #0D1117; padding: 14px 16px; text-align: center; }
  .stat-n { font-size: 22px; font-weight: 600; margin-bottom: 3px; }
  .stat-l { font-size: 10px; color: #6E7681; text-transform: uppercase; letter-spacing: .05em; }
  .tabs { display: flex; border-bottom: 1px solid #21262D; background: #0D1117; }
  .tab { padding: 10px 18px; cursor: pointer; font-size: 12px; color: #8B949E;
          border-bottom: 2px solid transparent; }
  .tab.active { color: #58A6FF; border-bottom-color: #58A6FF; }
  .panel { display: none; padding: 16px 20px; overflow-y: auto; height: calc(100vh - 175px); }
  .panel.active { display: block; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { text-align: left; padding: 6px 10px; color: #6E7681; font-weight: 500;
       border-bottom: 1px solid #21262D; font-size: 11px; text-transform: uppercase; }
  td { padding: 7px 10px; border-bottom: 1px solid #161B22; vertical-align: middle; }
  tr:hover td { background: #161B22; }
  code { background: #161B22; padding: 2px 5px; border-radius: 4px; font-size: 11px; }
  .btn { padding: 6px 14px; border-radius: 6px; border: 1px solid #30363D;
          cursor: pointer; font-size: 12px; background: #21262D; color: #E6EDF3; }
  .btn:hover { background: #30363D; }
  .btn-primary { background: #1F6FEB; border-color: #1F6FEB; color: #fff; }
  .btn-primary:hover { background: #388BFD; }
  .section-head { font-size: 11px; font-weight: 600; color: #6E7681; text-transform: uppercase;
                   letter-spacing: .07em; margin-bottom: 10px; margin-top: 16px; }
  .validate-input { background: #161B22; border: 1px solid #30363D; border-radius: 6px;
                    padding: 6px 10px; color: #E6EDF3; font-size: 12px; font-family: monospace;
                    width: 100%; margin-bottom: 8px; }
  .result-box { background: #161B22; border: 1px solid #30363D; border-radius: 8px;
                 padding: 12px; margin-top: 12px; font-size: 12px; line-height: 1.6; }
  .verdict-ok  { color: #1D9E75; font-weight: 600; }
  .verdict-bad { color: #E24B4A; font-weight: 600; }
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>🛡 VulnGraph Risk Dashboard</h1>
    <div style="font-size:11px;color:#6E7681;margin-top:2px">
      Local analysis — no code leaves this machine
    </div>
  </div>
  <div style="display:flex;gap:8px;align-items:center">
    <span class="src">${srcLabel} data · ${timeline.length} commits</span>
    <button class="btn btn-primary" onclick="exportReport()">⬇ Export Report</button>
  </div>
</div>

<div class="stats">
  <div class="stat">
    <div class="stat-n" style="color:#FF4444">${criticalCount}</div>
    <div class="stat-l">Critical commits</div>
  </div>
  <div class="stat">
    <div class="stat-n" style="color:#FF9500">${newPathsTotal}</div>
    <div class="stat-l">New attack paths</div>
  </div>
  <div class="stat">
    <div class="stat-n" style="color:#FFD700">${guardEvents}</div>
    <div class="stat-l">Guard weakening</div>
  </div>
  <div class="stat">
    <div class="stat-n" style="color:#58A6FF">${sinks.length}</div>
    <div class="stat-l">Sink nodes</div>
  </div>
  <div class="stat">
    <div class="stat-n" style="color:#8B949E">${avgRF}</div>
    <div class="stat-l">Avg RF score</div>
  </div>
</div>

<div class="tabs">
  <div class="tab active" onclick="showTab('commits',this)">Commit Timeline</div>
  <div class="tab" onclick="showTab('sinks',this)">Sink Analysis</div>
  <div class="tab" onclick="showTab('validate',this)">Statistical Validation</div>
</div>

<!-- COMMIT TIMELINE TAB -->
<div id="commits" class="panel active">
  <table>
    <thead><tr>
      <th>Commit</th><th>Message</th><th>Author</th>
      <th>Severity</th><th>Risk Factor</th><th>Detail</th>
    </tr></thead>
    <tbody>${commitRows || '<tr><td colspan="6" style="text-align:center;color:#6E7681;padding:20px">No commit data. Scan a project first.</td></tr>'}</tbody>
  </table>
</div>

<!-- SINK ANALYSIS TAB -->
<div id="sinks" class="panel">
  <div class="section-head">Sink nodes — residual taint risk after guard attenuation</div>
  <table>
    <thead><tr>
      <th>Sink</th><th>Location</th><th>CWE</th>
      <th>Residual risk</th><th>Guard strength</th>
    </tr></thead>
    <tbody>${sinkRows || '<tr><td colspan="5" style="text-align:center;color:#6E7681;padding:20px">No sinks found. Scan a project first.</td></tr>'}</tbody>
  </table>
</div>

<!-- STATISTICAL VALIDATION TAB -->
<div id="validate" class="panel">
  <div class="section-head">Validate RF formula against known CVE commits</div>
  <p style="color:#8B949E;font-size:12px;margin-bottom:16px;line-height:1.6">
    Enter known vulnerability-contributing commit hashes (comma-separated).
    TDRA will run Mann-Whitney U and Cliff's delta to validate that your RF formula
    correctly separates risky commits from benign ones.
  </p>
  <textarea id="vcc-input" class="validate-input" rows="4"
    placeholder="abc1234, def5678, 9a1b2c3d..."></textarea>
  <button class="btn btn-primary" onclick="runValidation()">▶ Run Statistical Validation</button>
  <div id="validation-result"></div>
</div>

<script>
  function showTab(id, el) {
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.getElementById(id).classList.add('active');
    el.classList.add('active');
  }

  const vscode = acquireVsCodeApi();

  function runValidation() {
    const raw = document.getElementById('vcc-input').value;
    const hashes = raw.split(',').map(h => h.trim()).filter(Boolean);
    if (!hashes.length) {
      document.getElementById('validation-result').innerHTML =
        '<div class="result-box" style="color:#E24B4A">Enter at least one commit hash.</div>';
      return;
    }
    document.getElementById('validation-result').innerHTML =
      '<div class="result-box" style="color:#8B949E">Running validation...</div>';
    vscode.postMessage({ command: 'validate', hashes });
  }

  function exportReport() {
    vscode.postMessage({ command: 'exportReport' });
  }

  window.addEventListener('message', e => {
    const { type, data } = e.data;
    if (type === 'validationResult') {
      const sig = data.statistically_significant;
      const d   = data.cliffs_delta || 0;
      const p   = data.p_value || 1;
      document.getElementById('validation-result').innerHTML = \`
        <div class="result-box">
          <div class="\${sig ? 'verdict-ok' : 'verdict-bad'}" style="font-size:14px;margin-bottom:10px">
            \${sig ? '✅ TDRA VALIDATED' : '❌ NOT SIGNIFICANT'}
          </div>
          <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:10px">
            <div><span style="color:#6E7681">p-value:</span> <strong>\${p.toFixed(6)}</strong></div>
            <div><span style="color:#6E7681">Cliff's δ:</span> <strong>\${d.toFixed(4)}</strong></div>
            <div><span style="color:#6E7681">Effect size:</span> <strong>\${data.effect_size || '—'}</strong></div>
            <div><span style="color:#6E7681">VCC mean RF:</span> <strong>\${data.vcc_mean || '—'}</strong></div>
            <div><span style="color:#6E7681">Non-VCC mean RF:</span> <strong>\${data.non_vcc_mean || '—'}</strong></div>
            <div><span style="color:#6E7681">Samples:</span> 
              <strong>VCC=\${data.sample_sizes?.vcc||0} / non-VCC=\${data.sample_sizes?.non_vcc||0}</strong></div>
          </div>
          <div style="color:#8B949E;font-size:11px;line-height:1.6">\${data.interpretation || ''}</div>
        </div>\`;
    }
  });
</script>
</body>
</html>`;
}

// ── Activate ──────────────────────────────────────────────────────────────────
function activate(context) {
  // Status bar
  _statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  _statusBarItem.text = '$(shield) VulnGraph';
  _statusBarItem.tooltip = 'VulnGraph security analyzer — click to open dashboard';
  _statusBarItem.command = 'vulngraph.openDashboard';
  _statusBarItem.show();
  context.subscriptions.push(_statusBarItem);

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand('vulngraph.analyzeFile', () => {
      const doc = vscode.window.activeTextEditor?.document;
      if (doc) analyzeFile(doc);
    }),
    vscode.commands.registerCommand('vulngraph.analyzeWorkspace', () => {
      const doc = vscode.window.activeTextEditor?.document;
      if (doc) analyzeFile(doc);
    }),
    vscode.commands.registerCommand('vulngraph.openDashboard', () => {
      openRiskPanel(context);
    }),
    vscode.commands.registerCommand('vulngraph.exportReport', async () => {
      const { backendUrl } = getConfig();
      try {
        const resp = await fetch(`${backendUrl}/api/report/html`);
        const html = await resp.text();
        const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '.';
        const uri = await vscode.window.showSaveDialog({
          defaultUri: vscode.Uri.file(path.join(ws, 'vulngraph_report.html')),
          filters: { 'HTML Report': ['html'] },
        });
        if (uri) {
          fs.writeFileSync(uri.fsPath, html, 'utf8');
          vscode.window.showInformationMessage(`✅ Report saved: ${path.basename(uri.fsPath)}`);
          vscode.env.openExternal(uri);
        }
      } catch (e) {
        vscode.window.showErrorMessage('Export failed — is the backend running? ' + e.message);
      }
    }),
    vscode.commands.registerCommand('vulngraph.runValidation', async () => {
      const { backendUrl } = getConfig();
      const input = await vscode.window.showInputBox({
        prompt: 'Enter known CVE commit hashes (comma-separated)',
        placeHolder: 'abc1234, def5678, ...',
      });
      if (!input || !_currentRepoPath) return;
      const hashes = input.split(',').map(h => h.trim()).filter(Boolean);
      try {
        const result = await apiFetch(`${backendUrl}/api/tdra/validate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ repo_path: _currentRepoPath, known_vcc_hashes: hashes, limit: 100 }),
        });
        const sig = result.statistically_significant;
        vscode.window.showInformationMessage(
          `VulnGraph validation: ${sig ? '✅ SIGNIFICANT' : '❌ NOT SIGNIFICANT'} ` +
          `(p=${result.p_value?.toFixed(4)}, δ=${result.cliffs_delta?.toFixed(3)})`
        );
      } catch (e) {
        vscode.window.showErrorMessage('Validation failed: ' + e.message);
      }
    })
  );

  // Auto-analyze on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(doc => {
      const { autoAnalyze } = getConfig();
      if (!autoAnalyze) return;
      clearTimeout(_saveDebounce);
      _saveDebounce = setTimeout(() => analyzeFile(doc), 800);
    })
  );

  // Re-apply decorations when switching editors
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(editor => {
      if (editor && _lastGraph) applyDecorations(editor.document, _lastGraph);
    })
  );

  // Auto-analyze on open
  const activeDoc = vscode.window.activeTextEditor?.document;
  if (activeDoc) analyzeFile(activeDoc);
}

function deactivate() {
  Object.values(DECORATIONS).forEach(d => d.dispose());
  _statusBarItem?.dispose();
  _riskPanel?.dispose();
  clearTimeout(_saveDebounce);
}

module.exports = { activate, deactivate };
