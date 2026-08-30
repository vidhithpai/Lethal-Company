/**
 * VulnGraph IDE Extension
 * Static Application Security Testing (SAST) & Taint-Differential Risk Analysis (TDRA).
 * All analysis is LOCAL — no source code leaves the machine.
 * Communicates with local VulnGraph FastAPI backend service.
 */

const vscode = require('vscode');
const path   = require('path');
const fs     = require('fs');

// ── Decoration Types (Vibrant Color Highlighting, Solid Borders, & Bold Circular Dots) ──
const DECORATIONS = {
  source: vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(0, 230, 118, 0.18)',
    borderLeft: '5px solid #00E676',
    isWholeLine: true,
    overviewRulerColor: '#00E676',
    overviewRulerLane: vscode.OverviewRulerLane.Left,
    after: {
      contentText: ' ● ENTRY (Source)',
      color: '#00E676',
      margin: '0 0 0 16px',
      fontWeight: 'bold',
      fontSize: '11px',
    },
  }),
  sink: vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(255, 68, 68, 0.22)',
    borderLeft: '5px solid #FF4444',
    isWholeLine: true,
    overviewRulerColor: '#FF4444',
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    after: {
      contentText: ' ● SINK (Vulnerable)',
      color: '#FF4444',
      margin: '0 0 0 16px',
      fontWeight: 'bold',
      fontSize: '11px',
    },
  }),
  sanitizer: vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(180, 100, 255, 0.18)',
    borderLeft: '5px solid #B464FF',
    isWholeLine: true,
    overviewRulerColor: '#B464FF',
    overviewRulerLane: vscode.OverviewRulerLane.Center,
    after: {
      contentText: ' ● GUARD (Sanitizer)',
      color: '#B464FF',
      margin: '0 0 0 16px',
      fontWeight: 'bold',
      fontSize: '11px',
    },
  }),
  critical_sink: vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(255, 0, 0, 0.32)',
    borderLeft: '6px solid #FF0000',
    isWholeLine: true,
    overviewRulerColor: '#FF0000',
    overviewRulerLane: vscode.OverviewRulerLane.Full,
    fontWeight: 'bold',
    after: {
      contentText: ' ● CRITICAL SINK (Residual Risk > 0.70)',
      color: '#FF1744',
      margin: '0 0 0 16px',
      fontWeight: 'bold',
      fontSize: '11px',
    },
  }),
  new_path: vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(255, 165, 0, 0.22)',
    borderLeft: '5px solid #FFA500',
    isWholeLine: true,
    overviewRulerColor: '#FFA500',
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    after: {
      contentText: ' ● NEW ATTACK PATH (Latest Commit)',
      color: '#FFA500',
      margin: '0 0 0 16px',
      fontWeight: 'bold',
      fontSize: '11px',
    },
  }),
  step_highlight: vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(88, 166, 255, 0.30)',
    border: '1px solid #58A6FF',
    isWholeLine: true,
  }),
};

// ── Extension State ───────────────────────────────────────────────────────────
let _lastScanData      = null;   // Result of /api/cve/scan
let _lastGraph         = null;   // Result of /api/graph
let _lastAttackPaths   = [];     // Result of /api/attack-paths
let _lastTimeline      = null;   // Result of /api/tdra/timeline
let _riskPanel         = null;   // WebviewPanel for TDRA risk dashboard
let _statusBarItem     = null;
let _saveDebounce      = null;
let _currentRepoPath   = null;
let _taintTreeProvider = null;
let _codeLensProvider  = null;

// ── Robust Path Matching Helper (Cross-Platform / Windows-Safe) ───────────────
function isSameFile(file1, file2) {
  if (!file1 || !file2) return false;
  const n1 = String(file1).replace(/\\/g, '/').toLowerCase().trim();
  const n2 = String(file2).replace(/\\/g, '/').toLowerCase().trim();
  if (n1 === n2) return true;
  if (n1.endsWith('/' + n2) || n2.endsWith('/' + n1)) return true;
  if (n1.endsWith(n2) || n2.endsWith(n1)) return true;
  const b1 = path.basename(n1);
  const b2 = path.basename(n2);
  return b1 === b2;
}

// ── Configuration Helper ──────────────────────────────────────────────────────
function getConfig() {
  const cfg = vscode.workspace.getConfiguration('vulngraph');
  return {
    backendUrl: cfg.get('backendUrl', 'http://localhost:8002'),
    autoAnalyze: cfg.get('autoAnalyzeOnSave', true),
    showGuards: cfg.get('showGuardDecorations', true),
    enableCodeLens: cfg.get('enableCodeLens', true),
  };
}

function getWorkspacePath(document) {
  if (document) {
    const wf = vscode.workspace.getWorkspaceFolder(document.uri);
    if (wf) return wf.uri.fsPath;
    const docDir = path.dirname(document.uri.fsPath);
    if (docDir && fs.existsSync(docDir)) return docDir;
  }

  if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
    const wsRoot = vscode.workspace.workspaceFolders[0].uri.fsPath;
    if (fs.existsSync(path.join(wsRoot, 'demo_project'))) {
      return path.join(wsRoot, 'demo_project');
    }
    return wsRoot;
  }

  return null;
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

function normalizeRisk(val) {
  if (typeof val === 'number') return val;
  const s = String(val || '').toUpperCase();
  if (s === 'CRITICAL') return 0.95;
  if (s === 'HIGH') return 0.80;
  if (s === 'MEDIUM') return 0.50;
  if (s === 'LOW') return 0.20;
  return 0.50;
}

function getCweTitle(cwe) {
  const map = {
    'CWE-89': 'SQL Injection',
    'CWE-78': 'OS Command Injection',
    'CWE-95': 'Code Injection',
    'CWE-22': 'Path Traversal',
    'CWE-502': 'Deserialization of Untrusted Data',
    'CWE-79': 'Cross-Site Scripting',
    'CWE-918': 'Server-Side Request Forgery',
    'CWE-1336': 'Server-Side Template Injection',
  };
  return map[cwe] || (cwe ? cwe : 'Vulnerability Path');
}

// ── Core Analysis Routine ─────────────────────────────────────────────────────
async function analyzeProject(projectPath, backendUrl, notifyUser = false) {
  setStatus('$(sync~spin) VulnGraph: scanning...', 'Scanning project AST and data flows...');
  _currentRepoPath = projectPath;

  // 1. Scan codebase
  const scanData = await apiFetch(`${backendUrl}/api/cve/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ project_path: projectPath }),
  });
  _lastScanData = scanData;

  // 2. Fetch full graph
  const graphData = await apiFetch(`${backendUrl}/api/graph`);
  _lastGraph = graphData;

  // 3. Fetch attack paths
  try {
    const pathsData = await apiFetch(`${backendUrl}/api/attack-paths?limit=50&max_depth=15`);
    _lastAttackPaths = pathsData.paths || [];
  } catch (e) {
    _lastAttackPaths = [];
  }

  // 4. Update TreeView and CodeLens
  if (_taintTreeProvider) {
    _taintTreeProvider.refresh(_lastAttackPaths, _lastGraph);
  }
  if (_codeLensProvider) {
    _codeLensProvider.refresh();
  }

  // 5. Update Status and Notifications
  const projectName = path.basename(projectPath);
  const sourcesCount = scanData.sources || 0;
  const sinksCount = scanData.sinks || 0;
  const pathsCount = _lastAttackPaths.length;
  const nodesCount = scanData.nodes || graphData.nodes?.length || 0;

  setStatus(
    `$(shield) VulnGraph: ${sourcesCount} src | ${sinksCount} sinks | ${pathsCount} paths`,
    `VulnGraph Scan Complete for ${projectName}\n` +
    `- Total AST Nodes: ${nodesCount}\n` +
    `- Input Sources (Entry): ${sourcesCount}\n` +
    `- Execution Sinks: ${sinksCount}\n` +
    `- Active Attack Paths: ${pathsCount}\n` +
    `Click to open Risk Dashboard.`
  );

  if (notifyUser) {
    vscode.window.showInformationMessage(
      `VulnGraph: Scan complete for "${projectName}". Analyzed ${nodesCount} nodes — found ${sourcesCount} entry sources, ${sinksCount} sinks, and ${pathsCount} active attack paths.`
    );
  }

  // 6. Fetch TDRA timeline (non-blocking)
  apiFetch(
    `${backendUrl}/api/tdra/timeline` +
    `?repo_path=${encodeURIComponent(projectPath)}&limit=30`
  ).then(d => {
    _lastTimeline = d;
    const editor = vscode.window.activeTextEditor;
    if (editor && _lastGraph) applyDecorations(editor.document, _lastGraph);
    if (_riskPanel) refreshRiskPanel();
  }).catch(() => {});

  return { scanData, graphData, attackPaths: _lastAttackPaths };
}

async function analyzeFile(document) {
  const ext = path.extname(document.fileName).toLowerCase();
  if (!['.py', '.java'].includes(ext) && !['python', 'java'].includes(document.languageId)) return;

  const { backendUrl } = getConfig();
  const projectPath = getWorkspacePath(document);
  if (!projectPath) return;

  try {
    const { graphData } = await analyzeProject(projectPath, backendUrl, false);
    applyDecorations(document, graphData);

    const latestCommit = _lastTimeline?.timeline?.slice(-1)[0];
    const rfValue = (latestCommit?.risk_factor != null) ? Number(latestCommit.risk_factor) : null;
    const rfText = latestCommit
      ? (rfValue != null ? ` | RF ${rfValue.toFixed(2)} (${latestCommit.severity || 'Low'})` : ` | (${latestCommit.severity || 'Low'})`)
      : '';
    
    const criticalSinks = (_lastGraph?.nodes || []).filter(
      n => n.type === 'sink' && ((n.residual_risk || 0) > 0.7 || String(n.risk).toUpperCase() === 'CRITICAL')
    );
    if (criticalSinks.length > 0) {
      setStatus(
        `$(shield) VulnGraph $(warning) ${criticalSinks.length} critical`,
        `${criticalSinks.length} critical sink(s) detected in ${path.basename(projectPath)}.`
      );
    }

    if (_riskPanel) refreshRiskPanel();
  } catch (err) {
    setStatus('$(warning) VulnGraph: backend offline', 'Start backend: uvicorn backend.main:app --port 8002');
    vscode.window.setStatusBarMessage('VulnGraph: backend service not reachable at ' + backendUrl, 5000);
  }
}

async function autoScanWorkspace() {
  const { backendUrl } = getConfig();
  const projectPath = getWorkspacePath(vscode.window.activeTextEditor?.document);
  if (!projectPath) return;

  try {
    const { graphData } = await analyzeProject(projectPath, backendUrl, true);
    const activeEditor = vscode.window.activeTextEditor;
    if (activeEditor) {
      applyDecorations(activeEditor.document, graphData);
    }
  } catch (err) {
    setStatus('$(warning) VulnGraph: backend offline', 'Start backend: uvicorn backend.main:app --port 8002');
  }
}

// ── In-Editor Decorations (Prominent Colors & Matching) ────────────────────────
function applyDecorations(document, graphData) {
  const editor = vscode.window.visibleTextEditors.find(
    e => e.document.uri.toString() === document.uri.toString()
  ) || vscode.window.activeTextEditor;
  if (!editor) return;

  const { showGuards } = getConfig();
  const nodes = Array.isArray(graphData) ? graphData : (graphData?.nodes || []);
  const docFile = document.uri.fsPath;

  const ranges = { source: [], sink: [], sanitizer: [], critical_sink: [], new_path: [] };

  const latestCommit = _lastTimeline?.timeline?.slice(-1)[0];
  const newPathNodes = new Set((latestCommit?.new_paths_detail || []).flat());

  for (const node of nodes) {
    if (!isSameFile(docFile, node.file)) continue;

    const lineNo = (node.line || 1) - 1;
    if (lineNo < 0 || lineNo >= document.lineCount) continue;

    const lineRange = document.lineAt(lineNo).range;
    const isNewPath = newPathNodes.has(node.id);
    const isCritical = node.type === 'sink' && ((node.residual_risk != null && node.residual_risk > 0.7) || String(node.risk).toUpperCase() === 'CRITICAL');

    const nodeTypeUpper = (node.type || 'UNKNOWN').toUpperCase();
    const hoverMsg = new vscode.MarkdownString(
      `### VulnGraph [${nodeTypeUpper}]\n\n` +
      `- **Label:** \`${node.label || node.id}\`\n` +
      `- **File:** \`${node.file || 'unknown'}:${node.line || 1}\`\n` +
      (node.cwe ? `- **CWE:** \`${node.cwe}\` — ${node.cwe_name || getCweTitle(node.cwe)}\n` : '') +
      (node.residual_risk != null ? `- **Residual Risk:** \`${node.residual_risk.toFixed(3)}\`\n` : '') +
      (node.effective_guard_strength != null
        ? `- **Guard Strength:** \`${(node.effective_guard_strength * 100).toFixed(0)}%\`\n` : '') +
      (node.git_blame && node.git_blame.author ? `- **Git Attribution:** ${node.git_blame.author} (${node.git_blame.commit || 'uncommitted'}, ${node.git_blame.date || ''})\n` : '') +
      (isNewPath ? '\n**[NOTICE] This node appears in a new attack path introduced by the latest commit.**' : '')
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
    if (key === 'step_highlight') return;
    editor.setDecorations(dec, ranges[key] || []);
  });
}

// ── 1. TreeDataProvider: Interactive Dataflow Step-by-Step Explorer ───────────
class VulnGraphTaintTreeProvider {
  constructor() {
    this._onDidChangeTreeData = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    this.attackPaths = [];
    this.graph = null;
  }

  refresh(attackPaths, graph) {
    this.attackPaths = attackPaths || _lastAttackPaths || [];
    this.graph = graph || _lastGraph || { nodes: [] };
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element) {
    return element;
  }

  getChildren(element) {
    if (!element) {
      if (!this.attackPaths || this.attackPaths.length === 0) {
        const item = new vscode.TreeItem('No active attack paths detected.', vscode.TreeItemCollapsibleState.None);
        item.description = _lastScanData ? `Scanned ${_lastScanData.nodes || 0} nodes` : 'Save a file or run workspace scan';
        item.iconPath = new vscode.ThemeIcon('shield');
        return [item];
      }

      return this.attackPaths.map((p, idx) => {
        const cwe = p.cwe || 'CWE-Unknown';
        const title = getCweTitle(cwe);
        const hops = Array.isArray(p.path) ? p.path.length : 0;
        const residualRisk = p.residual_risk != null ? p.residual_risk : normalizeRisk(p.risk);
        const riskFormatted = typeof residualRisk === 'number' ? residualRisk.toFixed(3) : String(residualRisk);

        const item = new vscode.TreeItem(
          `[${cwe}] ${title} | ${hops} hops | R=${riskFormatted}`,
          vscode.TreeItemCollapsibleState.Collapsed
        );

        item.description = p.sink_category ? `[${p.sink_category}]` : '';
        item.tooltip = new vscode.MarkdownString(
          `### Path #${idx + 1}: ${title} (${cwe})\n\n` +
          `- **Source Entry:** \`${p.path?.[0] || 'unknown'}\`\n` +
          `- **Dangerous Sink:** \`${p.path?.[p.path.length - 1] || 'unknown'}\`\n` +
          `- **Residual Risk:** \`${riskFormatted}\`\n` +
          `- **Guards On Path:** ${p.guard_attenuations?.length || 0}\n` +
          `- **Total Steps:** ${hops} execution hops`
        );

        if (residualRisk >= 0.70) {
          item.iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
        } else if (residualRisk >= 0.45) {
          item.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
        } else {
          item.iconPath = new vscode.ThemeIcon('info', new vscode.ThemeColor('editorInfo.foreground'));
        }

        item.contextValue = 'attackPathRoot';
        item.pathData = p;
        item.pathIndex = idx;
        return item;
      });
    }

    if (element.pathData && Array.isArray(element.pathData.path)) {
      const pathNodes = element.pathData.path;
      const nodesMap = new Map((this.graph?.nodes || []).map(n => [n.id, n]));

      return pathNodes.map((nodeId, i) => {
        const nodeInfo = nodesMap.get(nodeId) || {};
        const nodeType = nodeInfo.type || (i === 0 ? 'source' : i === pathNodes.length - 1 ? 'sink' : 'intermediate');
        
        let stepTag = '[VAR]';
        let iconName = 'symbol-variable';

        if (i === 0 || nodeType === 'source') {
          stepTag = '[SRC]';
          iconName = 'arrow-circle-right';
        } else if (i === pathNodes.length - 1 || nodeType === 'sink') {
          stepTag = '[SINK]';
          iconName = 'flame';
        } else if (nodeType === 'sanitizer' || nodeType === 'guard') {
          stepTag = '[GRD]';
          iconName = 'shield';
        } else if (nodeType === 'function' || nodeType === 'normal') {
          stepTag = '[CALL]';
          iconName = 'symbol-method';
        }

        const labelText = nodeInfo.label || nodeId.split('::').pop() || nodeId;
        const lineNo = nodeInfo.line || 1;
        const filePath = nodeInfo.file || '';
        const shortFile = filePath ? path.basename(filePath) : '';

        const stepItem = new vscode.TreeItem(
          `Step ${i + 1}: ${stepTag} ${labelText}`,
          vscode.TreeItemCollapsibleState.None
        );

        stepItem.description = shortFile ? `${shortFile}:${lineNo}` : '';
        stepItem.iconPath = new vscode.ThemeIcon(iconName);
        stepItem.tooltip = new vscode.MarkdownString(
          `**Step ${i + 1} of ${pathNodes.length} — ${stepTag}**\n\n` +
          `- **Identifier:** \`${nodeId}\`\n` +
          `- **Location:** \`${filePath}:${lineNo}\`\n` +
          (nodeInfo.cwe ? `- **CWE:** \`${nodeInfo.cwe}\`\n` : '') +
          (nodeInfo.attenuation ? `- **Attenuation:** \`${(nodeInfo.attenuation * 100).toFixed(0)}%\`\n` : '') +
          (nodeInfo.git_blame?.author ? `- **Author:** ${nodeInfo.git_blame.author} (${nodeInfo.git_blame.commit || ''})\n` : '') +
          `\n*Click step to center and highlight in editor.*`
        );

        stepItem.command = {
          command: 'vulngraph.jumpToLocation',
          title: 'Jump to Location',
          arguments: [{
            file: filePath,
            line: lineNo,
            col: nodeInfo.col || 0,
            id: nodeId,
            label: labelText,
          }],
        };

        return stepItem;
      });
    }

    return [];
  }
}

// ── 2. CodeLens Provider: Inline Execution Metrics ─────────────────────────────
class VulnGraphCodeLensProvider {
  constructor() {
    this._onDidChangeCodeLenses = new vscode.EventEmitter();
    this.onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;
  }

  refresh() {
    this._onDidChangeCodeLenses.fire();
  }

  provideCodeLenses(document, token) {
    const { enableCodeLens, showGuards } = getConfig();
    if (!enableCodeLens) return [];

    const lenses = [];
    const docFile = document.uri.fsPath;
    const nodes = _lastGraph?.nodes || [];
    const attackPaths = _lastAttackPaths || [];

    const docNodes = nodes.filter(n => isSameFile(docFile, n.file));

    for (const node of docNodes) {
      const lineNo = (node.line || 1) - 1;
      if (lineNo < 0 || lineNo >= document.lineCount) continue;
      const range = new vscode.Range(lineNo, 0, lineNo, 0);

      if (node.type === 'source') {
        const reachedPaths = attackPaths.filter(p => Array.isArray(p.path) && p.path.includes(node.id));
        const reachedSinks = reachedPaths.map(p => p.path[p.path.length - 1]);
        const uniqueSinks = [...new Set(reachedSinks)];
        const maxRisk = reachedPaths.reduce((max, p) => Math.max(max, normalizeRisk(p.residual_risk || p.risk)), 0);

        lenses.push(
          new vscode.CodeLens(range, {
            title: `VulnGraph: [${uniqueSinks.length} Reached Sinks] | [Max Risk: ${maxRisk.toFixed(2)}]`,
            command: 'vulngraph.openDashboard',
            tooltip: `Traces into ${uniqueSinks.length} dangerous execution sinks. Click to inspect dashboard.`,
          }),
          new vscode.CodeLens(range, {
            title: `[Simulate Sanitizer / View Paths]`,
            command: 'vulngraph.focusDataflowPath',
            arguments: [node.id],
            tooltip: `View dataflow attack paths in sidebar tree.`,
          })
        );
      } else if (node.type === 'sink') {
        const cwe = node.cwe || 'CWE-Unknown';
        const residualRisk = node.residual_risk != null ? node.residual_risk : normalizeRisk(node.risk || 0.85);
        const blame = node.git_blame;
        const blameStr = blame && blame.author ? `${blame.commit || ''} (${blame.author})` : 'uncommitted';

        lenses.push(
          new vscode.CodeLens(range, {
            title: `VulnGraph: [${cwe} ${node.sink_kind || 'Execution Sink'}] | [Residual Risk: ${residualRisk.toFixed(2)}] | [Blame: ${blameStr}]`,
            command: 'vulngraph.openDashboard',
            tooltip: `CWE: ${cwe}. Residual Risk after guard attenuation: ${residualRisk.toFixed(3)}. Introduced by ${blameStr}.`,
          })
        );
      } else if ((node.type === 'sanitizer' || node.type === 'guard') && showGuards) {
        const att = node.effective_guard_strength != null ? (node.effective_guard_strength * 100).toFixed(0) : '65';
        const basis = node.guard_basis || 'name';
        lenses.push(
          new vscode.CodeLens(range, {
            title: `VulnGraph: [GUARD: -${att}% Attenuation] | [Basis: ${basis}]`,
            command: 'vulngraph.openDashboard',
            tooltip: `Attenuates downstream taint propagation by ${att}%.`,
          })
        );
      }
    }

    return lenses;
  }
}

// ── 3. CodeAction Provider: Interactive Security Fixes & Inspections ──────────
class VulnGraphCodeActionProvider {
  provideCodeActions(document, range, context, token) {
    const docFile = document.uri.fsPath;
    const nodes = _lastGraph?.nodes || [];
    const lineNo = range.start.line + 1;

    const matchedNode = nodes.find(n => isSameFile(docFile, n.file) && n.line === lineNo);
    if (!matchedNode) return [];

    const actions = [];

    const viewAction = new vscode.CodeAction('VulnGraph: Inspect Taint & Guard Attenuation', vscode.CodeActionKind.QuickFix);
    viewAction.command = {
      command: 'vulngraph.openDashboard',
      title: 'Inspect Taint & Guard Attenuation',
    };
    actions.push(viewAction);

    if (['sink', 'intermediate', 'function'].includes(matchedNode.type)) {
      const patchAction = new vscode.CodeAction(`VulnGraph: Simulate Patch on "${matchedNode.label || matchedNode.id}"`, vscode.CodeActionKind.RefactorRewrite);
      patchAction.command = {
        command: 'vulngraph.simulatePatchNode',
        title: 'Simulate Patch on Node',
        arguments: [matchedNode.id],
      };
      actions.push(patchAction);
    }

    return actions;
  }
}

// ── Jump to Location & Highlight Helper ────────────────────────────────────────
async function jumpToLocation(loc) {
  if (!loc || !loc.file) return;

  let targetUri = null;
  if (path.isAbsolute(loc.file) && fs.existsSync(loc.file)) {
    targetUri = vscode.Uri.file(loc.file);
  } else if (_currentRepoPath) {
    const candidate = path.join(_currentRepoPath, loc.file);
    if (fs.existsSync(candidate)) targetUri = vscode.Uri.file(candidate);
  }

  if (!targetUri && vscode.workspace.workspaceFolders) {
    for (const folder of vscode.workspace.workspaceFolders) {
      const candidate = path.join(folder.uri.fsPath, loc.file);
      if (fs.existsSync(candidate)) {
        targetUri = vscode.Uri.file(candidate);
        break;
      }
    }
  }

  if (!targetUri) {
    const baseName = path.basename(loc.file);
    const found = await vscode.workspace.findFiles(`**/${baseName}`, null, 1);
    if (found.length > 0) targetUri = found[0];
  }

  if (!targetUri) {
    vscode.window.showWarningMessage(`VulnGraph: Target file not found: ${loc.file}`);
    return;
  }

  const doc = await vscode.workspace.openTextDocument(targetUri);
  const lineNo = Math.max(0, (loc.line || 1) - 1);
  const colNo = Math.max(0, loc.col || 0);
  const lineRange = doc.lineAt(Math.min(lineNo, doc.lineCount - 1)).range;
  const targetPos = new vscode.Position(lineNo, colNo);
  const selectionRange = new vscode.Range(targetPos, targetPos);

  const editor = await vscode.window.showTextDocument(doc, {
    selection: selectionRange,
    preview: true,
  });

  editor.revealRange(lineRange, vscode.TextEditorRevealType.InCenter);

  editor.setDecorations(DECORATIONS.step_highlight, [lineRange]);
  setTimeout(() => {
    if (editor && !editor.document.isClosed) {
      editor.setDecorations(DECORATIONS.step_highlight, []);
    }
  }, 2000);
}

// ── SVG Call Graph Flow Visualization Generator ───────────────────────────────
function generateCallGraphSvg(graph, attackPaths) {
  const nodes = graph?.nodes || [];
  const links = graph?.links || [];
  const nodeMap = new Map(nodes.map(n => [n.id, n]));

  // Extract call links and attack path links
  const callEdges = links.filter(l => l.kind === 'call' || l.kind === 'dataflow');

  if (callEdges.length === 0 && (!attackPaths || attackPaths.length === 0)) {
    return `<div style="padding:24px;text-align:center;color:#8B949E;font-size:12px">No inter-function call flows detected in this codebase.</div>`;
  }

  const flows = (attackPaths || []).slice(0, 6).map((p, pIdx) => {
    const pNodes = (p.path || []).map(id => nodeMap.get(id) || { id, label: id.split('::').pop() });
    const cwe = p.cwe || 'CWE-Unknown';
    const residualRisk = p.residual_risk != null ? p.residual_risk.toFixed(3) : '0.85';

    const cardWidth = 740;
    const stepBoxWidth = 140;
    const stepBoxHeight = 44;
    const gap = 38;
    const startX = 20;
    const startY = 32;

    const visibleNodes = pNodes.slice(0, 4);
    const svgWidth = Math.max(cardWidth, startX + visibleNodes.length * (stepBoxWidth + gap) + 40);

    const stepElements = visibleNodes.map((n, idx) => {
      const x = startX + idx * (stepBoxWidth + gap);
      const isSrc = idx === 0;
      const isSink = idx === visibleNodes.length - 1;
      let strokeColor = '#30363D';
      let fillColor = '#161B22';
      let tagText = '[CALL]';
      let tagColor = '#58A6FF';

      if (isSrc) {
        strokeColor = '#00E676';
        fillColor = 'rgba(0, 230, 118, 0.12)';
        tagText = '[ENTRY]';
        tagColor = '#00E676';
      } else if (isSink) {
        strokeColor = '#FF4444';
        fillColor = 'rgba(255, 68, 68, 0.15)';
        tagText = '[SINK]';
        tagColor = '#FF4444';
      } else if (n.type === 'sanitizer' || n.type === 'guard') {
        strokeColor = '#B464FF';
        fillColor = 'rgba(180, 100, 255, 0.15)';
        tagText = '[GUARD]';
        tagColor = '#B464FF';
      }

      const shortLabel = (n.label || n.id || '').split('::').pop().slice(0, 15);
      const locText = `${path.basename(n.file || 'file')}:${n.line || 1}`;

      const arrow = idx < visibleNodes.length - 1 ? `
        <g>
          <line x1="${x + stepBoxWidth + 4}" y1="${startY + stepBoxHeight / 2}" x2="${x + stepBoxWidth + gap - 8}" y2="${startY + stepBoxHeight / 2}" stroke="#58A6FF" stroke-width="2" stroke-dasharray="3,3"/>
          <polygon points="${x + stepBoxWidth + gap - 8},${startY + stepBoxHeight / 2 - 4} ${x + stepBoxWidth + gap},${startY + stepBoxHeight / 2} ${x + stepBoxWidth + gap - 8},${startY + stepBoxHeight / 2 + 4}" fill="#58A6FF"/>
        </g>
      ` : '';

      return `
        <g>
          <rect x="${x}" y="${startY}" width="${stepBoxWidth}" height="${stepBoxHeight}" rx="5" fill="${fillColor}" stroke="${strokeColor}" stroke-width="1.5"/>
          <text x="${x + 8}" y="${startY + 16}" fill="${tagColor}" font-size="9" font-family="monospace" font-weight="700">${tagText}</text>
          <text x="${x + 8}" y="${startY + 30}" fill="#E6EDF3" font-size="11" font-family="monospace" font-weight="600">${shortLabel}</text>
          <text x="${x + 8}" y="${startY + 40}" fill="#8B949E" font-size="8" font-family="monospace">${locText}</text>
          ${arrow}
        </g>
      `;
    }).join('');

    return `
      <div style="background:#161B22;border:1px solid #30363D;border-radius:6px;padding:14px;margin-bottom:16px">
        <div style="display:flex;justify-content:space-between;margin-bottom:8px;font-size:12px;font-weight:600">
          <span style="color:#58A6FF">CALL FLOW ${pIdx + 1}: ${getCweTitle(cwe)} (${cwe})</span>
          <span style="color:#FF4444">Residual Taint: ${residualRisk}</span>
        </div>
        <div style="overflow-x:auto">
          <svg width="${svgWidth}" height="88" style="background:#0D1117;border-radius:4px">
            ${stepElements}
          </svg>
        </div>
      </div>
    `;
  }).join('');

  return flows;
}

// ── SVG Attenuation Waterfall Generator ───────────────────────────────────────
function generateWaterfallSvg(attackPaths) {
  if (!attackPaths || attackPaths.length === 0) {
    return `<div style="padding:24px;text-align:center;color:#8B949E;font-size:12px">No attack paths available for attenuation waterfall analysis.</div>`;
  }

  const svgCharts = attackPaths.slice(0, 5).map((p, idx) => {
    const cwe = p.cwe || 'CWE-Unknown';
    const title = getCweTitle(cwe);
    const guards = p.guard_attenuations || [];

    const steps = [{ label: 'Taint Entry Point (Source)', value: 1.000, note: 'Initial untrusted input', type: 'source' }];
    let currentTaint = 1.000;

    for (const g of guards) {
      const att = Math.max(0.10, Math.min(1.0, g.attenuation || 0.35));
      currentTaint = currentTaint * (1.0 - att);
      steps.push({
        label: `Guard: ${g.label || g.node_id || 'Sanitizer'}`,
        value: currentTaint,
        note: `-${(att * 100).toFixed(0)}% attenuation (${g.basis || 'name'})`,
        type: 'guard',
      });
    }

    steps.push({
      label: `Dangerous Sink (${cwe})`,
      value: currentTaint,
      note: `Final residual risk reaching sink: ${currentTaint.toFixed(3)}`,
      type: 'sink',
    });

    const chartWidth = 720;
    const barMaxWidth = 420;
    const rowHeight = 36;
    const svgHeight = steps.length * rowHeight + 40;

    const bars = steps.map((s, sIdx) => {
      const y = 30 + sIdx * rowHeight;
      const w = Math.max(12, Math.round(s.value * barMaxWidth));
      let barColor = '#FF5050';
      if (s.type === 'guard') barColor = '#A371F7';
      if (s.type === 'sink') {
        barColor = currentTaint >= 0.7 ? '#FF4444' : currentTaint >= 0.45 ? '#FF9500' : '#1D9E75';
      }

      return `
        <g>
          <text x="15" y="${y + 14}" fill="#E6EDF3" font-size="11" font-family="monospace">${s.label.slice(0, 32)}</text>
          <rect x="250" y="${y}" width="${w}" height="18" rx="3" fill="${barColor}" opacity="0.85" />
          <text x="${260 + w}" y="${y + 13}" fill="#8B949E" font-size="10" font-family="monospace">
            ${(s.value * 100).toFixed(1)}% [${s.note}]
          </text>
        </g>
      `;
    }).join('');

    return `
      <div style="background:#161B22;border:1px solid #30363D;border-radius:6px;padding:14px;margin-bottom:18px">
        <div style="display:flex;justify-content:space-between;margin-bottom:8px;font-size:12px;font-weight:600">
          <span style="color:#58A6FF">PATH ${idx + 1}: ${title} (${cwe})</span>
          <span style="color:${currentTaint >= 0.7 ? '#FF4444' : '#1D9E75'}">
            Residual Risk: ${currentTaint.toFixed(3)} | Effective Guard Strength: ${((1 - currentTaint) * 100).toFixed(1)}%
          </span>
        </div>
        <svg width="100%" height="${svgHeight}" viewBox="0 0 ${chartWidth} ${svgHeight}" style="background:#0D1117;border-radius:4px">
          <line x1="250" y1="20" x2="250" y2="${svgHeight - 10}" stroke="#21262D" stroke-dasharray="2,2"/>
          <line x1="${250 + barMaxWidth * 0.25}" y1="20" x2="${250 + barMaxWidth * 0.25}" y2="${svgHeight - 10}" stroke="#21262D" stroke-dasharray="2,2"/>
          <line x1="${250 + barMaxWidth * 0.50}" y1="20" x2="${250 + barMaxWidth * 0.50}" y2="${svgHeight - 10}" stroke="#21262D" stroke-dasharray="2,2"/>
          <line x1="${250 + barMaxWidth * 0.75}" y1="20" x2="${250 + barMaxWidth * 0.75}" y2="${svgHeight - 10}" stroke="#21262D" stroke-dasharray="2,2"/>
          <line x1="${250 + barMaxWidth}" y1="20" x2="${250 + barMaxWidth}" y2="${svgHeight - 10}" stroke="#21262D" stroke-dasharray="2,2"/>
          
          <text x="245" y="15" fill="#6E7681" font-size="9" text-anchor="middle">0%</text>
          <text x="${250 + barMaxWidth * 0.50}" y="15" fill="#6E7681" font-size="9" text-anchor="middle">50%</text>
          <text x="${250 + barMaxWidth}" y="15" fill="#6E7681" font-size="9" text-anchor="middle">100%</text>
          
          ${bars}
        </svg>
      </div>
    `;
  }).join('');

  return svgCharts;
}

// ── SVG Taint Coupling Matrix Generator ───────────────────────────────────────
function generateMatrixSvg(graph, timeline) {
  const nodes = graph?.nodes || [];
  const links = graph?.links || [];

  const fileSet = new Set();
  nodes.forEach(n => {
    if (n.file) fileSet.add(path.basename(n.file));
  });
  const files = Array.from(fileSet).slice(0, 10);

  if (files.length === 0) {
    return `<div style="padding:24px;text-align:center;color:#8B949E;font-size:12px">No file dependencies available for coupling matrix.</div>`;
  }

  const matrix = {};
  files.forEach(f1 => {
    matrix[f1] = {};
    files.forEach(f2 => { matrix[f1][f2] = 0; });
  });

  const nodeFileMap = new Map(nodes.map(n => [n.id, n.file ? path.basename(n.file) : '']));

  links.forEach(link => {
    const srcFile = nodeFileMap.get(link.source) || '';
    const tgtFile = nodeFileMap.get(link.target) || '';
    if (matrix[srcFile] && matrix[srcFile][tgtFile] !== undefined) {
      matrix[srcFile][tgtFile] += 1;
    }
  });

  const cellSize = 38;
  const padLeft = 140;
  const padTop = 140;
  const svgWidth = padLeft + files.length * cellSize + 40;
  const svgHeight = padTop + files.length * cellSize + 40;

  let headersX = '';
  let headersY = '';
  let gridCells = '';

  files.forEach((f, idx) => {
    const x = padLeft + idx * cellSize + cellSize / 2;
    const y = padTop + idx * cellSize + cellSize / 2;
    headersX += `<text x="${x}" y="${padTop - 12}" fill="#8B949E" font-size="10" font-family="monospace" text-anchor="start" transform="rotate(-45, ${x}, ${padTop - 12})">${f.slice(0, 14)}</text>`;
    headersY += `<text x="${padLeft - 10}" y="${y + 4}" fill="#8B949E" font-size="10" font-family="monospace" text-anchor="end">${f.slice(0, 14)}</text>`;
  });

  files.forEach((rFile, rIdx) => {
    files.forEach((cFile, cIdx) => {
      const count = matrix[rFile][cFile] || 0;
      const x = padLeft + cIdx * cellSize;
      const y = padTop + rIdx * cellSize;
      let cellFill = '#161B22';
      let textFill = '#484F58';

      if (count > 0) {
        if (rFile === cFile) {
          cellFill = 'rgba(88,166,255,0.25)';
          textFill = '#58A6FF';
        } else {
          cellFill = 'rgba(255,80,80,0.35)';
          textFill = '#FF7B72';
        }
      }

      gridCells += `
        <rect x="${x + 2}" y="${y + 2}" width="${cellSize - 4}" height="${cellSize - 4}" rx="4" fill="${cellFill}" stroke="#21262D"/>
        <text x="${x + cellSize / 2}" y="${y + cellSize / 2 + 4}" fill="${textFill}" font-size="11" font-family="monospace" font-weight="600" text-anchor="middle">${count > 0 ? count : '.'}</text>
      `;
    });
  });

  const blastCounts = {};
  (timeline || []).forEach(c => {
    (c.changed_files || []).forEach(f => {
      const b = path.basename(f);
      blastCounts[b] = (blastCounts[b] || 0) + 1;
    });
  });

  const blastRows = Object.entries(blastCounts).slice(0, 6).map(([file, count]) => `
    <tr>
      <td><code style="font-size:11px">${file}</code></td>
      <td style="font-family:monospace;color:#FFA500">${count} commit(s)</td>
      <td>
        <div style="background:#21262D;border-radius:3px;height:8px;width:160px;overflow:hidden">
          <div style="background:#FFA500;height:100%;width:${Math.min(100, count * 20)}%"></div>
        </div>
      </td>
    </tr>
  `).join('');

  return `
    <div style="background:#161B22;border:1px solid #30363D;border-radius:6px;padding:16px;margin-bottom:18px">
      <div style="font-size:12px;font-weight:600;color:#E6EDF3;margin-bottom:4px">CROSS-FILE TAINT COUPLING MATRIX</div>
      <div style="font-size:11px;color:#8B949E;margin-bottom:14px">Number of directed dataflow and call edges connecting project source files.</div>
      <div style="overflow-x:auto">
        <svg width="${svgWidth}" height="${svgHeight}" style="background:#0D1117;border-radius:6px">
          ${headersX}
          ${headersY}
          ${gridCells}
        </svg>
      </div>
    </div>

    <div style="background:#161B22;border:1px solid #30363D;border-radius:6px;padding:16px">
      <div style="font-size:12px;font-weight:600;color:#E6EDF3;margin-bottom:4px">COMMIT BLAST-RADIUS CO-CHANGE FREQUENCY</div>
      <div style="font-size:11px;color:#8B949E;margin-bottom:12px">Files most frequently co-modified in vulnerability-contributing commits.</div>
      <table>
        <thead><tr><th>File</th><th>Co-Change Frequency</th><th>Relative Blast Radius</th></tr></thead>
        <tbody>${blastRows || '<tr><td colspan="3" style="text-align:center;color:#6E7681">No commit history found.</td></tr>'}</tbody>
      </table>
    </div>
  `;
}

// ── Webview Dashboard Provider ────────────────────────────────────────────────
function refreshRiskPanel() {
  if (!_riskPanel) return;

  const timeline = _lastTimeline?.timeline || [];
  const sinks = (_lastGraph?.nodes || []).filter(n => n.type === 'sink');

  const RF_COLOR = rf => {
    if (rf >= 0.7) return '#FF4444';
    if (rf >= 0.45) return '#FF9500';
    if (rf >= 0.2) return '#FFD700';
    return '#1D9E75';
  };

  const commitRows = timeline.map(c => {
    const rf = c.risk_factor || 0;
    const col = RF_COLOR(rf);
    const shortHash = (c.commit_hash || '').slice(0, 7);
    const newPaths = c.new_attack_paths || 0;
    const guardEvents = c.guard_weakening_events || 0;
    const linesChanged = c.diff_lines_changed ? `+${c.diff_lines_changed}` : '';

    return `
      <tr>
        <td>
          <a href="#" onclick="openCommitDiff('${c.commit_hash}')" style="color:#58A6FF;font-family:monospace">
            ${shortHash}
          </a>
        </td>
        <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${c.message||''}">
          ${c.message || '—'}
        </td>
        <td style="color:#8B949E;font-size:11px">${c.author || '—'}</td>
        <td>
          <span style="background:${col}22;color:${col};border:1px solid ${col};padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600">
            ${c.severity || 'Low'}
          </span>
        </td>
        <td style="font-family:monospace;font-weight:600;color:${col}">${rf.toFixed(3)}</td>
        <td style="font-size:11px;color:#8B949E">
          ${newPaths > 0 ? `<span style="color:#FFA500">+${newPaths} path(s)</span> ` : ''}
          ${guardEvents > 0 ? `<span style="color:#FFD700">-${guardEvents} guard(s)</span> ` : ''}
          ${linesChanged}
        </td>
      </tr>
    `;
  }).join('');

  const sinkRows = sinks.map(n => {
    const rr = n.residual_risk != null ? n.residual_risk.toFixed(3) : 'N/A';
    const gs = n.effective_guard_strength != null ? (n.effective_guard_strength * 100).toFixed(0) + '%' : 'N/A';
    return `
      <tr>
        <td><code style="font-size:11px">${(n.label || n.id || '?').slice(0, 35)}</code></td>
        <td style="color:#8B949E;font-size:11px">${n.file || '?'}:${n.line || '?'}</td>
        <td><code style="color:#7EE787">${n.cwe || '?'}</code></td>
        <td style="color:${RF_COLOR(n.residual_risk || 0)};font-family:monospace">${rr}</td>
        <td style="color:#1D9E75;font-family:monospace">${gs}</td>
      </tr>
    `;
  }).join('');

  const criticalCount = timeline.filter(c => (c.risk_factor || 0) >= 0.7).length;
  const newPathsTotal = timeline.reduce((a, c) => a + (c.new_attack_paths || 0), 0);
  const guardEvents   = timeline.reduce((a, c) => a + (c.guard_weakening_events || 0), 0);
  const avgRF         = timeline.length
    ? (timeline.reduce((a, c) => a + (c.risk_factor || 0), 0) / timeline.length).toFixed(3) : '—';
  const srcLabel      = _lastTimeline?.source === 'live' ? 'LIVE' : 'DEMO';
  const scannedFolder = _currentRepoPath ? path.basename(_currentRepoPath) : 'Active Workspace';

  const callGraphHtml = generateCallGraphSvg(_lastGraph, _lastAttackPaths);
  const waterfallHtml = generateWaterfallSvg(_lastAttackPaths);
  const matrixHtml    = generateMatrixSvg(_lastGraph, timeline);

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
  .tabs { display: flex; border-bottom: 1px solid #21262D; background: #0D1117; overflow-x: auto; }
  .tab { padding: 10px 18px; cursor: pointer; font-size: 12px; color: #8B949E;
          border-bottom: 2px solid transparent; white-space: nowrap; }
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
    <h1>VulnGraph Risk Dashboard — <span style="color:#58A6FF">${scannedFolder}</span></h1>
    <div style="font-size:11px;color:#6E7681;margin-top:2px">
      Local SAST & Taint-Differential Risk Analysis — All AST parsing runs locally
    </div>
  </div>
  <div style="display:flex;gap:8px;align-items:center">
    <span class="src">[${srcLabel} DATA] · ${_lastScanData?.nodes || 0} nodes scanned</span>
    <button class="btn" onclick="open3D()">3D View</button>
    <button class="btn btn-primary" onclick="exportReport()">Export Report</button>
  </div>
</div>

<div class="stats">
  <div class="stat">
    <div class="stat-n" style="color:#FF4444">${criticalCount}</div>
    <div class="stat-l">Critical commits</div>
  </div>
  <div class="stat">
    <div class="stat-n" style="color:#FF9500">${_lastAttackPaths.length || newPathsTotal}</div>
    <div class="stat-l">Attack paths</div>
  </div>
  <div class="stat">
    <div class="stat-n" style="color:#00E676">${_lastScanData?.sources || 0}</div>
    <div class="stat-l">Entry sources</div>
  </div>
  <div class="stat">
    <div class="stat-n" style="color:#FF4444">${sinks.length}</div>
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
  <div class="tab" onclick="showTab('callgraph',this)">Call Graph Flow</div>
  <div class="tab" onclick="showTab('waterfall',this)">Attenuation Waterfall</div>
  <div class="tab" onclick="showTab('matrix',this)">Taint Coupling Matrix</div>
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

<!-- CALL GRAPH FLOW TAB -->
<div id="callgraph" class="panel">
  <div class="section-head">Inter-Procedural Call Graph & Taint Invocations</div>
  <p style="color:#8B949E;font-size:12px;margin-bottom:16px;line-height:1.6">
    Visualizes the direct function caller -> callee invocation chain through controllers, services, and execution sinks.
  </p>
  ${callGraphHtml}
</div>

<!-- ATTENUATION WATERFALL TAB -->
<div id="waterfall" class="panel">
  <div class="section-head">Guard Attenuation Waterfall — Multiplicative Taint Decay</div>
  <p style="color:#8B949E;font-size:12px;margin-bottom:16px;line-height:1.6">
    Visualizes how consecutive guard and sanitization nodes compound to attenuate taint flow probability from 1.00 down to the sink residual risk R(P) = Product(1 - A_i).
  </p>
  ${waterfallHtml}
</div>

<!-- TAINT COUPLING MATRIX TAB -->
<div id="matrix" class="panel">
  <div class="section-head">Cross-File Dataflow Coupling & Git Blast Radius</div>
  ${matrixHtml}
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
  <button class="btn btn-primary" onclick="runValidation()">Run Statistical Validation</button>
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

  function open3D() {
    vscode.postMessage({ command: 'open3D' });
  }

  function openCommitDiff(hash) {
    if (!hash.startsWith('parent')) {
      vscode.postMessage({ command: 'openCommitDiff', hash });
    }
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
            \${sig ? '[VALIDATED] TDRA Statistical Separation Confirmed' : '[INCONCLUSIVE] Not Statistically Significant'}
          </div>
          <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:10px">
            <div><span style="color:#6E7681">p-value:</span> <strong>\${p.toFixed(6)}</strong></div>
            <div><span style="color:#6E7681">Cliff's delta:</span> <strong>\${d.toFixed(4)}</strong></div>
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

function openRiskPanel(context) {
  if (_riskPanel) {
    _riskPanel.reveal(vscode.ViewColumn.Beside);
    refreshRiskPanel();
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
        const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '.';
        const uri = await vscode.window.showSaveDialog({
          defaultUri: vscode.Uri.file(path.join(ws, 'vulngraph_report.html')),
          filters: { 'HTML Report': ['html'] },
        });
        if (uri) {
          fs.writeFileSync(uri.fsPath, html, 'utf8');
          vscode.window.showInformationMessage(`Report saved: ${path.basename(uri.fsPath)}`);
          vscode.env.openExternal(uri);
        }
      } catch (e) {
        vscode.window.showErrorMessage('Export failed — is the backend running? ' + e.message);
      }
    }
    if (msg.command === 'open3D') {
      vscode.env.openExternal(vscode.Uri.parse('http://localhost:5173'));
    }
    if (msg.command === 'openCommitDiff' && msg.hash) {
      try {
        await vscode.commands.executeCommand('git.showCommit', msg.hash);
      } catch (e) {
        const out = vscode.window.createOutputChannel('VulnGraph Commit');
        out.clear();
        out.appendLine(`Commit: ${msg.hash}`);
        out.appendLine(`Inspect commit diff using VS Code Git extension or terminal: git show ${msg.hash}`);
        out.show();
      }
    }
  });

  if (!_lastGraph) {
    autoScanWorkspace().then(() => refreshRiskPanel()).catch(() => refreshRiskPanel());
  } else {
    refreshRiskPanel();
  }
}

// ── Extension Activation ──────────────────────────────────────────────────────
function activate(context) {
  // 1. Status Bar Item
  _statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  _statusBarItem.text = '$(shield) VulnGraph';
  _statusBarItem.tooltip = 'VulnGraph security analyzer — click to open dashboard';
  _statusBarItem.command = 'vulngraph.openDashboard';
  _statusBarItem.show();
  context.subscriptions.push(_statusBarItem);

  // 2. TreeDataProvider: Interactive Dataflow Step-by-Step Explorer
  _taintTreeProvider = new VulnGraphTaintTreeProvider();
  context.subscriptions.push(
    vscode.window.registerTreeDataProvider('vulngraph.taintView', _taintTreeProvider)
  );

  // 3. CodeLens Provider: Inline Execution Metrics
  _codeLensProvider = new VulnGraphCodeLensProvider();
  context.subscriptions.push(
    vscode.languages.registerCodeLensProvider({ language: 'python' }, _codeLensProvider),
    vscode.languages.registerCodeLensProvider({ language: 'java' }, _codeLensProvider)
  );

  // 4. CodeAction Provider: Interactive QuickFix / Patch Suggestions
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      [{ language: 'python' }, { language: 'java' }],
      new VulnGraphCodeActionProvider(),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix, vscode.CodeActionKind.RefactorRewrite] }
    )
  );

  // 5. Command Registrations
  context.subscriptions.push(
    vscode.commands.registerCommand('vulngraph.analyzeFile', () => {
      const doc = vscode.window.activeTextEditor?.document;
      if (doc) {
        analyzeFile(doc);
      } else {
        autoScanWorkspace();
      }
    }),

    vscode.commands.registerCommand('vulngraph.analyzeWorkspace', () => {
      autoScanWorkspace();
    }),

    vscode.commands.registerCommand('vulngraph.openDashboard', () => {
      openRiskPanel(context);
    }),

    vscode.commands.registerCommand('vulngraph.refreshDataflow', () => {
      autoScanWorkspace();
    }),

    vscode.commands.registerCommand('vulngraph.jumpToLocation', async (loc) => {
      await jumpToLocation(loc);
    }),

    vscode.commands.registerCommand('vulngraph.focusDataflowPath', () => {
      vscode.commands.executeCommand('vulngraph.taintView.focus');
    }),

    vscode.commands.registerCommand('vulngraph.simulatePatchNode', async (nodeId) => {
      const { backendUrl } = getConfig();
      if (!nodeId) return;
      try {
        const res = await apiFetch(`${backendUrl}/api/graph/patch/${encodeURIComponent(nodeId)}`, {
          method: 'POST',
        });
        const impact = res.patch_impact || {};
        const elim = impact.eliminated_paths != null ? impact.eliminated_paths : 0;
        const msg = `Simulated patch on node. Eliminated ${elim} attack path(s). Attack surface reduced.`;
        vscode.window.showInformationMessage(`VulnGraph: ${msg}`);

        await autoScanWorkspace();
      } catch (err) {
        vscode.window.showErrorMessage(`VulnGraph: Failed to simulate patch: ${err.message}`);
      }
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
          vscode.window.showInformationMessage(`Report saved: ${path.basename(uri.fsPath)}`);
          vscode.env.openExternal(uri);
        }
      } catch (e) {
        vscode.window.showErrorMessage('Export failed — is backend running? ' + e.message);
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
          `VulnGraph validation: ${sig ? 'SIGNIFICANT' : 'NOT SIGNIFICANT'} ` +
          `(p=${result.p_value?.toFixed(4)}, delta=${result.cliffs_delta?.toFixed(3)})`
        );
      } catch (e) {
        vscode.window.showErrorMessage('Validation failed: ' + e.message);
      }
    }),

    vscode.commands.registerCommand('vulngraph.checkCommitRisk', async () => {
      const { backendUrl } = getConfig();
      if (!_currentRepoPath) {
        _currentRepoPath = getWorkspacePath(null);
      }
      if (!_currentRepoPath) {
        vscode.window.showWarningMessage('VulnGraph: No workspace found.');
        return;
      }

      setStatus('$(sync~spin) VulnGraph: checking commit risk...', '');

      try {
        const data = await apiFetch(
          `${backendUrl}/api/tdra/timeline` +
          `?repo_path=${encodeURIComponent(_currentRepoPath)}&limit=5`
        );
        _lastTimeline = data;

        const latest = data.timeline?.slice(-1)[0];
        if (!latest) {
          vscode.window.showInformationMessage('VulnGraph: No commit history found.');
          return;
        }

        const rf = latest.risk_factor || 0;
        const sev = latest.severity || 'Low';
        const newPaths = latest.new_attack_paths || 0;
        const guardEvents = latest.guard_weakening_events || 0;
        const isDemo = data.source === 'mock';
        const demoNote = isDemo ? ' [demo data]' : '';

        const message = `[${sev.toUpperCase()} RISK]${demoNote}: RF ${rf.toFixed(3)}` +
          (newPaths > 0 ? ` | ${newPaths} new attack path(s)` : '') +
          (guardEvents > 0 ? ` | ${guardEvents} guard weakening event(s)` : '');

        if (rf >= 0.45) {
          const choice = await vscode.window.showWarningMessage(
            `VulnGraph Security Check: ${message}`,
            'View Details', 'Export Report', 'Dismiss'
          );
          if (choice === 'View Details') {
            openRiskPanel(context);
          } else if (choice === 'Export Report') {
            vscode.commands.executeCommand('vulngraph.exportReport');
          }
        } else {
          vscode.window.showInformationMessage(`VulnGraph Security Check: ${message}`);
        }

        if (_riskPanel) refreshRiskPanel();

        setStatus(
          `$(shield) VulnGraph: RF ${rf.toFixed(2)} (${sev})`,
          `Latest commit risk: ${sev} (RF ${rf.toFixed(3)})`
        );
      } catch (err) {
        vscode.window.showErrorMessage(
          'VulnGraph: Could not check commit risk. Is backend running at ' + backendUrl + '?'
        );
        setStatus('$(shield) VulnGraph', '');
      }
    })
  );

  // 6. Auto-analyze on File Save (Debounced)
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(doc => {
      const { autoAnalyze } = getConfig();
      if (!autoAnalyze) return;
      clearTimeout(_saveDebounce);
      _saveDebounce = setTimeout(() => analyzeFile(doc), 800);
    })
  );

  // 7. Re-apply decorations on editor switch
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(editor => {
      if (editor && _lastGraph) applyDecorations(editor.document, _lastGraph);
    })
  );

  // 8. Initial analyze on open (active document or entire workspace)
  const activeDoc = vscode.window.activeTextEditor?.document;
  if (activeDoc) {
    analyzeFile(activeDoc);
  } else {
    autoScanWorkspace();
  }
}

function deactivate() {
  Object.values(DECORATIONS).forEach(d => d.dispose());
  _statusBarItem?.dispose();
  _riskPanel?.dispose();
  clearTimeout(_saveDebounce);
}

module.exports = { activate, deactivate };
