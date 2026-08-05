const vscode = require('vscode');

const SUPPORTED_EXTENSIONS = new Set(['.py', '.java']);

const DECORATIONS = {
  source: vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(0,200,100,0.15)',
    borderLeft: '3px solid #00C864',
    after: { contentText: ' ⬤ ENTRY', color: '#00C864', margin: '0 0 0 8px' }
  }),
  sink: vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(255,80,80,0.15)',
    borderLeft: '3px solid #FF5050',
    after: { contentText: ' ⬤ SINK', color: '#FF5050', margin: '0 0 0 8px' }
  }),
  sanitizer: vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(180,100,255,0.15)',
    borderLeft: '3px solid #B464FF',
    after: { contentText: ' ⬤ GUARD', color: '#B464FF', margin: '0 0 0 8px' }
  })
};

let saveDebounceTimer = null;

async function scanProject(projectPath, backendUrl) {
  console.log('Backend request sent');
  const scanResponse = await fetch(`${backendUrl}/api/cve/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ project_path: projectPath })
  });
  if (scanResponse.ok) {
    const data = await scanResponse.json();
    return data;
  }

  const errorText = await scanResponse.text();
  throw new Error(`Scan request failed with status ${scanResponse.status}${errorText ? `: ${errorText}` : ''}`);
}

async function analyzeFile(document) {
  if (!document) return;

  const ext = document.fileName ? document.fileName.substring(document.fileName.lastIndexOf('.')).toLowerCase() : '';
  if (!['.py', '.java'].includes(ext) && !['python', 'java'].includes(document.languageId)) {
    return;
  }

  const config = vscode.workspace.getConfiguration('vulngraph');
  const backendUrl = config.get('backendUrl', 'http://localhost:8002');

  const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri) || vscode.workspace.workspaceFolders?.[0];
  if (!workspaceFolder) {
    vscode.window.showErrorMessage('No workspace folder is open.');
    return;
  }

  const path = require('path');
  const fs = require('fs');

  const docFsPath = document.uri.fsPath;
  let projectPath = workspaceFolder.uri.fsPath;

  // Walk up from document folder to workspace root to resolve specific sub-project folder (e.g. demo_project, sample_project)
  let currentDir = path.dirname(docFsPath);
  const wsFsPathNorm = workspaceFolder.uri.fsPath.replace(/\\/g, '/').toLowerCase();

  while (currentDir) {
    const normCurrent = currentDir.replace(/\\/g, '/').toLowerCase();
    if (!normCurrent.startsWith(wsFsPathNorm)) break;

    const files = fs.existsSync(currentDir) ? fs.readdirSync(currentDir) : [];
    const hasProjectFile = files.some(f => ['requirements.txt', 'pom.xml', 'build.gradle', 'package.json'].includes(f));
    const isSubdirOfWs = path.dirname(currentDir).replace(/\\/g, '/').toLowerCase() === wsFsPathNorm;

    if (hasProjectFile || (isSubdirOfWs && (ext === '.py' || ext === '.java'))) {
      projectPath = currentDir;
      break;
    }

    if (normCurrent === wsFsPathNorm) break;
    currentDir = path.dirname(currentDir);
  }

  try {
    const data = await scanProject(projectPath, backendUrl);

    // Fetch full graph nodes for line decoration matching (/api/graph)
    const graphResp = await fetch(`${backendUrl}/api/graph`);
    if (!graphResp.ok) {
      throw new Error(`Graph fetch failed with status ${graphResp.status}`);
    }
    const graph = await graphResp.json();
    console.log('Backend response received');

    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document.uri.toString() !== document.uri.toString()) return;

    const path = require('path');

    // Platform-safe path normalization (Windows backslashes vs POSIX forward slashes & lowercase)
    const norm = p => (p || '').replace(/\\/g, '/').toLowerCase();
    const docFsPathNorm = norm(document.uri.fsPath);
    const relPathNorm = norm(vscode.workspace.asRelativePath(document.uri, false));
    const docFileNameNorm = norm(path.basename(document.uri.fsPath));

    const sourceRanges = [];
    const sinkRanges = [];
    const guardRanges = [];

    for (const node of graph.nodes || []) {
      const nodeFileNorm = norm(node.file);
      const nodeIdFile = norm((node.id || '').split('::')[0]);

      // Robust matching against absolute fsPath, workspace relative path, node ID path, and filename
      const isMatch = Boolean(
        (nodeFileNorm && nodeFileNorm === docFsPathNorm) ||
        (nodeFileNorm && nodeFileNorm === relPathNorm) ||
        (nodeFileNorm && docFsPathNorm.endsWith(nodeFileNorm)) ||
        (nodeFileNorm && nodeFileNorm.endsWith('/' + relPathNorm)) ||
        (relPathNorm && relPathNorm.endsWith('/' + nodeFileNorm)) ||
        (nodeIdFile && nodeIdFile === relPathNorm) ||
        (nodeIdFile && docFsPathNorm.endsWith('/' + nodeIdFile)) ||
        (nodeIdFile && docFsPathNorm.endsWith(nodeIdFile)) ||
        (relPathNorm && relPathNorm.endsWith(nodeIdFile)) ||
        (nodeIdFile && nodeIdFile.endsWith(relPathNorm)) ||
        (nodeIdFile && nodeIdFile.endsWith('/' + docFileNameNorm)) ||
        (nodeIdFile && nodeIdFile === docFileNameNorm)
      );

      if (isMatch) {
        const line = (node.line || 1) - 1;
        const clampedLine = Math.max(0, Math.min(line, document.lineCount - 1));
        const lineRange = document.lineAt(clampedLine).range;
        const hoverText = `VulnGraph: ${(node.type || '').toUpperCase()} — ${node.id} (${node.label || ''})`;
        const rangeObj = { range: lineRange, hoverMessage: hoverText };

        if (node.type === 'source') {
          sourceRanges.push(rangeObj);
        } else if (node.type === 'sink') {
          sinkRanges.push(rangeObj);
        } else if (node.type === 'sanitizer') {
          guardRanges.push(rangeObj);
        }
      }
    }

    // Apply editor line decorations
    editor.setDecorations(DECORATIONS.source, sourceRanges);
    editor.setDecorations(DECORATIONS.sink, sinkRanges);
    editor.setDecorations(DECORATIONS.sanitizer, guardRanges);
    console.log('Decorations applied');

    vscode.window.showInformationMessage(
      `VulnGraph: Analysis complete. Found ${sourceRanges.length} ENTRY, ${sinkRanges.length} SINK, and ${guardRanges.length} GUARD nodes in this file. (Workspace total: ${data.sources || 0} sources, ${data.sinks || 0} sinks)`
    );
  } catch (e) {
    vscode.window.showWarningMessage(
      `VulnGraph: Backend not reachable at ${backendUrl}, or analysis failed (${e.message}). Start the local server and check the Output panel for details.`
    );
  }
}

function debouncedAnalyze(document) {
  if (saveDebounceTimer) clearTimeout(saveDebounceTimer);
  saveDebounceTimer = setTimeout(() => analyzeFile(document), 1500);
}

function activate(context) {
  console.log('Extension activated');
  // Listen for file save events
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(doc => {
      const config = vscode.workspace.getConfiguration('vulngraph');
      if (!config.get('analyzeOnSave', true)) return;
      debouncedAnalyze(doc);
    })
  );

  // Listen for editor tab change events (decorations render when switching tabs)
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(editor => {
      if (editor?.document) {
        analyzeFile(editor.document);
      }
    })
  );

  // Listen for file open events
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(doc => {
      analyzeFile(doc);
    })
  );

  // Register manual commands
  context.subscriptions.push(
    vscode.commands.registerCommand('vulngraph.analyzeFile', () => {
      const doc = vscode.window.activeTextEditor?.document;
      if (doc) analyzeFile(doc);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('vulngraph.analyzeWorkspace', () => {
      const doc = vscode.window.activeTextEditor?.document;
      if (doc) analyzeFile(doc);
    })
  );

  // Trigger immediate analysis on active document upon activation
  if (vscode.window.activeTextEditor?.document) {
    analyzeFile(vscode.window.activeTextEditor.document);
  }
}

function deactivate() {
  if (saveDebounceTimer) clearTimeout(saveDebounceTimer);
  Object.values(DECORATIONS).forEach(d => d.dispose());
}

module.exports = { activate, deactivate };
