const vscode = require('vscode');

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

async function analyzeFile(document) {
  const config = vscode.workspace.getConfiguration('vulngraph');
  const backendUrl = config.get('backendUrl', 'http://localhost:8002');

  try {
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
    const localWorkspacePath = workspaceFolder ? workspaceFolder.uri.fsPath : (vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || document.uri.fsPath);
    // A Dockerized backend cannot access host paths such as C:\\project. Allow a
    // configured container-visible path while retaining the local default.
    const configuredProjectPath = config.get('projectPath', '').trim();
    const projectPath = configuredProjectPath || localWorkspacePath;

    // Trigger local scan endpoint (/api/cve/scan)
    const scanResponse = await fetch(`${backendUrl}/api/cve/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ project_path: projectPath })
    });

    if (!scanResponse.ok) {
      const errorText = await scanResponse.text();
      throw new Error(`Scan request failed with status ${scanResponse.status}${errorText ? `: ${errorText}` : ''}`);
    }

    const data = await scanResponse.json();

    // Fetch full graph nodes for line decoration matching (/api/graph)
    const graphResp = await fetch(`${backendUrl}/api/graph`);
    if (!graphResp.ok) {
      throw new Error(`Graph fetch failed with status ${graphResp.status}`);
    }
    const graph = await graphResp.json();

    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document.uri.toString() !== document.uri.toString()) return;

    // Platform-safe path normalization (Windows backslashes vs POSIX forward slashes)
    const norm = p => (p || '').replace(/\\/g, '/');
    const relPath = norm(vscode.workspace.asRelativePath(document.uri, false));

    const sourceRanges = [];
    const sinkRanges = [];
    const guardRanges = [];

    for (const node of graph.nodes || []) {
      if (!node.file) continue;

      const nodeFileNorm = norm(node.file);
      // Platform-safe relative path matching
      if (nodeFileNorm === relPath || nodeFileNorm.endsWith('/' + relPath) || relPath.endsWith('/' + nodeFileNorm)) {
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
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(doc => {
      const config = vscode.workspace.getConfiguration('vulngraph');
      if (!config.get('analyzeOnSave', true)) return;
      if (['python', 'java'].includes(doc.languageId)) {
        debouncedAnalyze(doc);
      }
    })
  );

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
}

function deactivate() {
  if (saveDebounceTimer) clearTimeout(saveDebounceTimer);
  Object.values(DECORATIONS).forEach(d => d.dispose());
}

module.exports = { activate, deactivate };
