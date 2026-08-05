const vscode = require('vscode');
const path = require('path');
const FormData = require('form-data');

const SUPPORTED_EXTENSIONS = new Set(['.py', '.java']);
const SKIPPED_DIRECTORIES = new Set(['.git', '.idea', '.vscode', '__pycache__', 'node_modules', '.venv', 'venv']);


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

async function uploadProject(projectUri, backendUrl) {
  const files = [];
  let fileCount = 0;

  async function addDirectory(directoryUri) {
    const entries = await vscode.workspace.fs.readDirectory(directoryUri);
    for (const [name, type] of entries) {
      const entryUri = vscode.Uri.joinPath(directoryUri, name);
      if (type === vscode.FileType.Directory) {
        if (!SKIPPED_DIRECTORIES.has(name)) await addDirectory(entryUri);
        continue;
      }
      if (type !== vscode.FileType.File || !SUPPORTED_EXTENSIONS.has(path.extname(name).toLowerCase())) continue;
      if (fileCount >= 5000) throw new Error('Project contains more than 5000 supported files');

      const content = await vscode.workspace.fs.readFile(entryUri);
      const relativePath = path.relative(projectUri.fsPath, entryUri.fsPath).replace(/\\\\/g, '/');
      files.push({ content: Buffer.from(content), relativePath });
      fileCount += 1;
    }
  }

  await addDirectory(projectUri);
  if (fileCount === 0) throw new Error('No Python or Java files were found in the selected project');

  const form = new FormData();
  form.append('folder_name', path.basename(projectUri.fsPath) || 'uploaded_project');
  for (const file of files) {
    form.append('files', file.content, { filename: file.relativePath });
  }

  const response = await fetch(`${backendUrl}/api/cve/scan/upload`, {
    method: 'POST',
    body: form,
    ...(form.getHeaders && { headers: form.getHeaders() })
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Project upload failed with status ${response.status}${errorText ? `: ${errorText}` : ''}`);
  }
  return response.json();
}

async function scanProject(projectPath, projectUri, backendUrl, scanMode) {
  if (scanMode === 'upload') return uploadProject(projectUri, backendUrl);

  const scanResponse = await fetch(`${backendUrl}/api/cve/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ project_path: projectPath })
  });
  if (scanResponse.ok) return scanResponse.json();

  const errorText = await scanResponse.text();
  const unavailablePath = scanResponse.status === 400 && /project_path must be an existing directory/i.test(errorText);
  if (scanMode === 'auto' && unavailablePath) return uploadProject(projectUri, backendUrl);
  throw new Error(`Scan request failed with status ${scanResponse.status}${errorText ? `: ${errorText}` : ''}`);
}

async function analyzeFile(document, selectedProjectUri) {
  const config = vscode.workspace.getConfiguration('vulngraph');
  const backendUrl = config.get('backendUrl', 'http://localhost:8002');

  try {
    const workspaceFolder = document ? vscode.workspace.getWorkspaceFolder(document.uri) : undefined;
    const projectUri = selectedProjectUri || workspaceFolder?.uri || vscode.workspace.workspaceFolders?.[0]?.uri;
    if (!projectUri) throw new Error('Open a project folder or use "VulnGraph: Select and Analyze Project"');
    const localWorkspacePath = projectUri.fsPath;
    // A Dockerized backend cannot access host paths such as C:\\project. Allow a
    // configured container-visible path while retaining the local default.
    const configuredProjectPath = config.get('projectPath', '').trim();
    const projectPath = configuredProjectPath || localWorkspacePath;
    const scanMode = config.get('scanMode', 'auto');

    const data = await scanProject(projectPath, projectUri, backendUrl, scanMode);

    if (!document) {
      vscode.window.showInformationMessage(
        `VulnGraph: Analysis complete. Found ${data.sources || 0} ENTRY and ${data.sinks || 0} SINK nodes in the selected project.`
      );
      return;
    }

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

  context.subscriptions.push(
    vscode.commands.registerCommand('vulngraph.selectAndAnalyzeProject', async () => {
      const selection = await vscode.window.showOpenDialog({
        canSelectFiles: false,
        canSelectFolders: true,
        canSelectMany: false,
        openLabel: 'Analyze Project'
      });
      if (!selection?.[0]) return;
      const doc = vscode.window.activeTextEditor?.document;
      analyzeFile(doc, selection[0]);
    })
  );
}

function deactivate() {
  if (saveDebounceTimer) clearTimeout(saveDebounceTimer);
  Object.values(DECORATIONS).forEach(d => d.dispose());
}

module.exports = { activate, deactivate };
