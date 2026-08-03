const vscode = require('vscode');
const http = require('http');

// Node type colors matching the web UI
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

async function analyzeFile(document) {
  const config = vscode.workspace.getConfiguration('vulngraph');
  const backendUrl = config.get('backendUrl', 'http://localhost:8001');
  const filePath = document.uri.fsPath;
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  
  try {
    // POST to local backend — code never leaves the machine
    const response = await fetch(`${backendUrl}/api/cve/scan`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({project_path: workspaceRoot || filePath})
    });
    const data = await response.json();
    
    // Fetch the graph to get node positions
    const graphResp = await fetch(`${backendUrl}/api/graph`);
    const graph = await graphResp.json();
    
    // Apply decorations
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;
    
    const sourceRanges = [], sinkRanges = [], guardRanges = [];
    
    for (const node of graph.nodes || []) {
      if (node.file && document.uri.fsPath.endsWith(node.file)) {
        const line = (node.line || 1) - 1;
        const lineRange = document.lineAt(Math.min(line, document.lineCount-1)).range;
        const range = {range: lineRange, hoverMessage: 
          `VulnGraph: ${node.type?.toUpperCase()} — ${node.id}`};
        if (node.type === 'source') sourceRanges.push(range);
        else if (node.type === 'sink') sinkRanges.push(range);
        else if (node.type === 'sanitizer') guardRanges.push(range);
      }
    }
    
    editor.setDecorations(DECORATIONS.source, sourceRanges);
    editor.setDecorations(DECORATIONS.sink, sinkRanges);
    editor.setDecorations(DECORATIONS.sanitizer, guardRanges);
    
    vscode.window.showInformationMessage(
      `VulnGraph: Found ${data.sources} ENTRY, ${data.sinks} SINK nodes`
    );
  } catch (e) {
    vscode.window.showWarningMessage(
      `VulnGraph: Backend not reachable at ${backendUrl}. Start the local server.`
    );
  }
}

function activate(context) {
  // Auto-analyze on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(doc => {
      if (['python','java'].includes(doc.languageId)) analyzeFile(doc);
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
  Object.values(DECORATIONS).forEach(d => d.dispose());
}

module.exports = { activate, deactivate };
