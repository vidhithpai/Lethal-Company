# VulnGraph VS Code Extension 🔍

> **Real-time ENTRY, SINK, and GUARD line decorations powered by your local VulnGraph backend.**

---

## Features

- **Local & Private**: All code analysis runs on your local machine — no source code is ever uploaded to external servers.
- **Visual Gutter & In-line Decorations**:
  - 🟢 **ENTRY** (`source` nodes): Highlights entry points (HTTP params, inputs, environment variables).
  - 🔴 **SINK** (`sink` nodes): Highlights dangerous operations (SQL execution, command execution, `eval`).
  - 🟣 **GUARD** (`sanitizer` nodes): Highlights sanitization and validation calls.
- **Automated Analysis on Save**: Automatically re-analyzes Python (`.py`) and Java (`.java`) files upon saving (debounced by 1500ms).
- **Manual Commands**: Run `VulnGraph: Analyze Current File` or `VulnGraph: Analyze Workspace` on demand.

---

## Backend Requirements

The extension communicates with the local VulnGraph FastAPI backend service:
- Default URL: `http://localhost:8002`
- Endpoints consumed:
  - `POST /api/cve/scan` (Triggers workspace AST scan and returns source/sink counts)
  - `GET /api/graph` (Retrieves full node graph for line decoration matching)

Make sure the backend server is running locally:
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8002
```

---

## Configuration

You can customize extension behavior in VS Code Settings (`Ctrl+,` or `Cmd+,` -> search `VulnGraph`):

| Setting | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `vulngraph.backendUrl` | `string` | `http://localhost:8002` | URL of the local VulnGraph backend server |
| `vulngraph.projectPath` | `string` | _(empty)_ | Path that the backend can access. Set this to `/app/demo_project` or `/app/sample_project` when using the supplied Docker setup. |
| `vulngraph.analyzeOnSave` | `boolean` | `true` | Automatically re-analyze supported files on save (1500ms debounce) |

### Testing with Docker

The extension runs on the host, while the backend container sees only its mounted paths. To test the supplied Docker setup, open `demo_project` in VS Code and set `vulngraph.projectPath` to `/app/demo_project` in the workspace settings. For a different project, mount it into the backend container and set this value to the corresponding container path.

---

## Installation & Development

### Packaging to `.vsix`
To package the extension locally into a VSIX file for distribution:

1. Install `vsce` (Visual Studio Code Extension Manager):
   ```bash
   npm install -g @vscode/vsce
   ```
2. Run package command inside `vscode-extension/`:
   ```bash
   cd vscode-extension
   vsce package
   ```
3. Install VSIX in VS Code:
   - In VS Code, open Extensions view (`Ctrl+Shift+X` / `Cmd+Shift+X`).
   - Click the `...` (Views and More Actions) menu -> **Install from VSIX...**
   - Select `vulngraph-0.1.0.vsix`.

---

## Commands

- `vulngraph.analyzeFile`: Triggers security analysis for the currently active editor file.
- `vulngraph.analyzeWorkspace`: Triggers security analysis for the entire workspace.
