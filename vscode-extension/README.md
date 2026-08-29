# VulnGraph — Security Analysis for VS Code

VulnGraph is a local static application security testing (SAST) and Taint-Differential Risk Analysis (TDRA) extension for Python and Java codebases. It performs real-time taint analysis to highlight vulnerability entry points, sinks, and sanitizers directly inside your editor. Crucially, VulnGraph tracks commit-level risk evolution, scoring every git commit with a deterministic Risk Factor (RF) based on introduced attack paths and guard weakening events. All analysis runs 100% locally on your machine.

## What it does

- **Inline Risk Decorations**: On file save, highlights `ENTRY` (sources), `SINK` (vulnerable operations), `GUARD` (sanitizers), `CRITICAL SINK` (high residual risk > 0.7), and `NEW PATH` (introduced by latest commit) lines directly in the editor.
- **Rich Hover Insights**: Displays CWE identifiers, residual risk scores, guard attenuation strength %, and git blame attribution on decorated code lines.
- **Interactive Risk Dashboard**: 3-tab webview containing:
  1. *Commit Timeline*: Commit risk factor bars, severity ratings, expandable new attack paths, and click-to-diff inspection.
  2. *Sink Analysis*: Filtered inventory of sink nodes and residual taint risk.
  3. *Statistical Validation*: Inline Mann-Whitney U test and Cliff's delta effect size calculator against known vulnerability-contributing commits (VCCs).
- **Pre-Commit Security Check**: Integrated Source Control (SCM) panel action (`vulngraph.checkCommitRisk`) to evaluate commit risk before pushing changes.
- **HTML Report Export**: Generates self-contained security audit reports.
- **3D Web UI Bridge**: Launches the interactive 3D attack graph web application (`http://localhost:5173`) directly from the dashboard.

## Requirements

- **Local VulnGraph Backend**: FastAPI backend running locally (`http://localhost:8002` or `http://localhost:8001`).
- **VS Code Git Extension**: Built-in VS Code Git extension enabled for diff viewing and SCM title action integration.
- **Workspace Git Repository**: Workspace open with git history for commit-level TDRA differential analysis (falls back to demo mode if unavailable).

## Installation

### From VSIX Package (UI)
1. Open VS Code **Extensions** view (`Ctrl+Shift+X` / `Cmd+Shift+X`).
2. Click the `...` (three dots) menu at the top right of the Extensions panel.
3. Select **Install from VSIX...** and choose `vscode-extension/vulngraph-0.2.0.vsix`.

### Via Command Line
```bash
code --install-extension vscode-extension/vulngraph-0.2.0.vsix
```

## Setup

1. Start the local VulnGraph backend server:
   ```bash
   ./scripts/start_extension_backend.sh
   ```
2. Open VS Code Settings (`Ctrl+,` / `Cmd+,`), search for `vulngraph.backendUrl`, and verify it points to `http://localhost:8002` (or `http://localhost:8001` if running via Docker).
3. Open a Python or Java workspace folder containing git history.

## Usage

- **Auto-Scan on Save**: Open any `.py` or `.java` file and save (`Ctrl+S`). Line decorations and status bar indicators update automatically.
- **Inspect Line Vulnerabilities**: Hover cursor over any decorated line to view CWE classification, residual risk, and git attribution.
- **Open Risk Dashboard**: Open Command Palette (`Ctrl+Shift+P`), run `VulnGraph: Open Risk Dashboard` (or click the status bar item).
- **Pre-Commit Check**: Open the Source Control panel (`Ctrl+Shift+G`) and click the VulnGraph commit icon (`vulngraph.checkCommitRisk`) in the title bar before committing.
- **Export HTML Report**: Run `VulnGraph: Export Security Report` from the Command Palette or click **⬇ Export Report** in the webview dashboard.

## Settings

| Setting | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `vulngraph.backendUrl` | `string` | `"http://localhost:8002"` | Local VulnGraph backend API URL. |
| `vulngraph.autoAnalyzeOnSave` | `boolean` | `true` | Automatically trigger analysis on file save (debounced 800ms). |
| `vulngraph.showGuardDecorations` | `boolean` | `true` | Show `GUARD` node decorations on sanitizer methods. |

## How to test this extension

1. **Start Backend**: Run `python -m uvicorn backend.main:app --port 8002 --reload` or `./scripts/start_extension_backend.sh`.
2. **Launch Extension**: Open `vscode-extension/` in VS Code and press `F5` (Extension Development Host), or install `vulngraph-0.2.0.vsix`.
3. **Test with Demo Project (No Git Required)**:
   - Open `demo_project/app.py`, save the file, confirm `ENTRY`, `SINK`, and `GUARD` decorations appear.
4. **Test with Real Git Repository (TDRA Analysis)**:
   - Clone test repo: `git clone https://github.com/appsecco/dvja.git /tmp/dvja_test`.
   - Open `/tmp/dvja_test`, save any `.java` file, confirm status bar displays `RF X.XX (Severity)`.
   - Open Risk Dashboard (`vulngraph.openDashboard`) and verify commit timeline populates with real commit hashes.
5. **Test Offline Behavior**:
   - Stop the backend process, save a file, and confirm status bar displays `$(warning) VulnGraph: backend offline` without editor freezing or crashing.
6. **Smoke Test Verification Checklist**:
   - [x] Open `.py`/`.java` file $\rightarrow$ green/red/purple decorations appear on save.
   - [x] Hover SINK decoration $\rightarrow$ tooltip shows CWE, residual risk, file:line.
   - [x] Command Palette $\rightarrow$ `VulnGraph: Open Risk Dashboard` opens 3-tab panel.
   - [x] Dashboard Tab 1: commit timeline with RF bars loads.
   - [x] Dashboard Tab 3: paste commit hash $\rightarrow$ validation runs $\rightarrow$ p-value appears.
   - [x] Source Control panel $\rightarrow$ VulnGraph commit icon visible.
   - [x] Click commit icon $\rightarrow$ notification with RF score appears.
   - [x] `VulnGraph: Export Security Report` $\rightarrow$ save dialog $\rightarrow$ HTML opens in browser.
   - [x] Status bar shows `$(shield) VulnGraph: N sinks · RF X.XX (Severity)`.
   - [x] Backend offline $\rightarrow$ status bar shows offline, no crash.

## Known limitations

- **Heuristic Java Parser**: Java AST parsing relies on heuristic pattern matching rather than full compilation unit symbol resolution.
- **Sanitizer Attenuation**: Static guard strength rules evaluate predefined sanitizer patterns, which may produce false positives/negatives on custom validation wrappers.
- **Git Commit Diff View**: `openCommitDiff` delegates to VS Code's native `git.showCommit` command; if unhandled by installed git extensions, it falls back to a formatted output channel log.

## Architecture

The VS Code extension acts as the lightweight IDE client layer of VulnGraph, communicating asynchronously via HTTP JSON endpoints with the local FastAPI backend service. For complete details on the graph engine, taint propagation algorithm, and TDRA Risk Factor formulation, see the main [VulnGraph Architecture Documentation](../README.md).
