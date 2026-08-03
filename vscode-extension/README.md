# VulnGraph Security Analyzer VS Code Extension

Real-time ENTRY/SINK/GUARD detection with local analysis for Python and Java codebases.

## Key Features

- **100% Local and Private**: All analysis runs locally on your machine. Your source code never leaves your workspace or machine.
- **Visual Highlights**: Nodes in your program graphs are highlighted in the editor:
  - **ENTRY (Sources)** highlighted in Green.
  - **SINK (Sinks)** highlighted in Red.
  - **GUARD (Sanitizers)** highlighted in Purple.
- **Auto-Scan**: Automatically scans file modifications on save.

## Prerequisites

The VS Code extension requires the VulnGraph backend server running at `http://localhost:8001`.

To spin up the VulnGraph backend locally, run the following command in your VulnGraph project directory:
```bash
docker compose up --build
```

## How to Install

1. Install the global VS Code Extension Manager (`vsce`) if you haven't already:
   ```bash
   npm install -g @vscode/vsce
   ```
2. Navigate to the extension folder and package it into a `.vsix` bundle:
   ```bash
   cd vscode-extension
   vsce package
   ```
3. Open VS Code, open the Command Palette (`Ctrl+Shift+P` or `Cmd+Shift+P`), choose **Extensions: Install from VSIX...**, and select the generated `vulngraph-0.1.0.vsix` file.
