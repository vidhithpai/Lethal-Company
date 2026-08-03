#!/bin/bash
# ============================================================
# VulnGraph VS Code Extension Packager & Installer
# Packs the extension to a local .vsix file and installs it.
# ============================================================
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "Packaging VulnGraph VS Code Extension..."

# Clean up previous builds
rm -f *.vsix

# Install vsce globally if missing
if ! command -v vsce &> /dev/null; then
  echo "vsce not found globally. Attempting to install..."
  npm install -g @vscode/vsce 2>/dev/null || true
fi

# Package extension
if command -v vsce &> /dev/null; then
  vsce package --no-dependencies
else
  # fallback to node_modules local binary
  ./node_modules/.bin/vsce package --no-dependencies
fi

# Find compiled VSIX package
VSIX=$(ls *.vsix | head -1)

if [ -z "$VSIX" ]; then
  echo "Error: Failed to package extension."
  exit 1
fi

echo "Successfully packaged: $VSIX"

# Install extension to VS Code
if command -v code &> /dev/null; then
  echo "Installing to VS Code..."
  code --install-extension "$VSIX"
  echo "✓ VulnGraph extension installed. Please reload VS Code to activate."
else
  echo "Warning: 'code' command not found in PATH. Install the .vsix package manually in VS Code."
fi
