#!/bin/bash
cd "$(dirname "$0")/.."
echo "Starting VulnGraph backend for IDE extension on port 8002..."
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8002 --reload
