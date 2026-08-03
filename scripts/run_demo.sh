#!/bin/bash
# ============================================================
# VulnGraph Demo Launcher
# Starts backend + frontend and pre-warms the graph with demo_project
# Usage: bash scripts/run_demo.sh
# ============================================================
set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND_PORT=8001
FRONTEND_PORT=5173

echo "╔══════════════════════════════════════════════════╗"
echo "║         VulnGraph — Demo Mode                   ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "Project root : $REPO_ROOT"
echo "Backend      : http://127.0.0.1:$BACKEND_PORT"
echo "Frontend     : http://localhost:$FRONTEND_PORT"
echo ""

# ── 1. Kill any leftover processes on those ports ───────────────────────────
echo "[1/5] Freeing ports $BACKEND_PORT and $FRONTEND_PORT..."
lsof -ti tcp:$BACKEND_PORT | xargs kill -9 2>/dev/null || true
lsof -ti tcp:$FRONTEND_PORT | xargs kill -9 2>/dev/null || true
sleep 1

# ── 2. Start backend ────────────────────────────────────────────────────────
echo "[2/5] Starting FastAPI backend..."
cd "$REPO_ROOT"
uvicorn main:app --host 127.0.0.1 --port $BACKEND_PORT --reload &
BACKEND_PID=$!
echo "      Backend PID: $BACKEND_PID"

# Wait for backend to be ready
echo "      Waiting for backend to be healthy..."
for i in $(seq 1 20); do
  if curl -s "http://127.0.0.1:$BACKEND_PORT/" > /dev/null 2>&1; then
    echo "      ✓ Backend ready"
    break
  fi
  sleep 1
done

# ── 3. Start frontend ───────────────────────────────────────────────────────
echo "[3/5] Starting Vite dev server..."
cd "$REPO_ROOT"
npm run dev &
FRONTEND_PID=$!
echo "      Frontend PID: $FRONTEND_PID"
sleep 3

# ── 4. Pre-warm: scan demo_project ─────────────────────────────────────────
echo "[4/5] Pre-warming graph with demo_project..."
SCAN_RESPONSE=$(curl -s -X POST "http://127.0.0.1:$BACKEND_PORT/api/cve/scan" \
  -H "Content-Type: application/json" \
  -d "{\"project_path\": \"$REPO_ROOT/demo_project\"}" 2>/dev/null || echo "{}")

NODES=$(echo "$SCAN_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('nodes','?'))" 2>/dev/null || echo "?")
PATHS=$(echo "$SCAN_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('paths_found','?'))" 2>/dev/null || echo "?")
echo "      ✓ Scanned demo_project — $NODES nodes, $PATHS attack paths found"

# ── 5. Open browser ─────────────────────────────────────────────────────────
echo "[5/5] Opening browser..."
if command -v xdg-open > /dev/null 2>&1; then
  xdg-open "http://localhost:$FRONTEND_PORT" &
elif command -v open > /dev/null 2>&1; then
  open "http://localhost:$FRONTEND_PORT" &
fi

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  ✓ VulnGraph ready at http://localhost:$FRONTEND_PORT   ║"
echo "║  Press Ctrl+C to stop all processes              ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ── Cleanup on exit ─────────────────────────────────────────────────────────
cleanup() {
  echo ""
  echo "Stopping VulnGraph..."
  kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
  lsof -ti tcp:$BACKEND_PORT | xargs kill -9 2>/dev/null || true
  lsof -ti tcp:$FRONTEND_PORT | xargs kill -9 2>/dev/null || true
  echo "Done."
}
trap cleanup INT TERM

wait
