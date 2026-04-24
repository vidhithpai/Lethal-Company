# VulnGraph 🔍

> **AI-powered code security analysis that finds attack paths before attackers do.**

VulnGraph scans Python codebases, builds an interactive 3D graph of how dangerous data flows through your code, and uses Google Gemini AI to explain vulnerabilities in plain English.

---

## Table of Contents

- [What Is VulnGraph?](#what-is-vulngraph)
- [How It Works — Plain English](#how-it-works--plain-english)
- [Live Demo Flow](#live-demo-flow)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Running the App](#running-the-app)
- [Using the App](#using-the-app)
- [API Reference](#api-reference)
- [Key Concepts Explained](#key-concepts-explained)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## What Is VulnGraph?

VulnGraph is a **security analysis tool** that reads Python source code and answers the question:

> *"If an attacker sends malicious input to my app, how far can it travel, and what damage can it do?"*

It does this by:
1. **Reading your code** like a security expert would
2. **Drawing a map** (the graph) of where dangerous data can flow
3. **Highlighting the riskiest routes** (attack paths) from input → danger
4. **Letting you ask questions** in plain English ("show me SQL injection paths")
5. **Showing who introduced** each vulnerability and when (via git blame)

**You do not need to be a security expert to use it.** The AI explains everything.

---

## How It Works — Plain English

Imagine your web application is a building. Users enter through the **front door** (HTTP requests). Inside the building there are **dangerous rooms** — places where, if a bad actor gets in, they can steal data (SQL injection), run commands on your server (command injection), or read files they shouldn't (path traversal).

VulnGraph:

1. **Finds all the doors** — every place your code reads user input (`request.args`, `request.form`, form fields, etc.). These are called **Sources** 🟢.

2. **Finds all the dangerous rooms** — every place your code does something risky with data (runs a database query, executes a shell command, writes a file, calls `eval()`). These are called **Sinks** 🔴.

3. **Traces every corridor** between doors and rooms — follows the data as it moves through variables, function calls, and assignments. These intermediate steps are shown as **yellow nodes**.

4. **Checks for security guards** — sanitizer functions like `sanitize_input()`, `escape()`, `validate()` that clean data before it reaches danger. These are **purple nodes** 🟣.

5. **Scores the risk** — a path from a source to a sink with no sanitizer is **HIGH** risk. One that passes through a sanitizer is lower risk.

6. **Asks Gemini AI** to explain what it found and suggest fixes.

---

## Live Demo Flow

The project includes an intentionally vulnerable demo app at `demo_project/`:

```
demo_project/
├── app.py      ← Flask app with 4 vulnerabilities built in
├── db.py       ← SQL injection (vulnerable) + parameterized (safe) side by side
└── utils.py    ← Path traversal + sanitizer functions
```

**What VulnGraph will find in the demo:**

| Vulnerability | File | Severity |
|--------------|------|----------|
| SQL Injection | `db.py:8` — `cursor.execute(f"...{query}")` | 🔴 HIGH |
| Command Injection | `app.py:18` — `subprocess.run(cmd, shell=True)` | 🔴 HIGH |
| Code Injection | `app.py:25` — `eval(expr)` | 🔴 CRITICAL |
| Path Traversal | `utils.py:8` — `open(filename)` | 🟠 MEDIUM |
| Safe path | `db.py:17` — `cursor.execute(q, (param,))` | ✅ LOW (parameterized) |

---

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| **Frontend** | React 18 + Vite | Fast dev server, hot reload |
| **3D Graph** | `react-force-graph-3d` + Three.js | Interactive force-directed 3D visualization |
| **Node labels** | `three-spritetext` | Floating text in 3D space |
| **State** | Zustand | Lightweight, no boilerplate |
| **Backend** | FastAPI (Python) | Fast async API, auto-generates docs |
| **AST Analysis** | Python `ast` module | Reads code structure without running it |
| **Graph Engine** | NetworkX | Shortest path, taint propagation |
| **AI** | Google Gemini 2.0 Flash | Natural language security explanations |
| **Git Analysis** | `git blame` via subprocess | Commit attribution |

---

## Project Structure

```
Lethal-Company/               ← project root (yes, the folder name is Lethal-Company)
│
├── main.py                   ← FastAPI app entry point — wires all routers together
├── requirements.txt          ← Python dependencies
├── .env                      ← GEMINI_API_KEY lives here
│
├── backend/
│   ├── services/
│   │   ├── code_security_graph.py  ← ⭐ THE BRAIN: AST scanner + taint engine + graph builder
│   │   └── git_history.py          ← git blame, commit attribution, blast radius
│   │
│   └── routers/
│       ├── security.py      ← /api/graph, /api/attack-paths, /api/high-risk-paths
│       ├── scan.py          ← /api/cve/scan (triggers the AST analysis)
│       ├── query.py         ← /api/query/ask (Gemini AI integration)
│       └── git_router.py    ← /api/git/blame, /api/git/timeline
│
├── src/                      ← React frontend
│   ├── main.jsx              ← React entry point
│   ├── App.jsx               ← Root component, loads graph on startup
│   ├── api.js                ← All API endpoint URLs in one place
│   ├── styles.css            ← Global dark theme CSS
│   │
│   ├── components/
│   │   ├── GraphCanvas.jsx   ← 3D force graph renderer (Three.js)
│   │   ├── SidePanel.jsx     ← Selected node details, git blame, attack path edges
│   │   ├── QueryBar.jsx      ← Search bar + scan controls
│   │   └── EntryPage.jsx     ← Landing page
│   │
│   └── store/
│       └── useStore.js       ← Zustand global state (graph, path, selectedNode)
│
├── demo_project/             ← Intentionally vulnerable Flask app for demo scanning
│   ├── app.py
│   ├── db.py
│   └── utils.py
│
├── package.json              ← Node dependencies (React, Three.js, etc.)
└── vite.config.js            ← Vite build configuration
```

### The Two Most Important Files

**`backend/services/code_security_graph.py`** — This is where all the magic happens:
- Walks every `.py` file in the scanned folder
- Parses each file into an AST (Abstract Syntax Tree — a structured representation of code)
- Identifies sources, sinks, and sanitizers using pattern matching
- Runs taint propagation: tracks whether "tainted" (user-controlled) data reaches a sink
- Builds a `networkx.DiGraph` where nodes = code elements, edges = data flow
- Computes risk scores and HIGH/MEDIUM/LOW classifications

**`src/components/GraphCanvas.jsx`** — The 3D visualization:
- Renders the graph using Three.js force simulation
- Green spheres = sources, Red = sinks, Yellow = tainted intermediates, Purple = sanitizers
- Attack paths glow red with animated particles when highlighted
- Click any node to see details in the side panel

---

## Getting Started

### Prerequisites

You need these installed on your machine:

| Tool | Check if installed | Install |
|------|-------------------|---------|
| **Python 3.11+** | `python3 --version` | https://python.org |
| **Node.js 18+** | `node --version` | https://nodejs.org |
| **uv** (Python pkg manager) | `uv --version` | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| **git** | `git --version` | pre-installed on most systems |

> **Why `uv` instead of `pip`?** On modern Ubuntu systems `pip` is often not on the PATH. `uv` is faster and always works. You can also use `python3 -m pip` if you prefer.

---

### Installation

**Step 1 — Clone and enter the project**
```bash
git clone <repo-url>
cd Lethal-Company
```

**Step 2 — Install Python dependencies**
```bash
# Option A: using uv (recommended)
uv pip install -r requirements.txt

# Option B: using python3 -m pip
python3 -m pip install -r requirements.txt

# Option C: activate the existing venv first
source .venv/bin/activate
pip install -r requirements.txt
```

**Step 3 — Install Node dependencies**
```bash
npm install
```

**Step 4 — Set your Gemini API key**

The `.env` file already exists with a key. If you want to use your own:
```bash
# .env
GEMINI_API_KEY=your_key_here
```
Get a free key at: https://aistudio.google.com/apikey

---

## 🐳 Running with Docker (Recommended for sharing / other machines)

This is the **one-command** path. Docker handles Python, Node, nginx, and all dependencies automatically.

### Prerequisites

| Tool | Check | Install |
|------|-------|---------|
| **Docker** | `docker --version` | https://docs.docker.com/get-docker/ |
| **Docker Compose** | `docker compose version` | bundled with Docker Desktop |

### Steps

**Step 1 — Set your API key**
```bash
# Copy the example file
cp .env.example .env

# Edit .env and paste your Gemini key
# GEMINI_API_KEY=your_key_here
```

**Step 2 — Build and start everything**
```bash
docker compose up --build
```

That's it. First run takes ~2–3 minutes (downloads base images, builds layers). Subsequent runs are fast thanks to Docker layer caching.

**Step 3 — Open the app**
```
http://localhost:5173
```

### What Docker starts

| Container | What it runs | Port |
|-----------|-------------|------|
| `vulngraph-backend` | FastAPI + uvicorn | 8001 |
| `vulngraph-frontend` | nginx serving built React app | 5173 |

### Useful Docker commands

```bash
# Start in background (detached mode)
docker compose up --build -d

# See live logs
docker compose logs -f

# See logs for one service
docker compose logs -f backend

# Stop everything
docker compose down

# Stop and delete all data (full reset)
docker compose down -v

# Rebuild just one service after code changes
docker compose up --build backend
docker compose up --build frontend
```

### Scanning a project inside Docker

The `demo_project/` folder is pre-mounted into the backend container. In the app's scan box, enter:
```
./demo_project
```

To scan **your own project** from another machine, either:
1. Upload it via the **"Select Project Folder"** button in the UI, or
2. Add a volume mount in `docker-compose.yml`:
```yaml
volumes:
  - /absolute/path/to/your/project:/app/target_project:ro
```
Then scan path: `./target_project`

### Deploying to a server / VM

If the frontend and backend are on different hosts (e.g., backend on `api.example.com`), set the build arg:

```bash
VITE_API_URL=http://api.example.com:8001 docker compose up --build
```

Or in `docker-compose.yml` under `frontend.build.args`:
```yaml
args:
  VITE_API_URL: http://your-server-ip:8001
```

---

### Running the App (Manual — no Docker)



You need **two terminals** running simultaneously:

**Terminal 1 — Backend (Python API)**
```bash
# From the project root
uvicorn main:app --host 127.0.0.1 --port 8001 --reload
```

You should see:
```
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8001
```

**Terminal 2 — Frontend (React)**
```bash
# From the project root
npm run dev
```

You should see:
```
  VITE ready in 500ms
  ➜  Local:   http://localhost:5173/
```

**Open your browser:** http://localhost:5173

---

## Using the App

### Scanning a Project

**Option A — Scan by folder path** (fastest for local projects):
1. Type the path in the second text box: `./demo_project`
2. Click **Scan Project**
3. The 3D graph appears — green nodes are sources, red are sinks

**Option B — Upload a folder** (for sharing or CI):
1. Click **Select Project Folder**
2. Choose a folder from your file system
3. Click **Scan Project**

### Exploring the 3D Graph

| Action | How |
|--------|-----|
| Rotate | Left-click + drag |
| Zoom | Scroll wheel |
| Pan | Right-click + drag |
| Select a node | Left-click it |
| See node details | Check the right panel |

### Asking the AI

Type natural language questions in the search bar:

- *"show me SQL injection paths"*
- *"what are the high risk vulnerabilities?"*
- *"how does user input reach the database?"*
- *"which sinks have no sanitization?"*

The AI responds with an explanation and highlights the relevant path in the graph (red animated edges).

### Reading the Side Panel

When you click a node:

```
🎯 Selected Node
┌─────────────────────────────────────┐
│ [SINK]  ● HIGH                      │
│ cursor.execute(...)                 │
│ File:  demo_project/db.py           │
│ Line:  8                            │
│ Severity: 8/10                      │
│                                     │
│ 🔍 Commit Attribution               │
│ Commit:  a1b2c3d4                   │
│ Author:  Jane Dev                   │
│ Date:    2024-03-15                 │
│ Message: add user search endpoint   │
│                                     │
│ 💥 Blast Radius (3 files):          │
│   db.py                             │
│   app.py                            │
│   tests/test_search.py              │
└─────────────────────────────────────┘
```

### Marking a Node as Patched

Click **"🔧 Mark as Patched"** on any node. It turns grey and is excluded from future attack path calculations. This is useful for tracking remediation progress during a demo.

---

## API Reference

The backend auto-generates interactive docs at: **http://127.0.0.1:8001/docs**

### Key Endpoints

#### `POST /api/cve/scan`
Triggers a full AST scan of a folder.

```bash
curl -X POST http://127.0.0.1:8001/api/cve/scan \
  -H "Content-Type: application/json" \
  -d '{"project_path": "./demo_project"}'
```

Response:
```json
{
  "message": "Scan complete",
  "nodes": 24,
  "edges": 31,
  "sources": 6,
  "sinks": 7,
  "paths_found": 4,
  "git_root": "/home/user/project"
}
```

#### `GET /api/graph`
Returns the full graph (nodes + edges) for the frontend to render.

```bash
curl http://127.0.0.1:8001/api/graph
```

#### `GET /api/attack-paths`
Returns all source→sink paths with risk scores.

```bash
curl http://127.0.0.1:8001/api/attack-paths
```

Response includes:
```json
{
  "paths": [
    {
      "source": "demo_project/app.py:var:query",
      "sink":   "demo_project/db.py:8:sink:cursor.execute(...)",
      "path":   ["...", "...", "..."],
      "score":  7.7,
      "risk":   "HIGH",
      "sanitizers_on_path": []
    }
  ]
}
```

#### `POST /api/query/ask`
Ask a natural language question. Returns structured JSON + AI explanation.

```bash
curl -X POST http://127.0.0.1:8001/api/query/ask \
  -H "Content-Type: application/json" \
  -d '{"query": "show me SQL injection paths"}'
```

Response:
```json
{
  "intent": "show_attack_paths",
  "target_node": "demo_project/db.py:8:sink:cursor.execute(...)",
  "risk_filter": "HIGH",
  "explanation": "SQL injection occurs when user-supplied input is concatenated directly into SQL queries..."
}
```

#### `GET /api/git/blame?project_path=./demo_project`
Returns all sink/source nodes enriched with git blame data.

#### `GET /api/high-risk-paths`
Returns only HIGH-risk paths, sorted by score descending.

---

## Key Concepts Explained

### Taint Analysis
"Taint" means "this data came from a user and could be malicious." VulnGraph marks all user inputs as tainted and tracks that taint as it flows through your code:

```python
# Step 1: Source — data enters from user
query = request.args.get("q")     # ← TAINTED

# Step 2: Propagation — taint spreads
search_term = query.upper()        # ← STILL TAINTED

# Step 3: Sink — tainted data reaches danger
cursor.execute(f"SELECT * FROM users WHERE name = '{search_term}'")
# ↑ VULNERABILITY: tainted data in SQL query = SQL Injection
```

### Risk Score Calculation
```
score = sink_severity - (path_length × 0.3) - (sanitizers_on_path × 2.0)

score ≥ 7.0  → HIGH
score ≥ 4.0  → MEDIUM
score < 4.0  → LOW
```

Sink severities: `eval()`=10, `subprocess`=9, `os.system`=9, `cursor.execute`=8, `open('w')`=6

### Blast Radius
When git blame finds the commit that introduced a vulnerability, it also fetches every file changed in that same commit. This tells you how much code was touched at that moment — useful for understanding the scope of a potential patch.

---

## Configuration

### `backend/.env`
```env
GEMINI_API_KEY=your_key_here
```

### Changing scan behavior
Edit `backend/services/code_security_graph.py`:

```python
# Increase max files scanned (default: 5000)
max_files: int = 5000

# Change max attack path depth (default: 8)
compute_attack_paths(limit=50, max_depth=8)
```

### Adding new sink patterns
In `_is_sink_call()` in `code_security_graph.py`:
```python
# Add your pattern here:
if qn in {"your_dangerous_function"}:
    return True, "your_dangerous_function(...)", 8.0
```

---

## Troubleshooting

### `[Errno 98] Address already in use`
Port 8001 has a zombie process from a previous run:
```bash
fuser -k 8001/tcp
# then restart uvicorn
```

### `Command 'pip' not found`
Use one of these instead:
```bash
uv pip install -r requirements.txt
# or
python3 -m pip install -r requirements.txt
```

### `Failed to resolve import "react-force-graph-3d"`
The 3D packages weren't installed. Run in a terminal tab where `npm run dev` is NOT running:
```bash
npm install react-force-graph-3d three-spritetext
```

### `No module named 'google.generativeai'`
Gemini SDK not installed:
```bash
uv pip install google-generativeai
# or
python3 -m pip install google-generativeai
```

### Graph is empty after scan
1. Check the scan response — does `nodes` > 0?
2. Make sure the path exists: `curl -X POST .../api/cve/scan -d '{"project_path": "./demo_project"}'`
3. Refresh the graph: click anywhere and reload

### AI returns rule-based fallback instead of Gemini
- Check `GEMINI_API_KEY` is set in `.env`
- Verify the key works: https://aistudio.google.com
- The backend logs will show `AI_AVAILABLE = True/False` on startup

---

## Contributing

### Running locally in dev mode

Both servers must be running:
```bash
# Terminal 1
uvicorn main:app --host 127.0.0.1 --port 8001 --reload

# Terminal 2
npm run dev
```

Both support **hot reload** — save a file and changes appear immediately.

### Adding a new API endpoint

1. Create or edit a router in `backend/routers/`
2. Wire it into `main.py`:
   ```python
   from backend.routers.your_router import router as your_router
   app.include_router(your_router)
   ```
3. Add the URL to `src/api.js` so the frontend can call it

### Adding a new vulnerability pattern

Open `backend/services/code_security_graph.py` and find:
- `_is_source_expr()` — to add new input sources
- `_is_sink_call()` — to add new dangerous functions
- `_is_sanitizer_call()` — to add new sanitizer patterns

### Frontend components

| Component | Responsibility |
|-----------|---------------|
| `App.jsx` | Loads graph on startup, wires layout |
| `GraphCanvas.jsx` | 3D rendering only — reads from Zustand store |
| `SidePanel.jsx` | Displays selected node info — reads from Zustand store |
| `QueryBar.jsx` | Handles scan + AI query actions — writes to Zustand store |
| `useStore.js` | Single source of truth: `graph`, `path`, `selectedNode`, `explanation` |

### Code style

- Python: follow PEP 8, use type hints (`def foo(x: str) -> list[str]:`)
- JavaScript: functional components, hooks only, no class components
- CSS: use CSS variables from `:root` in `styles.css`, no inline styles

---

## How the Data Flows (End to End)

```
User clicks "Scan Project"
        │
        ▼
QueryBar.jsx → POST /api/cve/scan
        │
        ▼
scan.py router
        │
        ▼
code_security_graph.py
  ├── Walk .py files
  ├── ast.parse() each file
  ├── _TaintVisitor walks AST nodes
  │     ├── Finds sources → adds green nodes
  │     ├── Propagates taint through assignments
  │     ├── Finds sinks → adds red nodes + edges
  │     └── Finds sanitizers → purple nodes
  └── Builds nx.DiGraph
        │
        ▼
git_history.py (if .git found)
  └── Enriches sink/source nodes with blame data
        │
        ▼
Returns {nodes, edges, sources, sinks, paths_found}
        │
        ▼
App.jsx → GET /api/graph
        │
        ▼
GraphCanvas.jsx → Three.js renders 3D force graph
        │
User clicks a node
        ▼
SidePanel.jsx shows:
  type + risk + file + line + git blame + blast radius
        │
User types "show SQL injection paths"
        ▼
QueryBar.jsx → POST /api/query/ask
        │
        ▼
query.py → Gemini 2.0 Flash → structured JSON
        │
        ▼
GET /api/graph/path?target=<sink_id>
        │
        ▼
GraphCanvas.jsx highlights path in red with particles
```

---

*Built for the FusionX hackathon. Scans code, not excuses.*
