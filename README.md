# VulnGraph — Temporal Differential Reachability Analysis (TDRA)

> **Commit-level security regression detection for Java and Python codebases.**  
> TDRA answers the question no existing SAST tool can: *which specific commit made the system more exploitable, and by exactly how much?*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)]()
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-green.svg)]()
[![Node.js 18+](https://img.shields.io/badge/Node.js-18+-green.svg)]()
[![VS Code Extension](https://img.shields.io/badge/VS%20Code-Extension-blue.svg)]()

---

## Table of Contents

1. [What is VulnGraph?](#what-is-vulngraph)
2. [How it differs from existing tools](#how-it-differs-from-existing-tools)
3. [System Architecture](#system-architecture)
4. [Repository Structure](#repository-structure)
5. [Core Concepts](#core-concepts)
6. [Quick Start](#quick-start)
7. [VS Code Extension](#vs-code-extension)
8. [API Reference](#api-reference)
9. [Research Background](#research-background)

---

## What is VulnGraph?

VulnGraph is a **commit-level security regression detector**. It is not just a snapshot vulnerability scanner. It doesn't only tell you what is vulnerable in your codebase right now — it tells you which specific commit changed your security posture, how much the attack surface expanded, and exactly which new execution paths from user-controlled input to sensitive operations were introduced.

**The tool answers one key question per commit:**
> *"Does this change create a new path from user input → sensitive operation that didn't exist before? And did it weaken the guards protecting existing paths?"*

This is quantified as a **Risk Factor (RF ∈ [0,1])** per commit, computed using a deterministic, mathematically grounded formula validated against CVE-linked benchmark repositories.

---

## How it differs from existing tools

| Capability | SonarQube | CodeQL | Semgrep | CodeRabbit | VulnGraph TDRA |
|---|---|---|---|---|---|
| **Unit of analysis** | Codebase snapshot | Codebase snapshot | File/pattern | PR diff (text) | **Commit transition** |
| **Version-aware comparison** | ✗ | ✗ | ✗ | Partial | **✓ Core contribution** |
| **Guard weakening detection** | ✗ | ✗ | ✗ | ✗ | **✓ Novel** |
| **Commit-level RF score** | ✗ | ✗ | ✗ | ✗ | **✓ Deterministic** |
| **Cross-file Spring MVC paths** | ✗ | ✓ (requires QL) | ✗ | ✗ | **✓ Automatic** |
| **CWE-typed attenuation model** | ✗ | Partial | ✗ | ✗ | **✓ Product formula** |
| **Deterministic output** | ✓ | ✓ | ✓ | ✗ (LLM) | **✓** |
| **Local-only / no data upload** | Paid | GitHub hosted | Cloud option | Cloud | **✓ Always local** |

**One-sentence differentiation:**  
*Dependency scanners cover what you imported. SAST tools cover what is wrong now. VulnGraph covers what your last commit broke structurally.*

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     CLIENT LAYER                                 │
│                                                                  │
│  ┌───────────────────┐  ┌──────────────────┐  ┌─────────────┐  │
│  │  Web UI           │  │  VS Code         │  │  Docker     │  │
│  │  React + Three.js │  │  Extension       │  │  Compose    │  │
│  │  3D force graph   │  │  Node.js v0.2.0  │  │  (optional) │  │
│  └────────┬──────────┘  └────────┬─────────┘  └──────┬──────┘  │
└───────────┼──────────────────────┼──────────────────── ┼────────┘
            │                      │                      │
            └──────────────────────┼──────────────────────┘
                                   │ localhost only
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│                 API GATEWAY — FastAPI (port 8001 / 8002)         │
│                                                                  │
│   /api/cve/scan    /api/graph    /api/tdra/*    /api/report/html │
│   /api/query/ask   /api/git/*    /api/tdra/validate              │
└─────────────────────────────────────────────────────────────────┘
                                   │
            ┌──────────────────────┼──────────────────────┐
            ▼                      ▼                       ▼
┌───────────────────┐  ┌───────────────────┐  ┌──────────────────┐
│  ANALYSIS ENGINE  │  │  TDRA DIFFERENTIAL│  │  AI / RAG        │
│                   │  │  ENGINE           │  │                  │
│  • Python AST     │  │  • git diff scope │  │  • Groq Llama-3  │
│  • Java bridge    │  │  • G(V_prev/curr) │  │  • Local Fallback│
│  • Symbol table   │  │  • RF formula     │  │  • Context RAG   │
│  • Cross-file     │  │  • Attenuation    │  │  • Rule fallback │
│  • NetworkX graph │  │  • Mann-Whitney U │  │                  │
└───────────────────┘  └───────────────────┘  └──────────────────┘
            │                      │
            └──────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                     DATA LAYER (in-memory)                       │
│                                                                  │
│    NetworkX DiGraph    RAG index    TDRA result cache (5 min TTL)│
└─────────────────────────────────────────────────────────────────┘
```

### TDRA Pipeline (5 stages)

```
Git repo
   │
   ▼
Stage 1 ─── PyDriller commit iteration
             Extract (V_prev, V_curr) pairs
             git diff --name-only → changed files only
   │
   ▼
Stage 2 ─── Program graph construction (per version)
             Java: JavaParser + global symbol table → cross-file edges
             Python: ast.NodeVisitor → _TaintVisitor
             Nodes: ENTRY · SINK · GUARD · NORMAL
             NetworkX DiGraph G = (N, E)
   │
   ▼
Stage 3 ─── Constrained reachability analysis
             all_simple_paths(G, ENTRY, SINK, cutoff=15)
             Per path: residual_risk = ∏(1 - Aᵢ) for all GUARD nodes
             Aᵢ = attenuation score from CWE-typed table
   │
   ▼
Stage 4 ─── Differential analysis
             ΔPaths = R(V_curr) \ R(V_prev)       ← new attack paths
             ΔGuard = Σ[S_prev(p) - S_curr(p)]⁺  ← guard weakening
             RF = 0.6·(ΔPaths/|P_before|) + 0.4·(ΔGuard/A_total)
             RF ∈ [0,1], clamped
   │
   ▼
Stage 5 ─── Statistical validation + reporting
             Mann-Whitney U (VCC vs non-VCC RF scores)
             Cliff's delta (effect size)
             JSON + HTML report with TDRA section
```

---

## Repository Structure

```
TDRA/                              ← project root
│
├── backend/
│   ├── main.py                    ← FastAPI app, router registrations
│   ├── requirements.txt           ← Python deps (javalang, scipy, gitpython...)
│   │
│   ├── routers/
│   │   ├── scan.py                ← POST /api/cve/scan (triggers analysis)
│   │   ├── security.py            ← GET /api/graph, /api/attack-paths
│   │   ├── tdra.py                ← GET /api/tdra/timeline, /analyze, /validate
│   │   ├── git_router.py          ← GET /api/git/blame, /timeline
│   │   ├── query.py               ← POST /api/query/ask (AI + RAG)
│   │   ├── report.py              ← GET /api/report/html
│   │   └── graph.py               ← GET /api/graph path endpoints
│   │
│   └── services/
│       ├── code_security_graph.py ← ⭐ Python AST engine + NetworkX graph
│       ├── java_parser_bridge.py  ← Java source parser (regex + javalang)
│       ├── java_graph_builder.py  ← Java graph + symbol table + cross-file edges
│       ├── differential_engine.py ← ⭐ TDRA core: git diff, V_prev/curr, RF
│       ├── guard_attenuation.py   ← ⭐ Product attenuation model, CWE table
│       ├── cdg_guard_detector.py  ← CDG guard detector
│       ├── reaching_def.py        ← Reaching definitions analysis
│       ├── depth_budget.py        ← Search depth budget manager
│       ├── graph_manifest.py      ← Graph persistence & serialization
│       ├── statistical_validator.py ← Mann-Whitney U, Cliff's delta
│       ├── mock_tdra_data.py      ← Demo fallback when no .git repo
│       ├── git_history.py         ← git blame, blast radius, commit attribution
│       ├── rag_engine.py          ← In-memory RAG for AI queries
│       ├── tdra_context_builder.py← TDRA prompt context builder
│       └── tdra_rag_documents.py  ← TDRA RAG document indexing
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx                ← Root component, repo path input
│   │   ├── config.js              ← Environment API base configuration
│   │   ├── services/api.js        ← All endpoint URLs
│   │   ├── store/useStore.js      ← Zustand state (graph, diffMode, timeline)
│   │   │
│   │   └── components/
│   │       ├── canvas/
│   │       │   ├── GraphCanvas.jsx← ⭐ 3D Three.js force graph + diff mode
│   │       │   ├── SchematicView.jsx ← 2D Schematic Architecture diagram
│   │       │   └── ViewToggle.jsx  ← Toggle 3D Force Graph / 2D Schematic View
│   │       ├── panel/
│   │       │   ├── CommitTimeline.jsx ← RF bars, severity bands, diff trigger
│   │       │   ├── ExplorerPanel.jsx  ← Node & file tree explorer
│   │       │   └── UnifiedPanel.jsx   ← Node details + AI chat
│   │       └── metrics/
│   │           └── MetricsBar.jsx    ← Top stats bar + scan controls
│   │
│   └── package.json
│
├── vscode-extension/
│   ├── extension.js               ← ⭐ Extension engine: decorations, webview,
│   │                                   pre-commit check, report export
│   ├── package.json               ← Commands, settings, activation events
│   ├── vulngraph-0.2.0.vsix       ← Packaged VSIX extension (install directly)
│   └── README.md                  ← Extension-specific docs
│
├── tools/                         ← Standalone analysis scripts
│   ├── vuln_analyzer.py
│   └── debug_mapping.py
│
├── docs/                          ← Architecture & project audit documentation
│   ├── architecture.md
│   └── PROJECT_AUDIT.md
│
├── sample_project/                ← Vulnerable Java/Polyglot sample app
├── demo_project/                  ← Vulnerable Python Flask demo app
├── scripts/                       ← Utility scripts
│   └── start_extension_backend.sh ← Start backend on port 8002 for IDE extension
├── docker-compose.yml             ← Monorepo Docker orchestration
├── requirements.txt               ← Root-level Python dependencies
└── README.md
```

---

## Core Concepts

### Node Taxonomy

Every method in the analyzed codebase is classified into one of four types:

| Type | Color | Examples | Security role |
|---|---|---|---|
| `ENTRY` | 🟢 Green | `@RequestMapping`, `@PostMapping`, `main()`, `readLine()` | Source of untrusted input. Every attack path starts here. |
| `SINK` | 🔴 Red | `stmt.execute()`, `Runtime.exec()`, `Files.write()`, `eval()` | Dangerous operation. Attack path ends here. |
| `GUARD` | 🟣 Purple | `@Valid`, `@NotNull`, `validate*()`, `sanitize*()` | Validation barrier. Reduces taint reaching SINK. |
| `NORMAL` | ⚪ Gray | All other methods | Intermediate nodes in path traversal. |

### Guard Attenuation Model

Guards are not binary (present/absent). Each guard node has an **attenuation score Aᵢ ∈ [0,1]** based on:
- **Annotation / Function type**: `@Valid` on a SQL sink → A = 0.90. `checkInput()` name match → A = 0.35.
- **CWE sink category**: Same annotation, different strength depending on whether sink is SQL (CWE-89), command injection (CWE-78), path traversal (CWE-22), or XSS (CWE-79).

**Residual risk of a path:**
$$R(p) = \prod_{i} (1 - A_i) \quad \text{for all GUARD nodes on path } p$$

- $R(p) = 1.0 \rightarrow$ fully unguarded (maximum risk)
- $R(p) \rightarrow 0 \rightarrow$ fully attenuated (taint blocked)

### Risk Factor Formula

$$RF(c) = \alpha \cdot \frac{\Delta\text{Paths}}{\max(|P_{\text{before}}|, 1)} + \beta \cdot \frac{\Delta A_{\text{total}}}{\max(A_{\text{prev\_total}}, 0.01)}$$

where:
- $\alpha = 0.6$ (path expansion weight)
- $\beta = 0.4$ (guard regression weight)
- $\Delta\text{Paths} = |R(V_{\text{curr}}) \setminus R(V_{\text{prev}})|$ (new attack paths)
- $\Delta A_{\text{total}} = \sum [S_{\text{prev}}(p) - S_{\text{curr}}(p)]^+$ (guard strength lost)
- $RF \in [0, 1]$ after clamping

**Severity bands:**

| RF range | Severity | CI/CD action |
|---|---|---|
| 0.00 – 0.20 | Low | Pass |
| 0.21 – 0.45 | Medium | Flag for review |
| 0.46 – 0.70 | High | Block — require approval |
| 0.71 – 1.00 | Critical | Reject — redesign required |

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Git

### 1. Install Python dependencies

```bash
# Option A: using uv (recommended)
uv pip install -r requirements.txt

# Option B: using python3 -m pip
python3 -m pip install -r requirements.txt
```

### 2. Install Node dependencies

```bash
npm install
```

### 3. Set API key (optional — falls back to offline LLM assistant or rule-based)

```bash
cp .env.example .env
# Edit .env: GROQ_API_KEY=your_key_here
```

### 4. Run the web application

Run backend and frontend simultaneously:

**Terminal 1 — Backend API**
```bash
python3 -m uvicorn backend.main:app --host 127.0.0.1 --port 8001 --reload
```

**Terminal 2 — React Frontend**
```bash
npm run dev
```

* **Web UI:** http://localhost:5173  
* **API docs:** http://localhost:8001/docs

### 5. Scan a project

In the web UI, enter a project path and click **Scan Project**.  
For the built-in demo: enter `./demo_project`

---

## 🐳 Running with Docker

Docker handles Python, Node, nginx, and all dependencies automatically in a containerized setup.

```bash
# Copy environment file
cp .env.example .env

# Build and start services
docker compose up --build
```

Access the app at `http://localhost:5173`.

---

## VS Code Extension

The repository contains a fully functional VS Code Extension located in [vscode-extension/](file:///home/vaibhav-sharma/Projects/final_year_project/project-code/TDRA/vscode-extension).

### Key Features

| Feature | Description |
|---|---|
| **Inline decorations** | Green `ENTRY` · Red `SINK` · Purple `GUARD` on every relevant code line on save |
| **Critical SINK** | Bright red highlight when residual risk > 0.7 |
| **New path alert** | Orange decoration when a line is part of an attack path introduced by the latest commit |
| **Hover tooltips** | CWE classification · residual risk · effective guard strength · git blame attribution |
| **3-Tab Risk dashboard** | Webview containing: Commit timeline · Sink inventory · Statistical validation |
| **Pre-commit check** | RF score notification in Source Control (SCM) panel before committing |
| **Report export** | Download full HTML security report with TDRA differential section |
| **3D Web UI Bridge** | Open the 3D interactive force graph visualization in browser |

### Installation

```bash
# Install pre-built VSIX package directly
code --install-extension vscode-extension/vulngraph-0.2.0.vsix
```

### Start Extension Backend

```bash
# Starts backend on port 8002 for the IDE extension
./scripts/start_extension_backend.sh
```

---

## API Reference

### Core Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/cve/scan` | Trigger full AST analysis of a project path |
| `GET` | `/api/graph` | Full program graph (nodes + edges + attack paths) |
| `GET` | `/api/attack-paths` | Entry-to-sink paths with residual risk and CWE |
| `GET` | `/api/tdra/timeline` | Commit history with RF scores (mock if no .git) |
| `POST` | `/api/tdra/analyze` | Analyze all commits, sorted by RF descending |
| `GET` | `/api/tdra/commit/{hash}` | Single commit differential analysis |
| `GET` | `/api/tdra/risk-summary` | Aggregated risk metrics across commits |
| `POST` | `/api/tdra/validate` | Mann-Whitney U + Cliff's delta statistical validation |
| `GET` | `/api/git/blame` | Enrich nodes with commit blame attribution |
| `GET` | `/api/git/timeline` | Raw git commit history |
| `GET` | `/api/report/html` | Full HTML security report with TDRA section |
| `POST` | `/api/query/ask` | AI explanation of findings (Groq/local/rule fallback) |

### Example: Run TDRA Validation

```bash
curl -X POST http://localhost:8001/api/tdra/validate \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "./sample_project/dvja",
    "known_vcc_hashes": ["abc1234", "def5678"],
    "limit": 100
  }'
```

---

## Research Background

VulnGraph implements the **Temporal Differential Reachability Analysis (TDRA)** framework, designed for commit-level security regression detection across evolving Python and Java codebases.

**Core Research Questions Addressed:**
- **RQ1:** Does RF statistically separate vulnerability-contributing commits (VCCs) from benign commits? (Mann-Whitney U, p < 0.05)
- **RQ2:** Does TDRA detect commit-level regressions that static snapshot SAST tools cannot?
- **RQ3:** Does git diff-scoped analysis reduce per-commit analysis time vs full repository rebuilds?

---

## License

MIT License. See `LICENSE` for details.

---

*VulnGraph is a major security analysis project. All analysis runs 100% locally — no code leaves your machine.*
