# VulnGraph — Temporal Differential Reachability Analysis

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

VulnGraph is a **commit-level security regression detector**. It is not a vulnerability scanner. It does not tell you what is vulnerable in your codebase right now — it tells you which commit changed the security posture, how much the attack surface expanded, and exactly which new execution paths from user-controlled input to sensitive operations were opened.

**The tool answers one question per commit:**
> Does this change create a new path from user input → sensitive operation that didn't exist before? And did it weaken the guards protecting existing paths?

This is quantified as a **Risk Factor (RF ∈ [0,1])** per commit, computed using a deterministic, mathematically grounded formula validated against CVE-linked benchmark repositories.

---

## How it differs from existing tools

| Capability | SonarQube | CodeQL | Semgrep | CodeRabbit | VulnGraph TDRA |
|---|---|---|---|---|---|
| Unit of analysis | Codebase snapshot | Codebase snapshot | File/pattern | PR diff (text) | **Commit transition** |
| Version-aware comparison | ✗ | ✗ | ✗ | Partial | **✓ Core contribution** |
| Guard weakening detection | ✗ | ✗ | ✗ | ✗ | **✓ Novel** |
| Commit-level RF score | ✗ | ✗ | ✗ | ✗ | **✓ Deterministic** |
| Cross-file Spring MVC paths | ✗ | ✓ (requires QL) | ✗ | ✗ | **✓ Automatic** |
| CWE-typed attenuation model | ✗ | Partial | ✗ | ✗ | **✓ Product formula** |
| Deterministic output | ✓ | ✓ | ✓ | ✗ (LLM) | **✓** |
| Local-only / no data upload | Paid | GitHub hosted | Cloud option | Cloud | **✓ Always local** |

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
│                 API GATEWAY — FastAPI (port 8001/8002)           │
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
│  • Java bridge    │  │  • G(V_prev/curr) │  │  • Local LLM     │
│  • Symbol table   │  │  • RF formula     │  │  • CodeBERT      │
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
Lethal-Company/                    ← project root
│
├── backend/
│   ├── main.py                    ← FastAPI app, all router registrations
│   ├── requirements.txt           ← Python deps (javalang, scipy, gitpython...)
│   │
│   ├── routers/
│   │   ├── scan.py                ← POST /api/cve/scan (triggers analysis)
│   │   ├── security.py            ← GET /api/graph, /api/attack-paths
│   │   ├── tdra.py                ← GET /api/tdra/timeline, /analyze, /validate
│   │   ├── git_router.py          ← GET /api/git/blame, /timeline
│   │   ├── query.py               ← POST /api/query/ask (AI + RAG)
│   │   ├── report.py              ← GET /api/report/html
│   │   └── validation.py          ← POST /api/validation/run
│   │
│   └── services/
│       ├── code_security_graph.py ← ⭐ Python AST engine + NetworkX graph
│       ├── java_parser_bridge.py  ← Java source parser (regex + javalang)
│       ├── java_graph_builder.py  ← Java graph + symbol table + cross-file edges
│       ├── differential_engine.py ← ⭐ TDRA core: git diff, V_prev/curr, RF
│       ├── guard_attenuation.py   ← ⭐ Product attenuation model, CWE table
│       ├── statistical_validator.py ← Mann-Whitney U, Cliff's delta
│       ├── mock_tdra_data.py      ← Demo fallback when no .git repo
│       ├── git_history.py         ← git blame, blast radius, commit attribution
│       ├── rag_engine.py          ← In-memory RAG for AI queries
│       └── local_llm.py           ← Local LLM inference (Phi-3 / CodeBERT)
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx                ← Root component, repo path input
│   │   ├── api.js                 ← All endpoint URLs
│   │   ├── store/useStore.js      ← Zustand state (graph, diffMode, timeline)
│   │   │
│   │   └── components/
│   │       ├── canvas/
│   │       │   └── GraphCanvas.jsx ← ⭐ 3D Three.js force graph + diff mode
│   │       ├── panel/
│   │       │   ├── CommitTimeline.jsx ← RF bars, severity bands, diff trigger
│   │       │   └── UnifiedPanel.jsx   ← Node details + AI chat
│   │       └── metrics/
│   │           └── MetricsBar.jsx    ← Top stats bar + scan controls
│   │
│   └── package.json
│
├── vscode-extension/
│   ├── extension.js               ← ⭐ Full extension: decorations, dashboard,
│   │                                   pre-commit check, report export
│   ├── package.json               ← Commands, settings, activation events
│   ├── vulngraph-0.2.0.vsix       ← Packaged extension (install directly)
│   └── README.md                  ← Extension-specific docs
│
├── sample_project/
│   └── dvja/                      ← Damn Vulnerable Java Application
│       └── src/main/java/         ← Spring MVC controllers + repos (test target)
│
├── demo_project/                  ← Intentionally vulnerable Python Flask app
│   ├── app.py                     ← 4 built-in vulnerabilities
│   ├── db.py                      ← SQL injection (vulnerable + safe side by side)
│   └── utils.py                   ← Path traversal + sanitizer
│
├── models/
│   └── DOWNLOAD_MODEL.md          ← Instructions for local LLM (Phi-3 / TinyLlama)
│
├── scripts/
│   ├── run_demo.sh                ← One-command demo launcher
│   └── start_extension_backend.sh ← Start backend on port 8002 for IDE extension
│
├── paper/
│   ├── tdra_paper.tex             ← IEEE LaTeX source (IEEEtran format)
│   └── tdra_paper.pdf             ← Compiled 5-page conference paper draft
│
├── docker-compose.yml             ← Backend + frontend containers
├── requirements.txt               ← Root-level Python deps
└── package.json                   ← Frontend Node deps
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
- **Annotation type**: `@Valid` on a SQL sink → A = 0.90. `checkInput()` name match → A = 0.35.
- **CWE sink category**: Same annotation, different strength depending on whether sink is SQL (CWE-89), command injection (CWE-78), path traversal (CWE-22), or XSS (CWE-79).

**Residual risk of a path:**
```
R(p) = ∏ (1 - Aᵢ)  for all GUARD nodes on path p
```
- `R(p) = 1.0` → fully unguarded (maximum risk)
- `R(p) → 0` → fully attenuated (taint blocked)

### Risk Factor Formula

```
RF(c) = α · (ΔPaths / max(|P_before|, 1))
      + β · (ΔA_total / max(A_prev_total, 0.01))

where:
  α = 0.6  (path expansion weight)
  β = 0.4  (guard regression weight)
  ΔPaths = |R(V_curr) \ R(V_prev)|  (new attack paths)
  ΔA_total = Σ [S_prev(p) - S_curr(p)]⁺  (guard strength lost)
  RF ∈ [0, 1]  after clamping
```

**Severity bands:**

| RF range | Severity | CI/CD action |
|---|---|---|
| 0.00 – 0.20 | Low | Pass |
| 0.21 – 0.45 | Medium | Flag for review |
| 0.46 – 0.70 | High | Block — require approval |
| 0.71 – 1.00 | Critical | Reject — redesign required |

### Git Diff-Scoped Analysis

Instead of rebuilding the full repo graph per commit (O(repo)):

```bash
# 1. Find what changed
git diff --name-only --diff-filter=AM parent_hash commit_hash

# 2. Extract those files at each version
git show parent_hash:path/to/File.java > /tmp/prev/File.java
git show commit_hash:path/to/File.java  > /tmp/curr/File.java

# 3. Build partial graphs only for changed files
# Complexity: O(diff) not O(repo)
```

### Cross-File Symbol Resolution

Spring MVC attack paths span multiple files:
```
ApiController.java (@PostMapping)
    → UserService.java (business logic)
        → UserRepository.java (JPA: .executeQuery())
```

VulnGraph builds a global symbol table across all `.java` files before edge construction, enabling inter-file call resolution via field type inference:

```java
// In ApiController.java:
private UserService userService;  // → type inference: UserService
userService.createUser(input);    // → resolves to UserService.createUser node
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Git

### 1. Install backend dependencies

```bash
cd backend
pip install -r ../requirements.txt
```

### 2. Install frontend dependencies

```bash
npm install
```

### 3. Set API key (optional — falls back to local LLM or rule-based)

```bash
cp .env.example .env
# Edit .env: GROQ_API_KEY=your_key_here
```

### 4. Run the demo

```bash
chmod +x scripts/run_demo.sh
./scripts/run_demo.sh
```

**Web UI:** http://localhost:5173  
**API docs:** http://localhost:8001/docs

### 5. Scan a project

In the web UI, enter a project path and click **Scan Project**.  
For the built-in demo: enter `./demo_project`

### Docker (recommended for sharing)

```bash
docker compose up --build
```

---

## VS Code Extension

### What it does

The extension brings the full TDRA analysis into the editor without the 3D graph. All analysis runs **locally** — no code leaves your machine.

| Feature | Description |
|---|---|
| Inline decorations | Green ENTRY · Red SINK · Purple GUARD on every relevant line |
| Critical SINK | Bright red highlight when residual_risk > 0.7 |
| New path alert | Orange decoration when a line is part of a path introduced by the latest commit |
| Hover tooltips | CWE classification · residual risk · effective guard strength · git blame |
| Risk dashboard | 3-tab webview: commit timeline · sink analysis · statistical validation |
| Pre-commit check | RF score notification in Source Control panel before committing |
| Report export | Download full HTML security report with TDRA differential section |
| "Open 3D view" | Navigate to web UI for the full force graph visualization |

### Install

```bash
# From packaged .vsix
code --install-extension vscode-extension/vulngraph-0.2.0.vsix

# Or build from source
cd vscode-extension
npx vsce package --no-dependencies
code --install-extension vulngraph-0.2.0.vsix
```

### Start the backend for the extension

```bash
# The extension defaults to port 8002 to avoid clashing with the web app
chmod +x scripts/start_extension_backend.sh
./scripts/start_extension_backend.sh
```

### Extension settings

| Setting | Default | Description |
|---|---|---|
| `vulngraph.backendUrl` | `http://localhost:8002` | Backend URL. Change if running remotely. |
| `vulngraph.autoAnalyzeOnSave` | `true` | Re-analyze on every file save (800ms debounce). |
| `vulngraph.showGuardDecorations` | `true` | Show GUARD (purple) decorations on sanitizer methods. |

### Extension architecture

```
VS Code IDE
    │ onDidSaveTextDocument (800ms debounce)
    ▼
extension.js (Node.js process)
    │
    ├── analyzeProject()
    │       ├── POST /api/cve/scan → scan + graph (blocking, fast)
    │       └── GET /api/tdra/timeline → TDRA RF data (non-blocking)
    │
    ├── applyDecorations()
    │       └── Map graph nodes to editor line ranges
    │           ENTRY / SINK / GUARD / CRITICAL / NEW PATH
    │
    └── refreshRiskPanel() [if dashboard open]
            └── Re-render 3-tab HTML webview
                Tab 1: Commit timeline + RF bars
                Tab 2: Sink residual risk table
                Tab 3: Statistical validation UI

All HTTP calls → localhost only. No code leaves the machine.
```

---

## API Reference

### Core endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/cve/scan` | Trigger full AST analysis of a project path |
| `GET` | `/api/graph` | Full program graph (nodes + edges + attack paths) |
| `GET` | `/api/attack-paths` | Entry-to-sink paths with residual risk and CWE |
| `GET` | `/api/tdra/timeline` | Commit history with RF scores (mock if no .git) |
| `POST` | `/api/tdra/analyze` | Analyze all commits, sorted by RF descending |
| `GET` | `/api/tdra/commit/{hash}` | Single commit differential analysis |
| `GET` | `/api/tdra/risk-summary` | Aggregate: critical commits, avg RF, totals |
| `POST` | `/api/tdra/validate` | Mann-Whitney U + Cliff's delta on VCC hashes |
| `GET` | `/api/git/blame` | Enrich nodes with commit attribution |
| `GET` | `/api/git/timeline` | Raw git commit history |
| `GET` | `/api/report/html` | Full HTML security report with TDRA section |
| `POST` | `/api/query/ask` | AI explanation of findings (Groq/local/rule fallback) |

### Example: run TDRA validation

```bash
curl -X POST http://localhost:8001/api/tdra/validate \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "./sample_project/dvja",
    "known_vcc_hashes": ["abc1234", "def5678"],
    "limit": 100
  }'
```

Response:
```json
{
  "mann_whitney_u": 847.0,
  "p_value": 0.003421,
  "cliffs_delta": 0.512,
  "effect_size": "large",
  "statistically_significant": true,
  "verdict": "TDRA VALIDATED",
  "vcc_mean": 0.681,
  "non_vcc_mean": 0.234,
  "interpretation": "RF scores DO significantly separate VCC from non-VCC commits (p < 0.05, δ=0.512, large effect)."
}
```

---

## Research Background

VulnGraph implements the **Temporal Differential Reachability Analysis (TDRA)** framework, described in the accompanying conference paper:

> **TDRA: Temporal Differential Reachability Analysis for Detecting Change-Induced Security Risk in Evolving Java Codebases**  
> *[Authors] — MITE Moodabidri, Karnataka, India*  
> Target venues: IEEE SANER 2027, IEEE COMPSAC 2027, ACM MSR 2027

**Key references:**

- Sözer, H. (2024). *Call Graph Delta Analysis and Security Vulnerability Assessment with Static Analysis.* IEEE COMPSAC. ← Closest prior work
- Li, Z. et al. (2024). *IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities.* arXiv:2405.17238.
- Zhong, Z. et al. (2023). *Scalable Compositional Static Taint Analysis for Industrial Micro-Services.* IEEE ICSE-SEIP.
- Zhang, J. et al. (2023). *Vulnerability Detection by Learning From Syntax-Based Execution Paths.* IEEE TSE.
- Wu, Y. et al. (2024). *Understanding and Improving Change Risk Detection in Practice.* IEEE SANER.
- Rajbhandari, Y. et al. (2025). *Attack Surface Score for Software Systems.* Future Internet.

**Research questions the tool is validated against:**

- **RQ1:** Does RF statistically separate vulnerability-contributing commits from benign commits? (Mann-Whitney U, p < 0.05)
- **RQ2:** Does TDRA detect commit-level regressions that snapshot SAST tools cannot?
- **RQ3:** Does git diff-scoped analysis reduce per-commit time vs full repo rebuild?

---

## License

MIT License. See `LICENSE` for details.

---

*VulnGraph is a final-year major project at MITE Moodabidri. All analysis runs locally — no code is uploaded to any server.*
