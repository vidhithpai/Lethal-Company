# Detailed Codebase Audit & Architectural Report: VulnGraph

**Project Name**: VulnGraph (Lethal-Company)  
**Date**: August 3, 2026  
**Audit Type**: Complete Codebase Audit, Implementation Analysis, Technical Debt Assessment & Workflow Review  
**Target Scope**: Backend services, Router layers, Parser engines, AI/RAG integrations, Git attribution, and React 3D Frontend.

---

## Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Full Directory & Codebase Mapping](#2-full-directory--codebase-mapping)
3. [System Architecture & Data Workflow](#3-system-architecture--data-workflow)
4. [Component-by-Component Technical Audit](#4-component-by-component-technical-audit)
   - [4.1 Backend Core & API Layer](#41-backend-core--api-layer)
   - [4.2 Security Analysis & Taint Engine](#42-security-analysis--taint-engine)
   - [4.3 Multi-Language Java Parser Engine](#43-multi-language-java-parser-engine)
   - [4.4 Git Attribution & Blast Radius Service](#44-git-attribution--blast-radius-service)
   - [4.5 AI Intelligence Layer & RAG Engine](#45-ai-intelligence-layer--rag-engine)
   - [4.6 Executive Report Generators](#46-executive-report-generators)
   - [4.7 React 3D Frontend](#47-react-3d-frontend)
5. [End-to-End Execution Workflows](#5-end-to-end-execution-workflows)
   - [Workflow A: Project Ingestion & Static Scan](#workflow-a-project-ingestion--static-scan)
   - [Workflow B: Natural Language AI Querying](#workflow-b-natural-language-ai-querying)
   - [Workflow C: Interactive Node Patching & Re-computation](#workflow-c-interactive-node-patching--re-computation)
6. [Audit Findings: Strengths, Weaknesses & Technical Debt](#6-audit-findings-strengths-weaknesses--technical-debt)
7. [Actionable Recommendations & Roadmap](#7-actionable-recommendations--roadmap)
8. [Conclusion](#8-conclusion)

---

## 1. Executive Summary

**VulnGraph** is an interactive, 3D AST-based static application security testing (SAST) and security intelligence platform designed for Python and Java codebases.

Unlike traditional static scanners that output flat text logs or static PDF reports, VulnGraph performs **taint analysis**, maps data-flow corridors from entry points (**Sources**) to dangerous execution functions (**Sinks**), enriches these nodes with **Git commit attribution** (author, date, commit hash, and blast radius), and visualizes the complete threat topology inside a responsive **3D Force-Directed Graph**.

Additionally, VulnGraph features an integrated **Retrieval-Augmented Generation (RAG) AI Assistant** powered by Groq's Llama-3.3 70B (with offline rule-based fallbacks) that allows security teams to query findings in natural language, animate live attack vectors on the graph, and simulate patch impact in real time.

---

## 2. Full Directory & Codebase Mapping

```
Lethal-Company/
├── main.py                         # FastAPI backend entry point & router wiring
├── vuln_analyzer.py                # Standalone CLI AST analyzer script
├── requirements.txt                # Python backend dependencies
├── package.json                    # Frontend Node.js dependencies
├── docker-compose.yml              # Multi-container orchestration (Backend + Nginx)
├── Dockerfile.backend              # Python 3.11 container setup
├── Dockerfile.frontend             # Multi-stage Node build -> Nginx SPA server
├── nginx.conf                      # Nginx static server & fallback configuration
├── vite.config.js                  # Vite bundler configuration
│
├── backend/                        # Main Backend Application Package
│   ├── data/
│   │   └── seed_graph.json         # Seed / mock graph fallback dataset
│   ├── services/
│   │   ├── code_security_graph.py  # ⭐ BRAIN: AST Scanner, Taint Engine & Graph Builder
│   │   ├── git_history.py          # Git blame, commit attribution & blast radius calculator
│   │   ├── java_parser_bridge.py   # JavaParser CLI bridge with Regex fallback
│   │   ├── java_graph_builder.py   # Call graph builder for Java source trees
│   │   └── rag_engine.py          # In-memory document indexing & prompt generator
│   └── routers/
│       ├── security.py             # /api/graph, /api/attack-paths, /api/communities, /api/node/*
│       ├── scan.py                 # /api/cve/scan, /api/cve/scan/upload, /api/cve/scan/realworld
│       ├── query.py                # /api/query/ask, /api/query/explain-node (Groq LLM)
│       ├── report.py               # /api/report/html, /api/report/json generators
│       ├── git_router.py           # /api/git/blame, /api/git/timeline
│       └── graph.py                # /api/graph pathing & mock selection
│
├── src/                            # React 18 Web Frontend
│   ├── main.jsx                    # React app entry point
│   ├── App.jsx                     # Top-level UI layout & upload handlers
│   ├── api.js                      # Centralized API endpoint mapping
│   ├── styles.css                  # Global dark-mode design system styles
│   ├── components/
│   │   ├── GraphCanvas.jsx         # Three.js 3D Force-Directed Graph renderer
│   │   ├── MetricsBar.jsx          # Top telemetry bar, status indicator & export actions
│   │   └── UnifiedPanel.jsx        # Tabbed panel (Node Inspector & RAG AI Chat)
│   └── store/
│       └── useStore.js             # Zustand global state store
│
├── demo_project/                   # Vulnerable Python Test Suite
│   ├── app.py                      # Flask routes exposing SQLi, RCE, Path Traversal, Eval
│   ├── db.py                       # Vulnerable SQL execution vs. Safe Parameterized
│   └── utils.py                    # Vulnerable file read/write & Sanitizers
│
└── sample_project/                 # Secondary Java/Python sample application
    └── src/
        ├── VulnerableController.java
        ├── app.py
        └── vulnerable_app.py
```

---

## 3. System Architecture & Data Workflow

The following architecture diagram details how data flows across the system layers:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           REACT 18 FRONTEND                             │
│  ┌──────────────────┐    ┌────────────────────┐    ┌─────────────────┐  │
│  │ MetricsBar.jsx   │    │  GraphCanvas.jsx   │    │UnifiedPanel.jsx │  │
│  │ (Status/Exports) │    │(Three.js 3D Graph) │    │(Details & Chat) │  │
│  └────────┬─────────┘    └─────────▲──────────┘    └────────┬────────┘  │
└───────────┼────────────────────────┼────────────────────────┼───────────┘
            │                        │                        │
            │ HTTP REST requests     │ Graph JSON             │ Ask Query
            ▼                        │                        ▼
┌────────────────────────────────────┴────────────────────────────────────┐
│                             FASTAPI BACKEND                             │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                            Routers                                │  │
│  │    security.py  │  scan.py  │  query.py  │  report.py  │ git.py   │  │
│  └───────┬─────────────┬────────────┬─────────────┬───────────┬──────┘  │
│          │             │            │             │           │         │
│          ▼             ▼            │             ▼           ▼         │
│  ┌──────────────┐ ┌──────────────┐  │       ┌──────────┐ ┌────────────┐ │
│  │ code_security│ │ java_builder │  │       │  report  │ │git_history │ │
│  │  _graph.py   │ │ _bridge.py   │  │       │generator │ │  .py       │ │
│  └───────┬──────┘ └──────┬───────┘  │       └────┬─────┘ └─────┬──────┘ │
│          │               │          │            │             │        │
│          └───────┬───────┘          │            │             │        │
│                  ▼                  ▼            │             │        │
│          ┌──────────────┐   ┌──────────────┐     │             │        │
│          │  NetworkX    │   │  rag_engine  │     │             │        │
│          │ DiGraph Core │   │   & Prompts  │     │             │        │
│          └──────────────┘   └──────┬───────┘     │             │        │
└────────────────────────────────────┼─────────────┼─────────────┼────────┘
                                     │             │             │
                                     ▼             ▼             ▼
                              ┌────────────┐ ┌──────────┐ ┌────────────┐
                              │ Groq Cloud │ │ Download │ │ Local Git  │
                              │ Llama-3.3  │ │ HTML/JSON│ │ CLI Blame  │
                              └────────────┘ └──────────┘ └────────────┘
```

---

## 4. Component-by-Component Technical Audit

### 4.1 Backend Core & API Layer
* **Files**: `main.py`, `backend/routers/*.py`
* **Implementation**:
  - `main.py` initializes FastAPI, configures CORS for Vite (`localhost:5173`), and mounts six dedicated routers.
  - Endpoint architecture is split into domain-specific modules (`security.py`, `scan.py`, `query.py`, `git_router.py`, `report.py`, `graph.py`).
* **Audit Observations**:
  - Standard REST design with full auto-generated OpenAPI documentation available at `/docs`.
  - Input path validation restricts scans to existing local directories or parent directories.

### 4.2 Security Analysis & Taint Engine
* **File**: `backend/services/code_security_graph.py`
* **Implementation**:
  - Uses Python's native `ast` module and custom `_TaintVisitor(ast.NodeVisitor)` to parse Python source code into AST trees without executing the code.
  - **Sources Identified**: HTTP parameters (`request.args`, `request.form`, `request.json`), env vars (`os.environ`, `os.getenv`), file readers (`read_text`, `open`), CLI args (`sys.argv`).
  - **Sinks Identified**:
    - Code Injection: `eval()`, `exec()` (Severity 10.0)
    - Command Injection: `subprocess.run()`, `os.system()` (Severity 9.0)
    - Insecure Deserialization: `pickle.loads()`, `yaml.load()` (Severity 8.5–9.5)
    - SQL Injection: `cursor.execute()` (Severity 8.0 string / 3.0 parameterized)
    - Path Traversal & Write: `open(..., 'w')`, `rmtree()` (Severity 6.0–7.5)
  - **Sanitizers Identified**: Checks functions containing keywords (`sanitize`, `escape`, `clean`, `validate`, `quote`, `bleach`).
  - **Graph Construction**: Builds a `networkx.DiGraph` where nodes represent functions/variables/calls and edges represent data flows or call dependencies.
* **Security Community Detection**: Clusters nodes into functional zones (`authentication_surface`, `data_input_surface`, `persistence_layer`, `execution_surface`, `sanitization_zone`, `application_logic`).
* **Patch Impact Calculator**: Computes the exact number of eliminated and mitigated attack paths if a specific node is marked as patched.

### 4.3 Multi-Language Java Parser Engine
* **Files**: `backend/services/java_parser_bridge.py`, `backend/services/java_graph_builder.py`
* **Implementation**:
  - `detect_project_language()` checks for `.java` files in the target directory.
  - Executes `javaparser-cli.jar` via Java subprocess if Java runtime is available.
  - If Java runtime is unavailable or parsing fails, falls back gracefully to a robust regex engine (`METHOD_START_RE`, `ANNOTATION_RE`, `SINK_PATTERNS`) to map Spring/Struts/Servlets controllers, sanitizers, and command execution sinks (`Runtime.getRuntime().exec()`, `ProcessBuilder`, `executeQuery`).

### 4.4 Git Attribution & Blast Radius Service
* **Files**: `backend/services/git_history.py`, `backend/routers/git_router.py`
* **Implementation**:
  - `find_git_root()` locates the nearest parent `.git` directory.
  - `git_blame_line()` invokes `git blame -L <line>,<line> --porcelain` to extract exact commit author, date, commit hash, and summary message.
  - `get_commit_diff()` invokes `git show --stat` on the commit hash to extract the **Blast Radius** (all files modified within the same commit).

### 4.5 AI Intelligence Layer & RAG Engine
* **Files**: `backend/services/rag_engine.py`, `backend/routers/query.py`
* **Implementation**:
  - **RAG Pipeline**: Indexes nodes and attack paths into an in-memory document store upon scan completion. Formats context-rich prompts using retrieved findings.
  - **LLM Integration**: Connects to **Groq Cloud API** (`llama-3.3-70b-versatile`) for natural language intent resolution and vulnerability explanation.
  - **Structured Action Output**: Returns response text alongside optional JSON graph actions (`{"action": "highlight_path", "path_index": N}` or `{"action": "select_node", "node_id": "..."}`) which directly manipulate the 3D visualization.
  - **Demo Fallback Bypass**: Intercepts network/quota errors to provide fallback answers during offline demonstrations.

### 4.6 Executive Report Generators
* **File**: `backend/routers/report.py`
* **Implementation**:
  - `/api/report/json`: Generates a structured JSON security audit report containing executive metrics, full vulnerability list, attack paths, remediation rankings, and AI query logs.
  - `/api/report/html`: Generates a self-contained, professional HTML report styled with CSS cards, risk color tags, and an AI executive summary.

### 4.7 React 3D Frontend
* **Files**: `src/App.jsx`, `src/components/GraphCanvas.jsx`, `src/components/UnifiedPanel.jsx`, `src/components/MetricsBar.jsx`, `src/store/useStore.js`
* **Implementation**:
  - Built with **React 18**, **Vite**, **Zustand**, and **react-force-graph-3d** (Three.js).
  - **GraphCanvas.jsx**: Renders nodes as 3D spheres with dynamic risk color coding (Red = Sink, Green = Source, Yellow = Intermediate, Purple = Sanitizer, Blue = Function). Highlighting an attack path triggers glowing red directional particles flowing along data-flow links.
  - **UnifiedPanel.jsx**: Provides a dual-tabbed interface:
    - *Node Info Tab*: Displays node metadata, risk scores, file location, AI vulnerability root cause analysis & fix guidance, commit attribution, blast radius, and patch simulation button.
    - *AI Chat Tab*: Natural language chat interface with Groq RAG assistant.
  - **MetricsBar.jsx**: Real-time stats bar showing Node count, Data Flows, Sources, Sinks, Patched items, live status indicator, and report download buttons.

---

## 5. End-to-End Execution Workflows

### Workflow A: Project Ingestion & Static Scan
```
1. User enters local folder path or uploads a folder via MetricsBar / input.
2. App.jsx calls POST /api/cve/scan (or /scan/upload).
3. scan.py detects language (Python or Java).
4. Taint visitor walks AST, identifies sources, sinks, sanitizers, and constructs NetworkX DiGraph.
5. find_git_root() locates repository root; git_history.py enriches nodes with git blame & blast radius.
6. rag_engine.py indexes findings into memory.
7. Graph JSON is returned to frontend; Zustand store updates; GraphCanvas renders 3D graph.
```

### Workflow B: Natural Language AI Querying
```
1. User types question into AI Chat tab ("show SQL injection paths").
2. UnifiedPanel.jsx posts query to POST /api/query/ask.
3. rag_engine.py retrieves relevant findings using semantic keyword scoring.
4. build_gemini_prompt() constructs a grounded prompt with retrieved findings.
5. Groq Llama-3.3 70B model processes request and returns explanation + action JSON.
6. UI displays assistant message and automatically triggers onHighlightPath(index) on the 3D graph.
```

### Workflow C: Interactive Node Patching & Re-computation
```
1. User selects a sink or intermediate node in the 3D graph.
2. User clicks "Simulate patch — remove from attack paths" in UnifiedPanel.jsx.
3. UnifiedPanel.jsx calls POST /api/graph/patch/{node_id}.
4. security.py calls patch_security_node(), marks node patched, and removes it from NetworkX graph.
5. Attack paths and patch impact metrics are recomputed instantly.
6. Node turns grey in 3D graph, and affected attack paths disappear from the live visualization.
```

---

## 6. Audit Findings: Strengths, Weaknesses & Technical Debt

### Key Strengths
1. **Innovative Security Paradigm**: Combines SAST taint tracking, 3D visualization, Git attribution, and conversational AI into a unified workflow.
2. **Git Commit Attribution**: Connects vulnerability sinks directly to author names, commit dates, commit hashes, and multi-file blast radius.
3. **Resilient Architecture**: Dual-engine fallbacks (JavaParser CLI -> Regex; Groq Cloud -> Rule-based fallback) ensure system stability.
4. **Interactive Remediation Simulation**: Real-time node patching visually demonstrates attack surface reduction.

### Weaknesses & Technical Debt
1. **Intra-file Taint Scope**:
   - Python AST taint visitor tracks variables primarily within single files. Complex multi-module imports across deep package trees require explicit symbol resolution.
2. **Lexical Sanitizer Match**:
   - Sanitizer detection checks function names against keywords (`sanitize`, `escape`). It does not verify AST return-value flow integrity.
3. **Large Graph Pathfinding Optimization**:
   - `nx.all_simple_paths` can experience slowdowns on very dense graphs (>2,000 nodes) without strict depth limits.

---

## 7. Actionable Recommendations & Roadmap

1. **Inter-Module Import Resolution**:
   - Enhance `_TaintVisitor` to parse `Import` and `ImportFrom` statements, maintaining a global symbol table across Python modules.
2. **Vector Database Activation**:
   - Enable the pre-configured ChromaDB + `sentence-transformers` vector storage in `rag_engine.py` for dense semantic retrieval when server resources allow.
3. **Automated Test Suite Expansion**:
   - Implement `pytest` test suites covering AST taint visitor fixtures across standard vulnerability patterns (OWASP Top 10).
4. **Export Format Extensions**:
   - Add PDF report generation using headless rendering or PDFkit alongside existing HTML and JSON report options.

---

## 8. Conclusion

VulnGraph is a state-of-the-art security intelligence tool that successfully bridges the gap between complex static analysis data and human decision-making. By combining AST taint tracking, NetworkX pathfinding, Git time-travel attribution, and Groq-powered AI interaction, VulnGraph provides security teams with an interactive platform for code auditing and vulnerability remediation.

---
*Report generated automatically by Antigravity AI Code Auditor.*
