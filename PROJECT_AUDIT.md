# Project Audit & Security Assessment Report: VulnGraph

This report provides a comprehensive, evidence-based assessment of the VulnGraph repository structure, security analysis engine, API layers, frontend, and overall codebase.

---

## 1. Project Architecture Summary

### What the Project Does
VulnGraph is an interactive, 3D AST-based security analysis tool that maps data flows from source to sink in a Python codebase. It aims to visualize potential vulnerability paths, allow simulating patches, and utilize AI for context-grounded queries about the security of the scanned codebase.

### Target Users
* Security researchers and engineers performing code reviews.
* AppSec professionals seeking visual representations of data flows.
* Software developers trying to understand threat propagation.

### Main Workflow
1. **Ingest/Scan**: User points the application to a local folder or uploads code files.
2. **Analysis**: The backend parses the Python AST to build a graph of function calls and variable-level data flows (taint propagation).
3. **Visualization**: A 3D force-directed graph is rendered in the frontend, highlighting vulnerable paths from inputs (sources) to dangerous execution points (sinks).
4. **Remediation & AI Chat**: Users can interactively ask questions (utilizing RAG) or simulate patches that visually break the flow of taint on the graph.

### Technology Stack
* **Frontend**: React (Vite), Zustand for state management, `react-force-graph-3d` for rendering.
* **Backend**: FastAPI, NetworkX for graph algorithms.
* **Security Engine**: Custom Python AST parsing (`ast.NodeVisitor`) for taint propagation.
* **AI/RAG**: Groq (`llama-3.3-70b-versatile`) with a custom in-memory semantic retrieval engine (collapsible to semantic sentence-transformers).
* **Git integration**: Subprocess invocation of `git blame` and `git show`.

---

## 2. Feature Discovery

Below is the grouping of discovered features based on source code inspections:

* **Static Taint Propagation**: Inter/intra-procedural tracking of variable assignments (`backend/services/code_security_graph.py`).
* **Source & Sink Detection**: Pre-defined rules matching inputs/dangerous functions (`backend/services/code_security_graph.py`).
* **Community Detection**: Community clustering based on node characteristics (`detect_security_communities`).
* **AI Querying & RAG**: RAG-enhanced explanations and interactive chat with graph execution controls (`backend/routers/query.py`).
* **Git Blame & Blast Radius**: Commit attribution and blast-radius tracking (`backend/services/git_history.py`).
* **Patch Simulation**: Graph mutation upon simulated patch action (`patch_security_node`).

---

## 3. Implementation Audit

### Feature: Static Taint Analysis
* **Purpose**: Track user-controlled inputs through variable assignments to sinks.
* **Files Involved**:
  * [code_security_graph.py](file:///home/vaibhav-sharma/Projects/final_year_project/project-code/TDRA/backend/services/code_security_graph.py)
* **Implementation Status**: MOSTLY COMPLETE
* **Evidence**: `_TaintVisitor` (lines 320-528) overrides `visit_Assign`, `visit_AnnAssign`, and `visit_Call` to populate the `tainted` set with identifiers and draw dataflow edges.
* **Missing Pieces**: Inter-file imports, dynamic attributes, tracking references through lists/dicts, control-flow awareness (loops, conditional branching).
* **Risk Level**: MEDIUM

### Feature: AI RAG Query
* **Purpose**: Allow users to query findings using natural language with source attribution.
* **Files Involved**:
  * [query.py](file:///home/vaibhav-sharma/Projects/final_year_project/project-code/TDRA/backend/routers/query.py)
  * [rag_engine.py](file:///home/vaibhav-sharma/Projects/final_year_project/project-code/TDRA/backend/services/rag_engine.py)
* **Implementation Status**: MOSTLY COMPLETE (Note: Gemini implementation is fully commented out; Groq/Llama-3.3 is the active implementation).
* **Evidence**: `ask_query` endpoint (lines 53-157) queries `retrieve_relevant_context` and passes results to Groq. Includes a demo fallback bypass if Groq/API fails.
* **Missing Pieces**: Real semantic embedding (ChromaDB + SentenceTransformers is commented out, leaving basic term-frequency matching active).
* **Risk Level**: LOW

### Feature: Git Blame Attribution & Blast Radius
* **Purpose**: Trace introduced vulnerabilities back to commits and identify blast radius (changed files).
* **Files Involved**:
  * [git_router.py](file:///home/vaibhav-sharma/Projects/final_year_project/project-code/TDRA/backend/routers/git_router.py)
  * [git_history.py](file:///home/vaibhav-sharma/Projects/final_year_project/project-code/TDRA/backend/services/git_history.py)
* **Implementation Status**: COMPLETE (with Demo Mock Bypass)
* **Evidence**: Functions `git_blame_line` and `get_commit_diff` make direct subprocess calls to `git`. If `.git` directory is missing, the code falls back gracefully to randomized mock authors ("Jane Dev", etc.) to prevent frontend crashes.
* **Missing Pieces**: None.
* **Risk Level**: LOW

### Feature: Mock Graph Activation
* **Purpose**: Allow switching to a predefined/mock dataset.
* **Files Involved**:
  * [graph.py](file:///home/vaibhav-sharma/Projects/final_year_project/project-code/TDRA/backend/routers/graph.py)
  * [graph_engine.py](file:///home/vaibhav-sharma/Projects/final_year_project/project-code/TDRA/backend/services/graph_engine.py)
  * [api.js](file:///home/vaibhav-sharma/Projects/final_year_project/project-code/TDRA/src/api.js)
* **Implementation Status**: BROKEN / NOT IMPLEMENTED
* **Evidence**: The frontend references `endpoints.useMock` (POST to `/api/graph/use-mock`). However, `/api/graph/use-mock` is declared in `backend/routers/graph.py` which is **never imported or registered** in `main.py`. As a result, clicking "Use Mock Data" in the UI causes a 404 error.
* **Missing Pieces**: Needs `app.include_router(graph_router)` in `main.py`.
* **Risk Level**: HIGH

---

## 4. End-to-End Flow Validation

* **Scan Project Flow**: **Working**. The user can trigger a scan of a directory or upload files. The backend runs the AST traversal, indexes documents into the in-memory RAG, and returns a JSON payload containing the built graph and statistics.
* **AI Query Flow**: **Working (with Mock Fallback)**. If the Groq API key is missing or calls fail, it falls back to pre-coded answers (e.g. "Here is the highest risk code injection...").
* **Graph Visualization Flow**: **Working**. React frontend uses `react-force-graph-3d` to display the nodes. Patched nodes are dynamically updated.
* **Attack Path Highlighting**: **Working**. Clicking "▶ Animate" in `UnifiedPanel` triggers the animation of red particles flowing along the path.
* **Git Analysis Flow**: **Working (with Mock Fallback)**. Correctly attributes commits when running in a git repo, and provides mock developers when run outside a repository.

---

## 5. API Audit

| Endpoint | Implemented | Functional | Used by Frontend | Notes |
| -------- | ----------- | ---------- | ---------------- | ----- |
| `/api/graph` (GET) | Yes (`security.py`) | Yes | Yes (`App.jsx`) | Retrieves node & edge list |
| `/api/graph/path` (GET) | Yes (`security.py`) | Yes | Yes (`useStore.js`) | Retrieves path list |
| `/api/graph/patch/{node_id}` | Yes (`security.py`) | Yes | Yes (`UnifiedPanel.jsx` / `App.jsx`) | Marks a node patched |
| `/api/query/ask` (POST) | Yes (`query.py`) | Yes | Yes (`UnifiedPanel.jsx`) | AI Query endpoint |
| `/api/query/explain-node` | Yes (`query.py`) | Yes | Yes (`UnifiedPanel.jsx`) | Explains a single node |
| `/api/cve/scan` (POST) | Yes (`scan.py`) | Yes | No | Endpoint exists but UI uses scan/upload |
| `/api/cve/scan/upload` (POST) | Yes (`scan.py`) | Yes | Yes (`App.jsx`) | Form upload scanning |
| `/api/git/blame` (GET) | Yes (`git_router.py`) | Yes | Yes (`SidePanel.jsx` / `UnifiedPanel.jsx`) | Commit attribution |
| `/api/git/timeline` (GET) | Yes (`git_router.py`) | Yes | No | Unused by frontend |
| `/api/graph/use-mock` (POST) | Yes (`graph.py`) | **No** | Yes (`QueryBar.jsx`) | Dead/404 because `graph.py` router is not imported in `main.py` |

---

## 6. Frontend Audit (React Components)

| Component | Status | Purpose | Issues |
| --------- | ------ | ------- | ------ |
| `App.jsx` | COMPLETE | Shell and coordination | None |
| `GraphCanvas.jsx` | COMPLETE | 3D Force-Directed visualizer | None |
| `MetricsBar.jsx` | COMPLETE | Top statistics bar & controls | None |
| `UnifiedPanel.jsx` | COMPLETE | Unified tabbed panel (Node details + Chat) | None |
| `EntryPage.jsx` | **UNUSED** | Landing screen for folder ingest | Leftover code, never rendered |
| `Landing.jsx` | **UNUSED** | Entry / landing interface | Leftover code, never rendered |
| `NodePanel.jsx` | **UNUSED** | Individual node viewer | Replaced by `UnifiedPanel` |
| `QueryBar.jsx` | **UNUSED** | Top bar for typing AI queries | Replaced by `UnifiedPanel` chat / `MetricsBar` |
| `Sidebar.jsx` | **UNUSED** | Left side actions list | Replaced by new layout |
| `SidePanel.jsx` | **UNUSED** | Older individual node details pane | Replaced by `UnifiedPanel` |

---

## 7. Backend Audit

* **Duplicate Graph Engines**: `GraphEngine` (`graph_engine.py`) and `get_security_graph` (`code_security_graph.py`) both build and hold separate graph states. `GraphEngine` operates on `seed_graph.json` files, whereas `code_security_graph` manages dynamically scanned AST paths. This causes state fragmentation.
* **Unregistered Routers**: As noted in the API audit, `backend/routers/graph.py` is unregistered, breaking `/api/graph/use-mock` and the mock graph loading path.
* **Security Concerns**: The server accepts absolute paths in `/api/cve/scan`. This could potentially allow scanning of restricted filesystem locations if the backend is exposed.

---

## 8. Security Engine Audit

* **Supported Vulnerability Classes**:
  * SQL Injection (`CWE-89`) via `.execute`
  * Command Injection (`CWE-78`) via `subprocess` or `os.system`
  * Code Injection (`CWE-95`) via `eval` or `exec`
  * Path Traversal (`CWE-22`) via `open`
  * Insecure Deserialization (`CWE-502`) via `pickle` or `yaml`
  * Arbitrary File Deletion / Write (`CWE-73`) via `shutil` or `open('w')`
* **Limitations**: High false negative rate due to lexical variable matching and lack of intra/inter-file import tracking.
* **Sanitizer Handling**: Relies entirely on checking if function/variable names contain substring patterns (e.g. `clean`, `safe`, `escape`). It does not verify if sanitizers are logically applied.

---

## 9. AI Integration Audit

* **Groq Integration**: Active (Gemini code is commented out).
* **Grounding**: RAG prompt template successfully binds retrieved node details.
* **Fallback Behavior**: Excellent fallback mock structures in place if the Groq server is unreachable.

---

## 10. Technical Debt & Fix Recommendations

### Critical: Unregistered Routers & Broken Mock Mode
* **Impact**: Clicking "Use Mock Data" fails with a 404, confusing users.
* **Fix**: Import and register the `graph.py` router inside `main.py`.
* **Effort**: 5 minutes.

### High: Duplicate Graph Engines
* **Impact**: Large memory overhead, confusing codebase, and fragmented state (REST updates the AST graph but mock modes interact with file-based graphs).
* **Fix**: Unify `GraphEngine` and `code_security_graph.py` to share the same NetworkX data structure.
* **Effort**: 2 hours.

---

## 11. Final Scorecard

| Area                 | Score /10 | Notes |
| -------------------- | --------- | ----- |
| Architecture         | 8/10      | Great 3D visual paradigm and integration concept. |
| Backend              | 7/10      | Unregistered router and duplicate graph engines. |
| Frontend             | 7/10      | High volume of dead/unused legacy files. |
| Security Analysis    | 6/10      | Basic AST visitor, lacks inter-file tracking. |
| Visualization        | 9/10      | High quality interactive 3D particle path animations. |
| AI Integration       | 8/10      | RAG grounding is good; Gemini implementation is commented out. |
| Maintainability      | 6/10      | State files and dead code need cleanup. |
| Production Readiness | 5/10      | Arbitrary path traversal scan risks; mock components left in build. |

---

## 12. How to Run the Project

### Prerequisites
* Python 3.10+
* Node.js 18+

### Setup and Start Backend
1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Install requirements:
   ```bash
   pip install -r ../requirements.txt
   ```
3. Set your environment variables in `.env` (optional for mock fallbacks, but recommended for full AI features):
   ```env
   GROQ_API_KEY=your_api_key_here
   ```
4. Start the FastAPI server on port 8001:
   ```bash
   uvicorn main:app --host 127.0.0.1 --port 8001 --reload
   ```

### Setup and Start Frontend
1. Navigate back to the project root:
   ```bash
   cd ..
   ```
2. Install frontend dependencies:
   ```bash
   npm install
   ```
3. Start the Vite development server:
   ```bash
   npm run dev
   ```
4. Access the web interface at `http://localhost:5173`.
