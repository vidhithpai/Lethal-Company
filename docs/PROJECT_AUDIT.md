# Project Audit & Technical Architecture Report: VulnGraph

This report provides an accurate, evidence-based assessment of the VulnGraph architecture, endpoints, services, frontend components, extension integrations, and security guardrails based directly on the current codebase.

---

## 1. Project Summary

### System Purpose
VulnGraph is a hybrid Differential Static Application Security Testing (SAST) and Taint-Directed Risk Assessment (TDRA) system. It maps data flows from source inputs to execution sinks across Python and Java codebases, calculates differential risk factor (RF) changes across git commit histories, provides interactive 3D visualizations, and enables evidence-grounded AI security explanations.

### Primary Capabilities
1. **Multi-Language AST Taint Analysis**: Inter- and intra-procedural tracking of user-controlled inputs, sanitization guards, and execution sinks for Python (`ast`) and Java (JavaParser bridge + regex heuristics).
2. **TDRA Differential Engine**: Evaluates consecutive git commit pairs to detect new attack paths, weakened security guards, and compute commit Risk Factors (RF).
3. **Interactive 3D Graph & Diff Visualization**: 3D force-directed representation (`react-force-graph-3d`) with distinct styling for Entry (green), Sink (red), Guard (purple), and Normal (blue) nodes, plus commit diff halos and ring indicators.
4. **Structured Diff & Security Annotations**: Line-by-line diff rendering with additions, deletions, context, and security markers (guard removal, new attack path nodes).
5. **Evidence-Grounded AI Forensic Assistant**: RAG pipeline powered by Groq (`llama-3.3-70b-versatile`) and ChromaDB vector store, restricted to explaining proven graph evidence without speculative hallucination.
6. **Path Guard Perimeter Security**: Multi-tier filesystem path restrictions ensuring callers cannot access unauthorized directories via traversal, symlinks, or arbitrary paths.

---

## 2. API Endpoints Catalog

All endpoints are registered on FastAPI (`backend/main.py`):

| Router Prefix | Method | Endpoint | Description |
|---|---|---|---|
| (Root) | GET | `/api/health` | Service health check |
| (Root) | GET | `/` | API metadata and root discovery |
| (Security) | GET | `/api/graph` | Returns nodes, dataflow edges, communities, and attack paths |
| (Security) | GET | `/api/attack-paths` | Discovers all source-to-sink paths with risk classification |
| (Security) | GET | `/api/high-risk-paths` | Returns top attack paths sorted by residual risk |
| (Security) | POST | `/api/graph/patch/{node_id}` | Simulates patch mitigation by disabling taint propagation |
| (Security) | GET | `/api/attack-surface` | Returns all detected input sources |
| (Security) | GET | `/api/communities` | Returns Louvain community clusters |
| (Security) | GET | `/api/node/context` | Detailed node metrics, upstream inputs, downstream sinks, and behavior analysis |
| (Security) | GET | `/api/node/patch-impact` | Calculates eliminated attack paths if node is patched |
| (Security) | GET | `/api/path` | Returns shortest path between specific source and sink |
| (Security) | GET | `/api/debug/edges` | Debug inspection of graph edges |
| (Security) | GET | `/api/file/source` | Secure source viewer (protected by `is_safe_file_path`) |
| `/api/query` | GET | `/api/query/rag-status` | RAG embedding mode and AI model availability status |
| `/api/query` | POST | `/api/query/ask` | Evidence-grounded conversational AI query |
| `/api/query` | POST | `/api/query/explain-node` | Explains security role of single node with real CWE mapping |
| `/api/cve` | POST | `/api/cve/scan` | Scans local filesystem directory (registers scanned root) |
| `/api/cve` | GET | `/api/cve/scan/status` | Polling endpoint for scan progress and node counts |
| `/api/cve` | POST | `/api/cve/scan/upload` | Upload zip/files for scanning (registers temporary root) |
| `/api/cve` | POST | `/api/cve/scan/realworld` | Scans directory with community and patch impact metrics |
| `/api/git` | GET | `/api/git/blame` | Resolves git repository root for project |
| `/api/git` | GET | `/api/git/timeline` | Returns git commit history list |
| `/api/git` | GET | `/api/git/commit-diff` | Structured file diff with TDRA security line markers |
| `/api/report` | GET | `/api/report/json` | Downloads machine-readable JSON forensic audit report |
| `/api/report` | GET | `/api/report/html` | Downloads standalone human-readable HTML audit report |
| `/api/graph` | GET | `/api/graph` | Graph node/edge export |
| `/api/graph` | GET | `/api/graph/path` | Attack path extraction |
| `/api/graph` | POST | `/api/graph/use-mock` | Activates built-in demo/mock dataset |
| `/api/graph` | GET | `/api/graph/node/context` | Context alias for node intelligence |
| `/api/tdra` | POST | `/api/tdra/analyze` | Evaluates commit pairs and returns differential RF metrics |
| `/api/tdra` | POST | `/api/tdra/validate` | Statistical validation (Mann-Whitney U, Cliff's delta) |
| `/api/tdra` | GET | `/api/tdra/risk-summary` | Aggregated risk metrics across commit history |
| `/api/tdra` | GET | `/api/tdra/commit/{hash}/path-contributions` | Option 1 per-path RF contribution breakdown |
| `/api/tdra` | GET | `/api/tdra/commit/{hash}` | Single commit differential security analysis |
| `/api/tdra` | GET | `/api/tdra/timeline` | Full TDRA commit timeline with source metadata |
| `/api/tdra` | GET | `/api/tdra/commit-graph-diff` | Per-node/edge diff status for 3D visualization |

---

## 3. Backend Services Architecture

* `backend/services/path_guard.py`: Centralized security boundary enforcing path containment against traversal, symlink attacks, and unauthorized access.
* `backend/services/code_security_graph.py`: AST parser for Python; tracks sources, sanitizers, sinks, data flows, and simulates patches.
* `backend/services/differential_engine.py`: Git commit pair analysis; builds AST graphs for commit and parent to detect delta attack corridors.
* `backend/services/git_history.py`: Git blame attribution, file revision extraction, and safe candidate path resolution.
* `backend/services/java_graph_builder.py`: Java project parser and graph builder.
* `backend/services/java_parser_bridge.py`: Bridge to optional JavaParser CLI fat JAR.
* `backend/services/rag_engine.py`: ChromaDB vector index with GraphCodeBERT / TF-IDF retrieval.
* `backend/services/statistical_validator.py`: Statistical validation of vulnerability-contributing commits.
* `backend/services/tdra_context_builder.py`: Grounds Groq LLM prompts directly in TDRA evidence.

---

## 4. Frontend Components Architecture

* `frontend/src/components/canvas/GraphCanvas.jsx`: 3D Force-Directed Graph canvas with customizable camera zoom, particle animations, and commit diff mode.
* `frontend/src/components/panel/UnifiedPanel.jsx`: Tabbed side-panel with Node Intelligence, real CWE mapping, Forensic AI chat, and patch simulation.
* `frontend/src/components/panel/CommitTimeline.jsx`: Commit risk timeline displaying live/demo status, RF badges, and diff triggers.
* `frontend/src/components/panel/DiffViewer.jsx`: Side-by-side / unified code diff viewer with syntax highlighting and TDRA security flags.
* `frontend/src/components/panel/ExplorerPanel.jsx`: File tree explorer and in-editor source code viewer.
* `frontend/src/components/panel/ExportModal.jsx`: Modal for exporting audit reports.
* `frontend/src/components/metrics/MetricsBar.jsx`: Top navigation metrics bar summarizing scan statistics and risk posture.
* `frontend/src/store/useStore.js`: Zustand reactive state management across all canvas, panel, and timeline components.

---

## 5. VS Code Extension Architecture

Located in `vscode-extension/`:
* Extension ID: `vulngraph-assistant`
* Status Bar: Real-time scan status, sink count, RF score, and `[demo]` indicator when running on demo data.
* Webview Panels: Call Graph SVG, Waterfall SVG, and Matrix View of commit risks.
* Auto-Scanning: Listens on workspace file save events to perform incremental scans.

---

## 6. Verification & Test Metrics

* Backend Test Suite (`backend/tests/test_path_guard.py`): **11 passed tests**.
* Frontend Production Build (`npm run build`): **Passes cleanly (0 errors)**.
