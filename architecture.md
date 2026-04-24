# VulnGraph Architecture

VulnGraph's architecture is designed around a clear pipeline: **Extract → Analyze → Enrich → Visualize & Query**. 

Below is the detailed architectural diagram illustrating the components and data flow, followed by an explanation of the core elements.

## System Architecture Diagram

```mermaid
graph TD
    %% Define Styles
    classDef frontend fill:#1e293b,stroke:#3b82f6,stroke-width:2px,color:#f8fafc;
    classDef api fill:#0f172a,stroke:#8b5cf6,stroke-width:2px,color:#f8fafc;
    classDef engine fill:#0f172a,stroke:#ef4444,stroke-width:2px,color:#f8fafc;
    classDef external fill:#1e293b,stroke:#22c55e,stroke-width:2px,color:#f8fafc;
    classDef storage fill:#334155,stroke:#f59e0b,stroke-width:2px,color:#f8fafc;

    %% Client Layer
    subgraph Client ["Frontend (React + Vite + Three.js)"]
        UI["React User Interface"]
        3DGraph["3D Force-Directed Graph<br/>react-force-graph-3d"]
        SidePanel["Interactive Side Panel<br/>Metrics & Vuln Details"]
        Store["Zustand State Store<br/>Live Path Animation"]
        
        UI <--> Store
        Store --> 3DGraph
        Store --> SidePanel
    end
    class UI,3DGraph,SidePanel,Store frontend;

    %% API Layer
    subgraph API ["FastAPI Backend Layer"]
        RouterScan["/api/cve/scan"]
        RouterQuery["/api/query/ask"]
        RouterSecurity["/api/graph & attack-paths"]
        RouterGit["/api/git/blame"]
        
        RouterScan --> ASTEngine
        RouterSecurity <--> GraphEngine
        RouterGit --> GitService
        RouterQuery --> GeminiIntents
    end
    class RouterScan,RouterQuery,RouterSecurity,RouterGit api;

    %% Core Engine Layer
    subgraph CoreEngine ["Vulnerability Analysis Engine"]
        ASTEngine["AST Parser & Taint Analysis<br/>Python ast module"]
        GraphEngine["NetworkX Graph Engine<br/>Dijkstra & Pathfinding"]
        GitService["Git History Analyzer<br/>Subprocess git blame"]
        
        ASTEngine -->|"Generates Nodes & Edges"| GraphEngine
        GitService -->|"Injects Attribution"| ASTEngine
    end
    class ASTEngine,GraphEngine,GitService engine;

    %% AI Layer
    subgraph AILayer ["AI Intelligence Layer"]
        GeminiIntents["Intent & Query Resolution"]
        GeminiVuln["Vulnerability Explainer<br/>/api/query/explain-node"]
        RuleFallback["Rule-Based Fallback Engine"]
        
        GeminiIntents -->|"Natural Language -> Intents"| GraphEngine
        GeminiVuln -->|"Generates Patch & Impact"| SidePanel
        GeminiIntents -.->|"Fails/Rate Limit"| RuleFallback
        GeminiVuln -.->|"Fails/Rate Limit"| RuleFallback
    end
    class GeminiIntents,GeminiVuln,RuleFallback api;

    %% External Systems
    subgraph External ["External Interfaces"]
        TargetRepo[("Target Python Codebase")]
        GeminiAPI(("Google Gemini 2.0 Flash"))
        LocalGit(("Local Git CLI"))
    end
    class TargetRepo,GeminiAPI,LocalGit external;

    %% Storage
    Cache[("In-Memory Graph Cache")]
    class Cache storage;

    %% Data Flow Connections
    TargetRepo -->|"Source Code"| ASTEngine
    LocalGit -->|"Blame & Diff Data"| GitService
    GeminiIntents <-->|"Prompt & Response"| GeminiAPI
    GeminiVuln <-->|"Prompt & Response"| GeminiAPI
    
    UI -->|"1. Upload/Select Repo"| RouterScan
    UI -->|"2. Ask Question"| RouterQuery
    UI -->|"3. Click Node/Patch"| RouterSecurity
    
    GraphEngine <--> Cache
    
    %% Output to UI
    GraphEngine -->|"Graph Data (Nodes/Links)"| Store
    RuleFallback --> Store
```

---

## Core Elements Explained

### 1. The Target Codebase (Input)
VulnGraph acts directly on Python source code (either via a local folder path or uploaded `.zip`). It does **not** execute the code (SAST approach), ensuring complete safety when analyzing malicious or highly vulnerable applications.

### 2. AST Parser & Taint Analysis (`backend/services/code_security_graph.py`)
This is the workhorse of the application. 
- It uses Python's native `ast` module to build an Abstract Syntax Tree of the entire project.
- It employs a **Visitor Pattern** (`_TaintVisitor`) to walk the tree, hunting for:
  - **Sources**: Untrusted inputs (e.g., `request.args`, `flask.request.form`).
  - **Sinks**: Dangerous execution points (e.g., `cursor.execute()`, `subprocess.run()`, `eval()`).
  - **Sanitizers**: Defensive functions (e.g., `escape()`, `validate()`).
- It maps the flow of variables from sources to sinks to generate data-flow edges.

### 3. Graph Engine (`backend/services/graph_engine.py`)
- Powered by **NetworkX**, this engine takes the nodes and edges from the AST parser and builds a Directed Graph (`DiGraph`).
- It executes pathfinding algorithms (like Dijkstra's) to find the shortest, most dangerous routes from a source to a sink.
- It calculates dynamic risk scores based on path length and the presence of sanitizers.
- **The "Patch" Mechanism:** When a user clicks "Mark as Patched", the engine removes the node/edges from the NetworkX graph and recalculates the attack surface instantly.

### 4. Git History Analyzer (`backend/services/git_history.py`)
- Maps the vulnerability back to the human who introduced it.
- Uses `subprocess` to execute `git blame --porcelain` on the exact file and line number of a detected source or sink.
- Calculates the **Blast Radius** by running `git show --stat` to see how many other files were modified in that exact same commit.

### 5. AI Intelligence Layer (`backend/routers/query.py`)
- Integrated with **Google Gemini 2.0 Flash**.
- **Intent Resolution (`/ask`)**: Translates plain English queries ("show me SQL injection paths") into actionable graph traversal commands (e.g., `{"intent": "show_attack_paths", "risk_filter": "HIGH"}`).
- **Vulnerability Explanation (`/explain-node`)**: Analyzes specific sink nodes to generate structured security reports: Impact, Root Cause, Fix, and CWE mappings.
- **Resiliency**: If the Gemini API hits a rate limit or lacks a key, a robust **Rule-Based Fallback Engine** seamlessly takes over using regex and keyword mapping so the demo never breaks.

### 6. Frontend Presentation Layer (`src/components/`)
- Built on **React** and **Vite**.
- **`GraphCanvas.jsx`**: Uses `react-force-graph-3d` and `Three.js` to render the NetworkX graph in a 3D space. Nodes are color-coded (Red = Sink, Green = Source), and active attack paths emit glowing, directional particles.
- **`QueryBar.jsx`**: The command center. It dispatches AI queries, triggers full-project scans, and manages the multi-path `setInterval` animation cycle.
- **`SidePanel.jsx`**: The "War Room". It displays the exact file/line, the Gemini AI vulnerability analysis, the Git Time-Travel attribution, and the real-time "Patch" controls. 
- **`MetricsBar.jsx`**: Uses `zustand` to monitor the live state of the graph, showing the total attack surface and shifting risk posture as nodes are dynamically patched.
