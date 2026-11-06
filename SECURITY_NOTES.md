# VulnGraph Security Notes & Privacy Architecture

This document describes the security model, network data flow, file system perimeter controls, and secret management policies implemented in VulnGraph.

---

## 1. Data Flow & External Network Egress

VulnGraph operates primarily as an on-premise, localized static application security testing (SAST) and taint-dependency risk analysis engine.

### What Leaves the Machine
- **CWE Identifiers & Dependency Metadata**: When vulnerability intelligence enrichment is enabled, only public identifiers (such as CWE IDs, package coordinates, and version numbers) are transmitted to external services (such as MITRE, NIST NVD, or OSV.dev).
- **LLM Context (Optional)**: If `GROQ_API_KEY` is provided, user queries and summarized node forensic metadata (node ID, label, CWE classification, attack surface summary) are sent over TLS to Groq's inference API for real-time natural language explanation.

### What NEVER Leaves the Machine
- **Source Code**: Raw source code, AST dumps, file paths outside user-specified summaries, and repository contents remain entirely on the local host.
- **Git Commit Histories**: Commit diffs, commit hashes, author emails, and patch hunks are parsed and analyzed purely in-memory on the local backend and are never sent to external intelligence feeds or cloud services.
- **Taint Graphs & Embeddings**: Graphs constructed by NetworkX and vector representations stored in local ChromaDB instances (`chroma_db/`) never egress the host environment.

---

## 2. File System Perimeter & Path Guard (`backend/services/path_guard.py`)

To prevent arbitrary filesystem reading, path traversal attacks, and symlink escape vulnerabilities:

1. **Strict Canonicalization**: All path parameters (`repo_path`, `project_path`, `file_path`) are resolved using `Path.resolve()`, stripping `..` sequences and resolving symlinks.
2. **Scanned Roots Allow-List**: Endpoints reject paths that do not fall under one of the allowed boundaries:
   - A previously scanned project root explicitly registered via `/api/scan`.
   - The current working directory (CWD) of the backend process.
   - Any directory path specified in the `VULNGRAPH_ALLOWED_ROOTS` environment variable (delimited by the OS path separator).
   - Git repository root containment: If a subfolder of a repository was scanned (e.g., in VS Code workspace workflows), the enclosing Git parent repository containing `.git` is authorized.
3. **HTTP 403 Forbidden**: Any path attempting to escape these authorized roots is blocked immediately with HTTP 403.
4. **HTTP 404 Not Found**: Non-existent paths within authorized roots return HTTP 404 rather than leaking directory existence outside the perimeter.

---

## 3. Secret Management & Credential Safety

- **Zero Hard-Coded Secrets**: No API keys, tokens, or private credentials exist within the codebase or repository commits.
- **Environment Isolation**: Sensitive configuration values (such as `GROQ_API_KEY`, `NVD_API_KEY`, and custom `VULNGRAPH_ALLOWED_ROOTS`) are loaded exclusively from system environment variables or local `.env` files.
- **Git Ignore Protection**: All `.env`, `backend/.env`, and `frontend/.env.local` files are registered in `.gitignore` to prevent accidental credential staging and check-in.

