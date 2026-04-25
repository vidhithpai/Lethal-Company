from __future__ import annotations

import os
import json

import google.generativeai as genai
from fastapi import APIRouter
from pydantic import BaseModel

from backend.services.code_security_graph import compute_high_risk_paths, get_security_graph
from backend.services.rag_engine import retrieve_relevant_context, build_gemini_prompt

router = APIRouter(prefix="/api/query", tags=["query"])

_cache: dict[str, dict] = {}
_node_cache: dict[str, dict] = {}
_graph_summary = {}  # Updated after each scan

try:
    genai.configure(api_key=os.getenv("GEMINI_API_KEY", ""))
    _model = genai.GenerativeModel("gemini-2.0-flash")
    AI_AVAILABLE = True
except Exception:
    AI_AVAILABLE = False
    _model = None


class QueryRequest(BaseModel):
    query: str
    filter_type: str | None = None  # "node" | "attack_path" | None


def update_graph_summary(summary: dict):
    """Call this after every scan to keep summary current."""
    global _graph_summary
    _graph_summary = summary


@router.post("/ask")
def ask_query(req: QueryRequest):
    cache_key = f"{req.query}:{req.filter_type}"
    if cache_key in _cache:
        return _cache[cache_key]

    # RAG retrieval
    try:
        retrieved = retrieve_relevant_context(
            req.query,
            n_results=5,
            filter_type=req.filter_type
        )
    except Exception as e:
        print(f"RAG Retrieval Error: {e}")
        retrieved = []

    fallback = {
        "explanation": "Scan a project first to get specific answers about your codebase.",
        "intent": "general",
        "action": None,
        "retrieved_docs": []
    }

    if not retrieved:
        return fallback

    prompt = build_gemini_prompt(req.query, retrieved, _graph_summary)

    if not AI_AVAILABLE or not _model:
        return {
            "explanation": retrieved[0]["document"] if retrieved else "No findings.",
            "intent": "rag_only",
            "action": None,
            "retrieved_docs": retrieved[:3]
        }

    try:
        response = _model.generate_content(prompt)
        text = response.text.strip()

        # Parse optional action JSON from last line
        action = None
        lines = text.split('\n')
        last_line = lines[-1].strip()
        if last_line.startswith('{') and last_line.endswith('}'):
            try:
                action = json.loads(last_line)
                text = '\n'.join(lines[:-1]).strip()
            except Exception:
                pass

        result = {
            "explanation": text,
            "intent": "rag_grounded",
            "action": action,
            "retrieved_docs": retrieved[:3],
            "context_used": len(retrieved)
        }
        _cache[cache_key] = result
        return result

    except Exception as e:
        return {
            "explanation": f"AI unavailable: {str(e)}. "
                          f"Top finding: {retrieved[0]['document'][:200]}",
            "intent": "fallback",
            "action": None,
            "retrieved_docs": retrieved[:3]
        }


# ─── Prompt: per-node vulnerability analysis ──────────────────────────────────

NODE_EXPLAIN_PROMPT = """You are an expert application security engineer.
You are given data about a specific vulnerability sink node found by static taint analysis.

Your task: produce a concise, accurate security analysis of this specific node.

Node data:
{node_json}

Respond ONLY with valid JSON containing exactly these fields:
- vuln_type: Short name of the vulnerability class (e.g. "SQL Injection", "Command Injection", "Path Traversal", "Code Injection", "Insecure Deserialization", "Arbitrary File Write")
- what_it_does: ONE sentence — what an attacker can achieve by exploiting this sink (be specific and concrete, e.g. "An attacker can execute arbitrary SQL queries, bypassing authentication or exfiltrating the entire database.")
- root_cause: ONE sentence — the technical root cause (e.g. "User-controlled input from request.args flows directly into cursor.execute() via an f-string without parameterization.")
- fix: ONE to TWO sentences — the specific code-level fix (e.g. "Replace cursor.execute(f'...{query}') with cursor.execute('...?', (query,)) to use parameterized queries.")
- cwe: The most applicable CWE ID as a string (e.g. "CWE-89")
- severity_reason: ONE sentence explaining why this is rated HIGH/MEDIUM/LOW based on exploitability and impact.

No markdown. No preamble. No trailing text. Valid JSON only.
"""

_SINK_PROFILES: list[tuple[str, dict]] = [
    ("cursor.execute", {
        "vuln_type": "SQL Injection",
        "what_it_does": "An attacker can manipulate SQL queries to bypass authentication, read arbitrary data, modify records, or drop tables.",
        "root_cause": "User-controlled input is concatenated directly into a SQL string passed to cursor.execute() without parameterization.",
        "fix": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE name = ?', (user_input,)) instead of f-strings or string concatenation.",
        "cwe": "CWE-89",
        "severity_reason": "Rated HIGH because SQL injection is trivially exploitable and gives full database access with no special privileges required.",
    }),
    ("connection.execute", {
        "vuln_type": "SQL Injection",
        "what_it_does": "An attacker can execute arbitrary SQL statements against the database, potentially reading, modifying, or deleting all data.",
        "root_cause": "Unsanitized user input is passed directly into a SQL execution function without using prepared statements.",
        "fix": "Switch to parameterized queries or an ORM. Never build SQL strings using user-controlled values.",
        "cwe": "CWE-89",
        "severity_reason": "Rated HIGH due to wide attack surface and full data compromise potential.",
    }),
    ("subprocess", {
        "vuln_type": "Command Injection",
        "what_it_does": "An attacker can execute arbitrary operating system commands on the server with the application's privileges.",
        "root_cause": "User-supplied input is passed to subprocess.run() or subprocess.Popen() with shell=True, allowing shell metacharacters to inject extra commands.",
        "fix": "Remove shell=True and pass arguments as a list: subprocess.run(['command', safe_arg]). Validate and whitelist allowed values.",
        "cwe": "CWE-78",
        "severity_reason": "Rated CRITICAL — full remote code execution on the server is possible with a single crafted request.",
    }),
    ("os.system", {
        "vuln_type": "Command Injection",
        "what_it_does": "An attacker can run arbitrary shell commands on the host server, potentially gaining full system access.",
        "root_cause": "User input is passed directly to os.system() which invokes a shell, allowing injection of additional commands via semicolons, pipes, or backticks.",
        "fix": "Replace os.system() with subprocess.run([...], shell=False) and validate all inputs against a strict whitelist.",
        "cwe": "CWE-78",
        "severity_reason": "Rated CRITICAL — os.system() always spawns a shell, making metacharacter injection trivially easy.",
    }),
    ("eval", {
        "vuln_type": "Code Injection",
        "what_it_does": "An attacker can execute arbitrary Python code on the server, achieving full remote code execution with no restrictions.",
        "root_cause": "User-controlled input is passed to eval(), which executes it as Python code in the current interpreter context.",
        "fix": "Never pass user input to eval(). Use ast.literal_eval() for safe expression parsing, or redesign to avoid dynamic evaluation entirely.",
        "cwe": "CWE-95",
        "severity_reason": "Rated CRITICAL — eval() is the most dangerous sink in Python; it grants unrestricted code execution.",
    }),
    ("exec", {
        "vuln_type": "Code Injection",
        "what_it_does": "An attacker can execute arbitrary Python statements, read secrets, modify application state, or pivot to other systems.",
        "root_cause": "User-controlled input reaches exec(), which evaluates it as Python code with full access to the runtime environment.",
        "fix": "Remove exec() from production code. Never pass user input to exec(). Use safe alternatives specific to the actual use case.",
        "cwe": "CWE-95",
        "severity_reason": "Rated CRITICAL — exec() provides unrestricted code execution equivalent to direct server access.",
    }),
    ("open", {
        "vuln_type": "Path Traversal",
        "what_it_does": "An attacker can read or write files outside the intended directory, potentially accessing /etc/passwd, private keys, or application secrets.",
        "root_cause": "A user-supplied filename or path is passed to open() without validation or normalization, allowing ../ sequences to escape the intended directory.",
        "fix": "Validate paths using os.path.basename() to strip directory components, or use pathlib.Path.resolve() and check that the result starts with the expected base directory.",
        "cwe": "CWE-22",
        "severity_reason": "Rated HIGH — path traversal can expose sensitive configuration files, credentials, and source code.",
    }),
    ("pickle.load", {
        "vuln_type": "Insecure Deserialization",
        "what_it_does": "An attacker can craft a malicious pickle payload that executes arbitrary Python code when deserialized, achieving full remote code execution.",
        "root_cause": "pickle.loads() is called on untrusted user-supplied data. Pickle deserialization executes __reduce__ methods which can run arbitrary code.",
        "fix": "Never deserialize pickle data from untrusted sources. Use JSON or another safe format. If pickle is required, verify data integrity with HMAC before deserializing.",
        "cwe": "CWE-502",
        "severity_reason": "Rated CRITICAL — pickle deserialization of attacker-controlled data is always a remote code execution vulnerability.",
    }),
    ("yaml.load", {
        "vuln_type": "Insecure Deserialization",
        "what_it_does": "An attacker can inject YAML that executes arbitrary Python code via PyYAML's !!python/object constructor tags.",
        "root_cause": "yaml.load() is called without specifying Loader=yaml.SafeLoader, enabling execution of Python object constructors embedded in YAML.",
        "fix": "Replace yaml.load(data) with yaml.safe_load(data), which disables arbitrary object construction.",
        "cwe": "CWE-502",
        "severity_reason": "Rated HIGH — unsafe YAML loading allows remote code execution via specially crafted input.",
    }),
    ("shutil.rmtree", {
        "vuln_type": "Arbitrary File Deletion",
        "what_it_does": "An attacker can delete arbitrary directories on the server, potentially removing the application, logs, or operating system files.",
        "root_cause": "User-controlled input is used as the path argument to shutil.rmtree() without validation, allowing path traversal to target any directory.",
        "fix": "Validate and normalize the path before deletion. Ensure it resolves within an allowed base directory using pathlib.Path.resolve().",
        "cwe": "CWE-73",
        "severity_reason": "Rated HIGH — arbitrary directory deletion can cause data loss, service disruption, or system compromise.",
    }),
]

def _rule_based_node_analysis(node: dict) -> dict:
    """Match a sink node to a known vulnerability profile."""
    label = (node.get("label") or "").lower()
    node_type = node.get("type", "")

    for pattern, profile in _SINK_PROFILES:
        if pattern in label:
            return {
                **profile,
                "severity_reason": profile["severity_reason"],
            }

    # Generic source analysis
    if node_type == "source":
        return {
            "vuln_type": "Untrusted Input Source",
            "what_it_does": "This node reads data from an external, attacker-controlled source. If this data reaches a sink without sanitization, it enables injection attacks.",
            "root_cause": f"The expression '{node.get('label', '')}' reads user-supplied input that is not yet validated.",
            "fix": "Validate, sanitize, or whitelist all values read from this source before using them in sensitive operations.",
            "cwe": "CWE-20",
            "severity_reason": "Risk depends on which sinks this data can reach. Follow attack paths to assess impact.",
        }

    return {
        "vuln_type": "Security-Sensitive Operation",
        "what_it_does": "This node performs an operation that may be dangerous if it receives attacker-controlled input.",
        "root_cause": "Taint analysis detected this node on a path from a user-controlled source.",
        "fix": "Validate all inputs reaching this operation and ensure sanitizers are present on every path.",
        "cwe": "CWE-20",
        "severity_reason": "Review the full attack path to determine exploitability.",
    }


class NodeExplainRequest(BaseModel):
    node_id: str | None = None
    label: str | None = None
    node_type: str | None = None
    severity: float | None = None
    risk: str | None = None
    file: str | None = None
    line: int | None = None


@router.post("/explain-node")
def explain_node(req: NodeExplainRequest):
    """
    Given a specific sink/source node, return structured vulnerability analysis.
    """
    node_dict = req.model_dump(exclude_none=True)
    cache_key = f"node:{req.node_id or req.label}"

    if cache_key in _node_cache:
        return _node_cache[cache_key]

    if AI_AVAILABLE and _model:
        try:
            node_json = json.dumps(node_dict, indent=2)
            prompt = NODE_EXPLAIN_PROMPT.format(node_json=node_json)
            response = _model.generate_content(prompt)
            text = response.text.strip()
            text = text.replace("```json", "").replace("```", "").strip()
            result = json.loads(text)
            _node_cache[cache_key] = result
            return result
        except Exception:
            pass  # Fall through to rule-based

    result = _rule_based_node_analysis(node_dict)
    _node_cache[cache_key] = result
    return result
