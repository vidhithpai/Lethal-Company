from __future__ import annotations

import os
import json

import google.generativeai as genai
from fastapi import APIRouter
from pydantic import BaseModel

from backend.services.code_security_graph import compute_high_risk_paths, get_security_graph

router = APIRouter(prefix="/api/query", tags=["query"])

# Simple in-process cache to protect demo from rate limits
_cache: dict[str, dict] = {}
_node_cache: dict[str, dict] = {}

_model = None
AI_AVAILABLE = False
_ai_initialized = False


def _ensure_ai() -> None:
    """Lazy init so we read GEMINI_API_KEY after dotenv has been loaded."""
    global _model, AI_AVAILABLE, _ai_initialized
    if _ai_initialized:
        return
    _ai_initialized = True
    try:
        api_key = os.getenv("GEMINI_API_KEY", "").strip()
        if api_key:
            genai.configure(api_key=api_key)
            _model = genai.GenerativeModel("gemini-2.0-flash")
            AI_AVAILABLE = True
    except Exception:
        AI_AVAILABLE = False


# ─── Prompt: general query ────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a security analyst assistant for VulnGraph, a code security analysis tool.
The user is asking about a code security graph produced by taint analysis.

Node types in this graph: source, sink, intermediate, function, sanitizer
Risk levels: HIGH, MEDIUM, LOW
Attack path concepts: taint flow, source-to-sink, sanitizer bypass

Common vulnerability types you know about:
- SQL injection: user input flows into cursor.execute() without parameterization
- Command injection: user input flows into subprocess.run/os.system with shell=True
- Path traversal: user input used in open() or file paths without validation
- Code injection: user input passed to eval() or exec()
- Insecure deserialization: pickle.loads() called on untrusted data

From the user's query, extract:
- intent: one of [show_attack_paths, show_high_risk, explain_path, show_sources, show_sinks, patch_node, general]
- target_node: node ID if a specific node is mentioned (or null)
- risk_filter: HIGH|MEDIUM|LOW|null
- explanation: 2-3 sentence security explanation answering their question, using specific vulnerability terminology

Respond ONLY with valid JSON. No markdown. No preamble. No trailing text.
Example:
{"intent":"show_high_risk","target_node":null,"risk_filter":"HIGH","explanation":"High-risk paths are direct source-to-sink flows without any sanitization. In this codebase, SQL injection and command injection paths represent the most critical attack vectors. These occur when request parameters flow directly into cursor.execute() or subprocess.run() calls."}
"""

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


# ─── Rule-based node analysis fallback ───────────────────────────────────────

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


# ─── Models ───────────────────────────────────────────────────────────────────

class QueryRequest(BaseModel):
    query: str


class NodeExplainRequest(BaseModel):
    node_id: str | None = None
    label: str | None = None
    node_type: str | None = None
    severity: float | None = None
    risk: str | None = None
    file: str | None = None
    line: int | None = None


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/ask")
def ask(req: QueryRequest):
    _ensure_ai()
    q = (req.query or "").strip()
    if not q:
        return _fallback("empty query")

    if q in _cache:
        return _cache[q]

    if AI_AVAILABLE and _model:
        try:
            response = _model.generate_content(
                SYSTEM_PROMPT + "\n\nUser query: " + q
            )
            text = response.text.strip()
            text = text.replace("```json", "").replace("```", "").strip()
            result = json.loads(text)
            _cache[q] = result
            return result
        except Exception:
            pass  # Fall through to rule-based

    return _rule_based_fallback(q)


@router.post("/explain-node")
def explain_node(req: NodeExplainRequest):
    """
    Given a specific sink/source node, return structured vulnerability analysis:
    - What type of vulnerability
    - What an attacker can do
    - What causes it (root cause)
    - 1-2 line fix suggestion
    - CWE reference
    """
    _ensure_ai()

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


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _fallback(reason: str = "") -> dict:
    return {
        "intent": "show_attack_paths",
        "target_node": None,
        "risk_filter": None,
        "explanation": "Showing all attack paths from sources to sinks in the scanned codebase.",
    }


def _rule_based_fallback(q: str) -> dict:
    ql = q.lower()
    built = get_security_graph()
    g = built["graph"]

    sink_keyword_map = [
        ("sql", "execute"),
        ("injection", "execute"),
        ("database", "execute"),
        ("command", "os.system"),
        ("rce", "os.system"),
        ("shell", "subprocess"),
        ("subprocess", "subprocess"),
        ("eval", "eval"),
        ("exec", "exec"),
        ("file", "open"),
        ("path traversal", "open"),
        ("pickle", "pickle"),
    ]

    sinks = [n for n, d in g.nodes(data=True) if d.get("type") == "sink"]
    target = None
    explanation = "Showing all attack paths from sources to sinks."

    for key, needle in sink_keyword_map:
        if key in ql:
            for s in sinks:
                label = str(g.nodes[s].get("label", "")).lower()
                if needle in label:
                    target = s
                    break
        if target:
            break

    risk_filter = None
    if "high" in ql:
        risk_filter = "HIGH"
        explanation = "Showing HIGH risk paths: direct source-to-sink flows without sanitization."
    elif "medium" in ql:
        risk_filter = "MEDIUM"
        explanation = "Showing MEDIUM risk paths: flows with partial mitigations."
    elif "low" in ql:
        risk_filter = "LOW"
        explanation = "Showing LOW risk paths: flows with significant sanitization."

    if "sql" in ql or "injection" in ql:
        explanation = (
            "SQL injection occurs when user-supplied input is concatenated directly into SQL queries. "
            "In this codebase, cursor.execute() calls with f-strings or string formatting are vulnerable. "
            "Use parameterized queries (cursor.execute(query, params)) to remediate."
        )
    elif "command" in ql or "rce" in ql or "shell" in ql:
        explanation = (
            "Command injection allows attackers to execute arbitrary shell commands. "
            "This codebase has subprocess.run() or os.system() calls with shell=True and unsanitized input. "
            "Remediate by avoiding shell=True and validating all command arguments."
        )
    elif "path" in ql or "traversal" in ql or "file" in ql:
        explanation = (
            "Path traversal vulnerabilities allow attackers to read files outside the intended directory. "
            "User-controlled filenames passed to open() without os.path.basename() are exploitable. "
            "Always validate and sanitize file paths before use."
        )

    if target is None:
        hr = compute_high_risk_paths(limit=1)
        if hr:
            target = hr[0]["sink"]
        elif sinks:
            target = sinks[0]

    intent = "show_attack_paths"
    if "high risk" in ql or "critical" in ql:
        intent = "show_high_risk"
    elif "source" in ql:
        intent = "show_sources"
    elif "sink" in ql:
        intent = "show_sinks"

    return {
        "intent": intent,
        "target_node": target,
        "risk_filter": risk_filter,
        "explanation": explanation,
    }
