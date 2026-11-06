from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
import os

from backend.services.rag_engine import (
    retrieve_relevant_context, build_tdra_context_block, get_embed_mode
)
from backend.services.tdra_context_builder import (
    detect_query_intent, build_retrieval_config,
    build_llm_prompt, build_structured_response
)
from backend.services.code_security_graph import get_security_graph

router = APIRouter(prefix="/api/query", tags=["query"])

# LLM clients (same as before)
try:
    from groq import Groq
    _groq_client = Groq(api_key=os.getenv("GROQ_API_KEY", ""))
    AI_AVAILABLE = bool(os.getenv("GROQ_API_KEY"))
except Exception:
    _groq_client = None
    AI_AVAILABLE = False

_graph_summary: dict = {}
_cache: dict = {}
ai_query_cache: dict = {}

def update_graph_summary(summary: dict):
    global _graph_summary
    _graph_summary = summary



class QueryRequest(BaseModel):
    query: str
    filter_type: Optional[str] = None
    severity_filter: Optional[str] = None


@router.get("/rag-status")
def get_rag_status():
    """Check RAG pipeline status: embed mode, indexed docs."""
    return {
        "embed_mode": get_embed_mode(),
        "ai_available": AI_AVAILABLE,
        "ai_model": "groq/llama-3.3-70b" if AI_AVAILABLE else "rule-based",
    }


@router.post("/ask")
def ask_query(req: QueryRequest):
    query = req.query.strip()
    if not query:
        return {"explanation": "Please enter a question.", "source": "error"}

    # 1. Detect intent
    intents = detect_query_intent(query)

    # 2. Build retrieval config from intent
    retrieval_config = build_retrieval_config(intents)
    if req.severity_filter:
        retrieval_config["severity_filter"] = req.severity_filter

    # 3. Retrieve relevant TDRA documents
    retrieved = retrieve_relevant_context(
        query=query,
        n_results=retrieval_config["n_results"],
        severity_filter=retrieval_config.get("severity_filter"),
        doc_types=retrieval_config.get("doc_types"),
    )

    # 4. Build context block
    context_block = build_tdra_context_block(retrieved)

    # 5. Generate explanation
    if AI_AVAILABLE and _groq_client:
        try:
            messages = build_llm_prompt(query, context_block, _graph_summary)
            response = _groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=messages,
                max_tokens=600,
                temperature=0.1,  # low temperature: stick to evidence
            )
            llm_text = response.choices[0].message.content.strip()
        except Exception as e:
            print(f"[RAG] Groq error: {e}")
            llm_text = _rule_based_answer(query, retrieved, intents)
    else:
        llm_text = _rule_based_answer(query, retrieved, intents)

    # 6. Build structured response
    structured = build_structured_response(llm_text, retrieved, query, intents)
    ai_query_cache[query] = {
        "explanation": structured.get("explanation", llm_text),
        "structured": structured,
    }
    return structured


def _rule_based_answer(query: str, docs: list[dict], intents: list[str]) -> str:
    """Deterministic rule-based fallback — no LLM required."""
    if not docs:
        return ("No TDRA findings match your query. "
                "Scan a project first, then ask about specific commits or vulnerabilities.")

    top = docs[0]
    meta = top["metadata"]
    dtype = meta.get("doc_type", "finding")

    if "worst_commits" in intents or "why_critical" in intents:
        sev = meta.get("severity", "unknown")
        rf  = meta.get("risk_factor", 0)
        np_ = meta.get("new_attack_paths", 0)
        return (
            f"The most critical finding is a {sev} severity commit "
            f"(RF={rf:.3f}) that introduced {np_} new attack path(s). "
            f"Evidence: {top['text'][:300]}"
        )
    elif "show_paths" in intents:
        cwe = meta.get("cwe", "unknown")
        rr  = meta.get("residual_risk", 1.0)
        return (
            f"Attack path found leading to {cwe} sink. "
            f"Residual risk: {rr:.3f} ({rr*100:.1f}% of taint reaches the sink). "
            f"Details: {top['text'][:300]}"
        )
    elif "who_introduced" in intents:
        author = meta.get("blame_author") or meta.get("author", "unknown")
        commit = meta.get("commit_hash", "unknown")
        return (
            f"Introduced by {author} in commit {commit}. "
            f"Details: {top['text'][:300]}"
        )
    elif "how_to_fix" in intents:
        cwe = meta.get("cwe", "")
        fixes = {
            "CWE-89": "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=?', (user_input,))",
            "CWE-78": "Use argument arrays: subprocess.run(['cmd', arg], shell=False)",
            "CWE-22": "Validate with os.path.realpath() and check it starts with the allowed base directory.",
            "CWE-95": "Remove eval(). Use ast.literal_eval() for safe data parsing.",
            "CWE-502": "Replace pickle with json.loads() for untrusted data.",
        }
        fix = fixes.get(cwe, "Add input validation at the entry point before data reaches the sink.")
        return f"Remediation for {cwe}: {fix}\n\nFinding context: {top['text'][:200]}"
    else:
        return f"TDRA finding: {top['text'][:400]}"


class ExplainNodeRequest(BaseModel):
    node_id: Optional[str] = None
    query: Optional[str] = "explain this vulnerability"
    label: Optional[str] = None
    node_type: Optional[str] = None
    severity: Optional[float] = None
    risk: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None


@router.post("/explain-node")
def explain_node(
    req: Optional[ExplainNodeRequest] = None,
    node_id: Optional[str] = None,
    query: Optional[str] = "explain this vulnerability"
):
    """Explain a specific node selected in the graph with real CWE context."""
    target_id = (req.node_id if req and req.node_id else node_id) or ""
    user_query = (req.query if req and req.query else query) or "explain this vulnerability"

    from backend.routers.security import read_node_context
    try:
        ctx = read_node_context(target_id)
    except Exception:
        ctx = {}

    analysis = ctx.get("analysis", {})
    cwe_id = analysis.get("cwe") or ""
    if cwe_id == "None":
        cwe_id = ""
    cwe_name = analysis.get("cwe_name") or ""
    role = analysis.get("role", req.node_type if req and req.node_type else "node")
    node_label = req.label if (req and req.label) else ctx.get("node", {}).get("label", target_id)

    # Cache key includes node id + CWE + query
    cache_key = f"{target_id}::{cwe_id}::{user_query}"
    if cache_key in ai_query_cache:
        cached = ai_query_cache[cache_key]
        return {
            **analysis,
            "explanation": cached.get("explanation", ""),
            "action": cached.get("action"),
            "structured": cached.get("structured"),
            "source": "cache"
        }

    explanation = ""
    if AI_AVAILABLE and _groq_client:
        try:
            prompt = (
                f"You are a forensic application security engineer analyzing a {role.upper()} node in a taint analysis graph.\n"
                f"Node ID: {target_id}\n"
                f"Label: {node_label}\n"
                f"Classification: {cwe_id} - {cwe_name}\n"
                f"Role: {role}\n"
                f"Summary: {analysis.get('what_it_does', '')}\n"
                f"Attack Surface: {analysis.get('root_cause', '')}\n"
                f"Fix: {analysis.get('fix', '')}\n\n"
                f"User question: {user_query}\n"
                f"Explain concisely the security role of this node, how taint reaches or leaves it, and actionable remediation."
            )
            response = _groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You are a specialized SAST forensic analyzer. Explain vulnerabilities using the exact provided CWE and attack paths without defaulting to CWE-20."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=400,
                temperature=0.1
            )
            explanation = response.choices[0].message.content.strip()
        except Exception as e:
            explanation = f"Analysis for {cwe_id} ({cwe_name}): {analysis.get('what_it_does', '')} {analysis.get('root_cause', '')}"
    else:
        explanation = f"Analysis for {cwe_id} ({cwe_name}): {analysis.get('what_it_does', '')} {analysis.get('root_cause', '')}"

    default_vuln = f"{cwe_id}: {cwe_name}" if (cwe_id and cwe_name) else (cwe_name or ("Benign / No Direct Attack Path" if role in ("normal", "intermediate") else "Node Analysis"))
    default_severity = "LOW" if role in ("normal", "intermediate") else ("HIGH" if role == "sink" else "MEDIUM")
    result = {
        "node_id": target_id,
        "vuln_type": analysis.get("vuln_type") or default_vuln,
        "cwe": cwe_id,
        "cwe_name": cwe_name,
        "cwes": analysis.get("cwes", []),
        "what_it_does": analysis.get("what_it_does", ""),
        "root_cause": analysis.get("root_cause", ""),
        "fix": analysis.get("fix", ""),
        "severity": analysis.get("severity") or default_severity,
        "role": role,
        "explanation": explanation
    }
    ai_query_cache[cache_key] = {"explanation": explanation, "structured": result}
    return result
