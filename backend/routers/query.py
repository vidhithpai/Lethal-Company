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
    return build_structured_response(llm_text, retrieved, query, intents)


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


@router.post("/explain-node")
def explain_node(node_id: str, query: str = "explain this vulnerability"):
    """Explain a specific node selected in the graph."""
    enriched_query = f"Explain the security implications of node '{node_id}'. {query}"
    return ask_query(QueryRequest(query=enriched_query))
