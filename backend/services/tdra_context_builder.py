"""
TDRA Context Builder — assembles retrieved documents into
a structured evidence block for LLM prompting.
Implements evidence-grounded prompting: the LLM can only
explain what the TDRA engine has already proven.
"""

from typing import Optional


SYSTEM_PROMPT_BASE = """You are VulnGraph's security intelligence assistant.
You explain security findings that were PROVEN by the TDRA graph engine.
You do NOT infer, guess, or speculate about vulnerabilities.
You ONLY explain what the evidence block shows.

Your role is to translate deterministic graph analysis results into 
plain English that a developer can act on immediately.

Always structure your response as:
1. What the finding means (1-2 sentences)
2. Which specific code locations are affected (file:line)
3. How the commit changed the security posture (before vs after)
4. Concrete remediation step (specific code change, not generic advice)
5. CWE reference if applicable

If the evidence does not contain enough information to answer the query,
say exactly that — do not guess."""


QUERY_INTENT_PATTERNS = {
    "why_critical": ["why", "critical", "explain", "reason", "how bad"],
    "show_paths": ["show", "path", "flow", "reach", "injection", "sink"],
    "who_introduced": ["who", "introduced", "commit", "author", "when", "blame"],
    "how_to_fix": ["fix", "remediate", "patch", "solve", "prevent", "mitigate"],
    "worst_commits": ["worst", "riskiest", "highest", "most dangerous", "top"],
    "guard_analysis": ["guard", "validation", "@valid", "sanitizer", "missing"],
}


def detect_query_intent(query: str) -> list[str]:
    """Detect what the developer is asking about to tune retrieval."""
    query_lower = query.lower()
    intents = []
    for intent, patterns in QUERY_INTENT_PATTERNS.items():
        if any(p in query_lower for p in patterns):
            intents.append(intent)
    return intents or ["general"]


def build_retrieval_config(intents: list[str]) -> dict:
    """
    Map query intents to retrieval parameters.
    Different intents need different collections and filters.
    """
    config = {
        "doc_types": ["commit", "attack_path", "sink_node", "guard_event"],
        "n_results": 5,
        "severity_filter": None,
    }

    if "why_critical" in intents:
        config["doc_types"] = ["commit", "attack_path", "guard_event"]
        config["severity_filter"] = "Critical"
        config["n_results"] = 6
    elif "show_paths" in intents:
        config["doc_types"] = ["attack_path", "sink_node"]
        config["n_results"] = 7
    elif "who_introduced" in intents:
        config["doc_types"] = ["commit", "sink_node"]
        config["n_results"] = 5
    elif "how_to_fix" in intents:
        config["doc_types"] = ["sink_node", "attack_path", "guard_event"]
        config["n_results"] = 6
    elif "worst_commits" in intents:
        config["doc_types"] = ["commit"]
        config["severity_filter"] = None  # we want all severities, sorted
        config["n_results"] = 8
    elif "guard_analysis" in intents:
        config["doc_types"] = ["guard_event", "attack_path"]
        config["n_results"] = 6

    return config


def build_llm_prompt(query: str, context_block: str,
                     graph_summary: dict = None) -> list[dict]:
    """
    Build the messages list for the LLM API call.
    Returns [system_message, user_message] in OpenAI/Groq chat format.
    """
    summary_str = ""
    if graph_summary:
        summary_str = (
            f"\nCurrent scan summary: {graph_summary.get('nodes', 0)} nodes, "
            f"{graph_summary.get('sinks', 0)} sinks, "
            f"{graph_summary.get('sources', 0)} entry points, "
            f"{graph_summary.get('paths_found', 0)} attack paths found.\n"
        )

    system_content = SYSTEM_PROMPT_BASE + summary_str

    user_content = (
        f"Developer query: {query}\n\n"
        f"{context_block}\n\n"
        "Answer the developer's question using ONLY the evidence above. "
        "Be specific about file names, line numbers, commit hashes, and CWEs. "
        "If the commit hash appears in the evidence, always mention it."
    )

    return [
        {"role": "system", "content": system_content},
        {"role": "user", "content": user_content},
    ]


def build_structured_response(
    llm_text: str,
    retrieved_docs: list[dict],
    query: str,
    intents: list[str],
) -> dict:
    """
    Wrap the LLM response with TDRA metadata so the frontend
    can show evidence cards alongside the explanation.
    """
    # Extract commit hashes mentioned in docs
    commits = []
    for doc in retrieved_docs:
        h = doc["metadata"].get("commit_hash", "")
        if h and h not in commits:
            commits.append(h)

    # Extract CWEs mentioned
    cwes = list(set(
        doc["metadata"].get("cwe", "")
        for doc in retrieved_docs
        if doc["metadata"].get("cwe")
    ))

    # Extract files mentioned
    files = list(set(
        doc["metadata"].get("file", "")
        for doc in retrieved_docs
        if doc["metadata"].get("file")
    ))

    # Average relevance score
    avg_score = (
        sum(d["score"] for d in retrieved_docs) / len(retrieved_docs)
        if retrieved_docs else 0.0
    )

    return {
        "explanation": llm_text,
        "query": query,
        "intents": intents,
        "evidence_count": len(retrieved_docs),
        "confidence": round(avg_score, 3),
        "affected_commits": commits[:5],
        "cwes": cwes,
        "affected_files": files[:5],
        "evidence_sources": [
            {
                "type": d["metadata"].get("doc_type"),
                "text": d["text"][:200] + "...",
                "score": round(d["score"], 3),
            }
            for d in retrieved_docs[:4]
        ],
        "source": "tdra_rag",
    }
