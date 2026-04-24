import json
import os
import re
from collections import OrderedDict
from typing import Any, Dict
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

try:
    import google.generativeai as genai
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "google-generativeai is not installed. Run: pip install -r requirements.txt"
    ) from exc


app = FastAPI(title="VulnGraph AI Query Layer", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SYSTEM_PROMPT = """
You are a cybersecurity assistant for VulnGraph.
Valid node IDs: internet, firewall, webserver, appserver, database, cache

Extract from the user query:
- target_node: one of the valid node IDs (default: database)
- intent: always "attack_path"
- explanation: 2-3 sentences of remediation advice for reaching that node

Respond ONLY with valid JSON, no markdown, no preamble.
""".strip()

FALLBACK_RESPONSE = {
    "target_node": "database",
    "intent": "attack_path",
    "explanation": "Patch critical CVEs on webserver and appserver to block database access.",
}
VALID_NODE_IDS = {"internet", "firewall", "webserver", "appserver", "database", "cache"}
CACHE_LIMIT = 10
QUERY_CACHE: "OrderedDict[str, Dict[str, str]]" = OrderedDict()


class AskRequest(BaseModel):
    query: str = Field(..., min_length=1, description="Natural language query")


class AskResponse(BaseModel):
    target_node: str
    intent: str
    explanation: str


def _extract_json(text: str) -> Dict[str, Any]:
    """
    Parse JSON from Gemini output, including fenced responses.
    """
    cleaned = text.strip()

    # Handle ```json ... ``` wrappers.
    fence_match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", cleaned, re.DOTALL)
    if fence_match:
        cleaned = fence_match.group(1).strip()

    # Fallback: first JSON object in text.
    if not cleaned.startswith("{"):
        obj_match = re.search(r"(\{.*\})", cleaned, re.DOTALL)
        if obj_match:
            cleaned = obj_match.group(1).strip()

    return json.loads(cleaned)


def _build_prompt(question: str) -> str:
    return f"""
{SYSTEM_PROMPT}

User query:
{question}
""".strip()


def _normalize_payload(payload: Dict[str, Any]) -> Dict[str, str]:
    target_node = str(payload.get("target_node", "database")).strip().lower()
    if target_node not in VALID_NODE_IDS:
        target_node = "database"

    explanation = str(payload.get("explanation", FALLBACK_RESPONSE["explanation"])).strip()
    if not explanation:
        explanation = FALLBACK_RESPONSE["explanation"]

    return {
        "target_node": target_node,
        "intent": "attack_path",
        "explanation": explanation,
    }


def _cache_get(query: str) -> Dict[str, str] | None:
    if query not in QUERY_CACHE:
        return None
    QUERY_CACHE.move_to_end(query)
    return QUERY_CACHE[query]


def _cache_put(query: str, value: Dict[str, str]) -> None:
    QUERY_CACHE[query] = value
    QUERY_CACHE.move_to_end(query)
    if len(QUERY_CACHE) > CACHE_LIMIT:
        QUERY_CACHE.popitem(last=False)


def ask_gemini(question: str) -> Dict[str, str]:
    cached = _cache_get(question)
    if cached:
        return cached

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        _cache_put(question, FALLBACK_RESPONSE)
        return FALLBACK_RESPONSE

    genai.configure(api_key=api_key)

    model = genai.GenerativeModel("gemini-2.0-flash")
    prompt = _build_prompt(question)

    try:
        response = model.generate_content(prompt)
        raw_text = (response.text or "").strip()
        payload = _extract_json(raw_text)
        normalized = _normalize_payload(payload)
        _cache_put(question, normalized)
        return normalized
    except Exception:
        _cache_put(question, FALLBACK_RESPONSE)
        return FALLBACK_RESPONSE


@app.post("/api/query/ask", response_model=AskResponse)
def ask_query(body: AskRequest) -> AskResponse:
    result = ask_gemini(body.query)
    return AskResponse(**result)
from fastapi import FastAPI

from backend.routers.graph import router as graph_router

app = FastAPI(title="VulnGraph Graph Engine")

app.include_router(graph_router)

