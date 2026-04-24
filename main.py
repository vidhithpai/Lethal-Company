import json
import os
import re
from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

try:
    import google.generativeai as genai
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "google-generativeai is not installed. Run: pip install -r requirements.txt"
    ) from exc


app = FastAPI(title="VulnGraph AI Query Layer", version="1.0.0")


class AskRequest(BaseModel):
    question: str = Field(..., min_length=1, description="Natural language query")


class QueryObject(BaseModel):
    intent: str
    source: str
    target: str


class AskResponse(BaseModel):
    query: QueryObject
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
You are the VulnGraph AI Query Layer.

Task:
Convert a natural language security graph question into strict JSON only.

Rules:
1) Extract target node from the question.
2) Default source to "user_device" when not explicitly provided.
3) intent must be "attack_path".
4) Return ONLY valid JSON with this exact shape:
{{
  "query": {{
    "intent": "attack_path",
    "source": "user_device",
    "target": "<extracted_target>"
  }},
  "explanation": "<short remediation suggestion>"
}}
5) explanation must be concise and actionable.
6) No markdown, no code fences, no extra keys.

Input question:
{question}
""".strip()


def ask_gemini(question: str) -> Dict[str, Any]:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=500, detail="Missing GEMINI_API_KEY environment variable"
        )

    genai.configure(api_key=api_key)

    # Gemini 1.5 model family
    model = genai.GenerativeModel("gemini-1.5-flash")
    prompt = _build_prompt(question)

    try:
        response = model.generate_content(prompt)
        raw_text = (response.text or "").strip()
        payload = _extract_json(raw_text)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=502, detail=f"Gemini returned non-JSON content: {exc}"
        ) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Gemini API error: {exc}") from exc

    # Enforce output contract even if model drifts.
    query = payload.get("query", {})
    target = query.get("target", "database")
    explanation = payload.get(
        "explanation",
        "Reduce attack paths by tightening access controls and segmenting sensitive services.",
    )

    return {
        "query": {
            "intent": "attack_path",
            "source": query.get("source", "user_device") or "user_device",
            "target": target,
        },
        "explanation": explanation,
    }


@app.post("/api/query/ask", response_model=AskResponse)
def ask_query(body: AskRequest) -> AskResponse:
    result = ask_gemini(body.question)
    return AskResponse(**result)
from fastapi import FastAPI

from backend.routers.graph import router as graph_router

app = FastAPI(title="VulnGraph Graph Engine")

app.include_router(graph_router)

