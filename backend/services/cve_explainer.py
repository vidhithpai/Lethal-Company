import os
import json
from typing import Dict, Any
try:
    from google import genai
except ImportError:
    genai = None

# Cache for AI explanations
_explanation_cache: Dict[str, str] = {}

def get_genai_client():
    if genai is None:
        raise ImportError("google.genai package is not installed.")
    api_key = os.getenv("GEMINI_API_KEY")
    if api_key:
        return genai.Client(api_key=api_key)
    return genai.Client() # Fallback to default if set in environment

def explain_cve(cve_data: Dict[str, Any], reachability_data: Dict[str, Any]) -> str:
    """
    Uses Gemini to explain a CVE based on structured evidence.
    """
    cve_id = cve_data.get('id')
    package = cve_data.get('package')
    reachable = reachability_data.get('reachable')
    
    cache_key = f"{cve_id}:{package}:{reachable}"
    if cache_key in _explanation_cache:
        return _explanation_cache[cache_key]

    try:
        client = get_genai_client()
    except ImportError as e:
        return f"AI Explanations disabled: {e}"

    prompt = f"""
    You are a Principal Security Engineer. Your task is to explain the following CVE and its exploitability in the context of the user's application.
    
    CRITICAL INSTRUCTIONS:
    - DO NOT fabricate any CVEs or hallucinate packages.
    - ONLY use the provided evidence.
    - DO NOT invent exploitability if the reachability data says it is not reachable.
    
    CVE Details:
    - ID: {cve_data.get('id')}
    - Package: {cve_data.get('package')}
    - Version: {cve_data.get('installed_version')}
    - Severity: {cve_data.get('severity')}
    - Summary: {cve_data.get('summary')}
    
    Application Context (Reachability Analysis):
    - Is Reachable: {reachability_data.get('reachable')}
    - Confidence: {reachability_data.get('confidence')}
    - Entry Points: {json.dumps(reachability_data.get('entry_points', []))}
    - Affected Files: {json.dumps(reachability_data.get('affected_files', []))}
    
    Provide a concise explanation covering:
    1. The core impact of the vulnerability.
    2. Exploitability (based on the reachability data). If it's reachable, explain how an attacker might trigger it from the entry points. If it's not reachable, explain that the risk is lower but still present.
    3. Remediation recommendations (e.g., upgrading the package).
    """
    
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )
        explanation = response.text
        _explanation_cache[cache_key] = explanation
        return explanation
    except Exception as e:
        return f"Error generating explanation: {e}"
