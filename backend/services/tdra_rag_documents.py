"""
TDRA RAG Document Builder.
Converts all TDRA engine output into structured text documents
ready for embedding into the vector store.

One document per:
  - Commit record (RF score, severity, new paths, guard events)
  - Attack path (ENTRY→SINK chain, guards, CWE, residual risk)
  - Guard weakening event (which guard, which path, attenuation drop)
  - SINK node (file, line, CWE, git blame, effective guard strength)
"""

from typing import Optional
import json


# ── Document builders ─────────────────────────────────────────────────────────

def build_commit_document(commit: dict) -> dict:
    """
    Convert a single TDRA commit analysis result into a text document.
    Includes all metadata as ChromaDB metadata fields for filtering.
    """
    rf     = commit.get("risk_factor", 0)
    sev    = commit.get("severity", "Low")
    author = commit.get("author", "unknown")
    date   = commit.get("date", "unknown")[:10]
    msg    = commit.get("message", "")[:120]
    hash_  = commit.get("commit_hash", "")[:12]
    np_    = commit.get("new_attack_paths", 0)
    gw     = commit.get("guard_weakening_events", 0)
    files  = commit.get("changed_files", [])
    paths  = commit.get("new_paths_detail", [])
    attn   = commit.get("total_attenuation_drop", 0)
    method = commit.get("analysis_method", "unknown")

    # Build human-readable evidence text
    path_descriptions = []
    for i, path in enumerate(paths[:3]):  # top 3 paths only
        nodes = path if isinstance(path, list) else [path]
        path_descriptions.append(
            f"Path {i+1}: {' → '.join(str(n).split(':')[-1] for n in nodes[:6])}"
        )

    text = (
        f"Commit {hash_} by {author} on {date}: {msg}. "
        f"Risk Factor: {rf:.3f} ({sev} severity). "
        f"This commit introduced {np_} new attack path(s) from user input to security-sensitive operations. "
        f"Guard weakening events detected: {gw}. "
        f"Total effective guard strength lost: {attn:.3f}. "
        f"Changed files: {', '.join(f.split('/')[-1] for f in files[:5])}. "
        + (f"New attack paths: {'; '.join(path_descriptions)}. " if path_descriptions else "")
        + f"Analysis method: {method}."
    )

    return {
        "text": text,
        "metadata": {
            "doc_type": "commit",
            "commit_hash": hash_,
            "author": author,
            "date": date,
            "severity": sev,
            "risk_factor": float(rf),
            "new_attack_paths": int(np_),
            "guard_weakening_events": int(gw),
            "changed_files": json.dumps(files[:10]),
            "message": msg[:100],
        }
    }


def build_attack_path_document(path_info: dict, commit_hash: str = "",
                                commit_author: str = "") -> dict:
    """
    Convert an attack path into a text document.
    path_info must have: path (list of node IDs), guards, residual_risk,
    effective_guard_strength, cwe, sink_category.
    """
    path_nodes = path_info.get("path", [])
    guards     = path_info.get("guards", [])
    rr         = path_info.get("residual_risk", 1.0)
    gs         = path_info.get("effective_guard_strength", 0.0)
    cwe        = path_info.get("cwe", "unknown")
    cat        = path_info.get("sink_category", "Generic")
    risk       = path_info.get("risk", rr)
    conf       = path_info.get("confidence", "EXTRACTED")

    # Extract readable node names (last segment of node ID)
    def readable(nid):
        parts = str(nid).split(":")
        return parts[-1] if parts else str(nid)

    entry = readable(path_nodes[0]) if path_nodes else "unknown"
    sink  = readable(path_nodes[-1]) if path_nodes else "unknown"
    hops  = [readable(n) for n in path_nodes[1:-1]]

    guard_str = (
        f"Protected by guards: {', '.join(readable(g) for g in guards[:3])}. "
        f"Effective guard strength: {gs*100:.1f}%. "
        if guards else "No guards on this path. "
    )

    text = (
        f"Attack path from entry point '{entry}' to security sink '{sink}' ({cat}, {cwe}). "
        f"Path length: {len(path_nodes)} hops. "
        f"Intermediate nodes: {' → '.join(hops[:5])}. "
        + guard_str +
        f"Residual taint risk: {rr:.3f} ({rr*100:.1f}% of taint reaches the sink). "
        f"Edge confidence: {conf}. "
        + (f"Introduced in commit {commit_hash[:8]} by {commit_author}. "
           if commit_hash else "")
    )

    return {
        "text": text,
        "metadata": {
            "doc_type": "attack_path",
            "cwe": cwe,
            "sink_category": cat,
            "residual_risk": float(rr),
            "effective_guard_strength": float(gs),
            "guard_count": len(guards),
            "path_length": len(path_nodes),
            "entry_node": entry,
            "sink_node": sink,
            "commit_hash": commit_hash[:12],
            "confidence": conf,
        }
    }


def build_guard_event_document(path: list, guard_node: str,
                                a_prev: float, a_curr: float,
                                commit_hash: str, sink_cwe: str = "") -> dict:
    """
    Build a document for a guard weakening event — when a guard was
    removed or weakened on a shared path across versions.
    """
    def readable(nid):
        parts = str(nid).split(":")
        return parts[-1] if parts else str(nid)

    drop = a_prev - a_curr
    guard_name = readable(guard_node)

    text = (
        f"Guard weakening detected in commit {commit_hash[:8]}. "
        f"Guard '{guard_name}' was removed or weakened on an existing attack path. "
        f"Effective guard strength dropped from {a_prev*100:.1f}% to {a_curr*100:.1f}% "
        f"(loss of {drop*100:.1f}%). "
        + (f"This path terminates at a {sink_cwe} sink. " if sink_cwe else "")
        + f"Path: {' → '.join(readable(n) for n in path[:6])}."
    )

    return {
        "text": text,
        "metadata": {
            "doc_type": "guard_event",
            "guard_node": guard_name,
            "attenuation_prev": float(a_prev),
            "attenuation_curr": float(a_curr),
            "attenuation_drop": float(drop),
            "commit_hash": commit_hash[:12],
            "sink_cwe": sink_cwe,
        }
    }


def build_sink_node_document(node: dict) -> dict:
    """
    Build a document for a SINK node — includes CWE, file location,
    git blame, and current guard coverage.
    """
    label   = node.get("label", node.get("id", "unknown"))
    file_   = node.get("file", "unknown")
    line    = node.get("line", "?")
    cwe     = node.get("cwe", "unknown")
    cwe_name= node.get("cwe_name", "")
    rr      = node.get("residual_risk", 1.0)
    gs      = node.get("effective_guard_strength", 0.0)
    risk    = node.get("risk", "UNKNOWN")
    blame   = node.get("git_blame", {})

    blame_str = ""
    if blame:
        blame_str = (
            f"Introduced by {blame.get('author','unknown')} "
            f"on {str(blame.get('date',''))[:10]} "
            f"in commit {str(blame.get('commit',''))[:8]}. "
        )

    guards = node.get("guard_attenuations", [])
    guard_str = (
        f"Protected by {len(guards)} guard(s): "
        f"{', '.join(g.get('label','?') for g in guards[:3])}. "
        f"Effective guard strength: {gs*100:.1f}%. "
        if guards else "No guards protecting this sink. "
    )

    text = (
        f"Security sink '{label}' in {file_.split('/')[-1]} at line {line}. "
        f"Vulnerability class: {cwe_name or cwe}. "
        f"Risk classification: {risk}. "
        + guard_str + blame_str +
        f"Residual taint risk: {rr:.3f}."
    )

    return {
        "text": text,
        "metadata": {
            "doc_type": "sink_node",
            "node_label": label[:100],
            "file": file_.split("/")[-1],
            "line": int(line) if str(line).isdigit() else 0,
            "cwe": cwe,
            "risk": risk,
            "residual_risk": float(rr),
            "effective_guard_strength": float(gs),
            "guard_count": len(guards),
            "blame_author": blame.get("author", ""),
        }
    }


def build_all_documents(
    graph_data: dict,
    attack_paths: list[dict],
    tdra_timeline: list[dict],
    source_snippets: dict[str, str] = None,  # {node_id: code_snippet}
) -> list[dict]:
    """
    Master builder: converts ALL TDRA outputs into a flat list of documents
    ready for embedding. Called after every scan + TDRA analysis.
    """
    docs = []

    # 1. TDRA commit records
    for commit in tdra_timeline:
        docs.append(build_commit_document(commit))
        # Also index each new path from this commit
        for path in commit.get("new_paths_detail", [])[:5]:
            if isinstance(path, list) and len(path) >= 2:
                path_doc = build_attack_path_document(
                    {"path": path, "residual_risk": commit.get("risk_factor", 1.0)},
                    commit_hash=commit.get("commit_hash", ""),
                    commit_author=commit.get("author", ""),
                )
                docs.append(path_doc)

    # 2. Attack paths (from current graph scan)
    for path in attack_paths:
        docs.append(build_attack_path_document(path))

    # 3. SINK nodes from current graph
    nodes = graph_data.get("nodes", [])
    for node in nodes:
        if node.get("type") == "sink":
            docs.append(build_sink_node_document(node))

    return docs
