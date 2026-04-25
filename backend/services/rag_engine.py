"""
rag_engine.py
RAG pipeline for VulnGraph using ChromaDB + sentence-transformers.
Converts graph findings into searchable documents.
Retrieves relevant context for Gemini queries.
All free — no API keys needed for embeddings.
"""

import json
import hashlib
from typing import Optional

# Lightweight in-memory document store to replace heavy ChromaDB/PyTorch
_documents = []

def _node_to_document(node: dict) -> str:
    parts = [
        f"Node: {node.get('label', 'unknown')}",
        f"Type: {node.get('type', 'unknown')}",
        f"Risk: {node.get('risk', 'UNKNOWN')}",
        f"File: {node.get('file', 'unknown')} line {node.get('line', '?')}",
        f"Community: {node.get('community', 'unknown')}",
    ]
    if node.get('sink_kind'): parts.append(f"Vulnerability type: {node['sink_kind']}")
    if node.get('source_kind'): parts.append(f"Input type: {node['source_kind']}")
    if node.get('git_blame'):
        blame = node['git_blame']
        parts.append(f"Introduced by {blame.get('author','unknown')} on {blame.get('date','unknown')} commit {blame.get('commit','unknown')}")
    if node.get('confidence'): parts.append(f"Confidence: {int(node['confidence']*100)}%")
    return ". ".join(parts)

def _path_to_document(path_info: dict, index: int) -> str:
    path_nodes = path_info.get('path', [])
    score = path_info.get('risk_score', 0)
    classification = path_info.get('classification', 'UNKNOWN')
    source = path_info.get('source', path_nodes[0] if path_nodes else 'unknown')
    sink = path_info.get('sink', path_nodes[-1] if path_nodes else 'unknown')

    parts = [
        f"Attack path {index+1}: {source} to {sink}",
        f"Risk classification: {classification}",
        f"Risk score: {score}",
        f"Path length: {len(path_nodes)} hops",
        f"Full path: {' -> '.join(str(n) for n in path_nodes)}",
    ]
    return ". ".join(parts)

def index_graph_findings(graph_data: dict, attack_paths: list[dict]) -> dict:
    global _documents
    _documents = []

    indexed_nodes = 0
    for node in graph_data.get('nodes', []):
        if node.get('type') in ('source', 'sink', 'sanitizer'):
            doc = _node_to_document(node)
            _documents.append({
                "document": doc,
                "metadata": {
                    "doc_type": "node",
                    "node_type": node.get('type', 'unknown'),
                    "risk": node.get('risk', 'LOW')
                }
            })
            indexed_nodes += 1

    indexed_paths = 0
    for i, path_info in enumerate(attack_paths):
        doc = _path_to_document(path_info, i)
        _documents.append({
            "document": doc,
            "metadata": {
                "doc_type": "attack_path",
                "classification": path_info.get('classification', 'UNKNOWN')
            }
        })
        indexed_paths += 1

    return {"indexed_nodes": indexed_nodes, "indexed_paths": indexed_paths, "total_docs": len(_documents)}

def retrieve_relevant_context(query: str, n_results: int = 5, filter_type: Optional[str] = None) -> list[dict]:
    if not _documents: return []
    
    query_terms = set(query.lower().split())
    scored_docs = []
    
    for doc in _documents:
        if filter_type and doc['metadata'].get('doc_type') != filter_type: continue
        
        text = doc['document'].lower()
        score = sum(1.0 for term in query_terms if term in text)
        if score > 0:
            scored_docs.append({
                "document": doc['document'],
                "metadata": doc['metadata'],
                "relevance_score": min(score / len(query_terms), 1.0)
            })
            
    scored_docs.sort(key=lambda x: x['relevance_score'], reverse=True)
    return scored_docs[:n_results]

def build_gemini_prompt(user_query: str,
                         retrieved_docs: list[dict],
                         graph_summary: dict) -> str:
    """
    Build a grounded Gemini prompt using retrieved RAG context.
    This is the key function that fixes the generic response problem.
    """
    context_blocks = []
    for i, doc in enumerate(retrieved_docs):
        relevance = doc['relevance_score']
        context_blocks.append(
            f"[Finding {i+1} — relevance {relevance:.0%}]\n{doc['document']}"
        )

    context_text = "\n\n".join(context_blocks) if context_blocks else \
        "No specific findings retrieved — answer generally."

    summary_text = (
        f"Scan summary: {graph_summary.get('total_nodes',0)} nodes, "
        f"{graph_summary.get('total_sources',0)} sources, "
        f"{graph_summary.get('total_sinks',0)} sinks, "
        f"{graph_summary.get('total_paths',0)} attack paths found. "
        f"Project: {graph_summary.get('scanned_project','unknown')}"
    )

    return f"""You are a cybersecurity analyst assistant for VulnGraph.
You have access to the actual findings from a real codebase security scan.
Answer the user's question using ONLY the findings provided below.
Be specific — reference actual file names, line numbers, authors, and CVEs from the findings.
Do not give generic security advice unless no specific findings are relevant.

SCAN SUMMARY:
{summary_text}

RELEVANT FINDINGS (retrieved by semantic search):
{context_text}

USER QUESTION: {user_query}

Respond in 3-5 sentences. Be specific about the actual findings.
If the question asks to highlight/show a path, also return:
{{"action": "highlight_path", "path_index": N}}
at the end of your response on a new line as JSON.
If the question asks about a specific node, also return:
{{"action": "select_node", "node_id": "..."}}
If no action needed, do not include the JSON line."""

# =============================================================================
# OPTIONAL: ChromaDB + PyTorch Sentence Transformers Implementation
# =============================================================================
# If you are running this on a machine with >4GB Docker RAM, you can swap 
# the lightweight keyword search above with this semantic embedding engine.
#
# To use: 
# 1. Comment out the lightweight `_documents`, `index_graph_findings`, and 
#    `retrieve_relevant_context` functions above.
# 2. Uncomment the block below.
#
# import chromadb
# from chromadb.config import Settings
# from sentence_transformers import SentenceTransformer
#
# _embedder = None
# _chroma_client = None
# _collection = None
# COLLECTION_NAME = "vulngraph_findings"
#
# def _get_embedder():
#     global _embedder
#     if _embedder is None:
#         _embedder = SentenceTransformer("all-MiniLM-L6-v2")
#     return _embedder
#
# def _get_collection():
#     global _chroma_client, _collection
#     if _chroma_client is None:
#         _chroma_client = chromadb.Client(Settings(
#             chroma_db_impl="duckdb+parquet",
#             persist_directory="./chroma_store",
#             anonymized_telemetry=False
#         ))
#     if _collection is None:
#         _collection = _chroma_client.get_or_create_collection(
#             name=COLLECTION_NAME,
#             metadata={"hnsw:space": "cosine"}
#         )
#     return _collection
#
# def index_graph_findings(graph_data: dict, attack_paths: list[dict]) -> dict:
#     collection = _get_collection()
#     embedder = _get_embedder()
#     try:
#         existing = collection.get()
#         if existing['ids']: collection.delete(ids=existing['ids'])
#     except Exception: pass
#
#     documents, metadatas, ids = [], [], []
#     indexed_nodes = 0
#     for node in graph_data.get('nodes', []):
#         if node.get('type') in ('source', 'sink', 'sanitizer'):
#             doc = _node_to_document(node)
#             doc_id = f"node_{node.get('id', hashlib.md5(doc.encode()).hexdigest()[:8])}"
#             documents.append(doc)
#             metadatas.append({"doc_type": "node", "node_type": node.get('type', 'unknown'), "risk": node.get('risk', 'LOW')})
#             ids.append(doc_id)
#             indexed_nodes += 1
#
#     indexed_paths = 0
#     for i, path_info in enumerate(attack_paths):
#         doc = _path_to_document(path_info, i)
#         doc_id = f"path_{i}_{hashlib.md5(doc.encode()).hexdigest()[:8]}"
#         documents.append(doc)
#         metadatas.append({"doc_type": "attack_path", "classification": path_info.get('classification', 'UNKNOWN')})
#         ids.append(doc_id)
#         indexed_paths += 1
#
#     if documents:
#         embeddings = embedder.encode(documents).tolist()
#         collection.add(documents=documents, embeddings=embeddings, metadatas=metadatas, ids=ids)
#
#     return {"indexed_nodes": indexed_nodes, "indexed_paths": indexed_paths, "total_docs": len(documents)}
#
# def retrieve_relevant_context(query: str, n_results: int = 5, filter_type: Optional[str] = None) -> list[dict]:
#     collection = _get_collection()
#     embedder = _get_embedder()
#     try:
#         if collection.count() == 0: return []
#     except Exception: return []
#
#     query_embedding = embedder.encode([query]).tolist()
#     where_filter = {"doc_type": filter_type} if filter_type else None
#
#     results = collection.query(
#         query_embeddings=query_embedding,
#         n_results=min(n_results, max(collection.count(), 1)),
#         where=where_filter,
#         include=["documents", "metadatas", "distances"]
#     )
#
#     retrieved = []
#     for i, doc in enumerate(results['documents'][0]):
#         retrieved.append({
#             "document": doc,
#             "metadata": results['metadatas'][0][i],
#             "relevance_score": round(1 - results['distances'][0][i], 3)
#         })
#     return retrieved
