"""
rag_engine.py — TDRA-aware RAG engine with ChromaDB + GraphCodeBERT.

Architecture:
  Documents → GraphCodeBERT embeddings → ChromaDB collections
  Query → embed → cosine search → structured context block → LLM

Three embedding modes (in priority order):
  1. GraphCodeBERT (microsoft/graphcodebert-base) — best for code+graph
  2. all-MiniLM-L6-v2 — lightweight, fast, good general purpose
  3. TF-IDF fallback — always works, no model download needed
"""

import json
import hashlib
import os
from typing import Optional
from pathlib import Path

# ── Embedding model loader ────────────────────────────────────────────────────

_embedder = None
_embed_mode = "tfidf"  # default until model loads

def _load_embedder():
    global _embedder, _embed_mode
    
    # Try GraphCodeBERT first (best for code security context)
    try:
        from sentence_transformers import SentenceTransformer
        model_name = os.getenv(
            "TDRA_EMBED_MODEL",
            "microsoft/graphcodebert-base"
        )
        _embedder = SentenceTransformer(model_name)
        _embed_mode = "graphcodebert"
        print(f"[RAG] Loaded embedding model: {model_name}")
        return
    except Exception as e:
        print(f"[RAG] GraphCodeBERT failed ({e}), trying MiniLM...")

    # Try lightweight MiniLM fallback
    try:
        from sentence_transformers import SentenceTransformer
        _embedder = SentenceTransformer("all-MiniLM-L6-v2")
        _embed_mode = "minilm"
        print("[RAG] Loaded fallback model: all-MiniLM-L6-v2")
        return
    except Exception as e:
        print(f"[RAG] MiniLM failed ({e}), using TF-IDF fallback")
        _embed_mode = "tfidf"

def get_embed_mode() -> str:
    return _embed_mode

def embed_texts(texts: list[str]) -> list[list[float]]:
    """Embed a list of text strings. Returns list of float vectors."""
    global _embedder, _embed_mode
    
    if _embedder is None:
        _load_embedder()
    
    if _embed_mode in ("graphcodebert", "minilm"):
        vectors = _embedder.encode(texts, batch_size=32,
                                    show_progress_bar=False,
                                    convert_to_numpy=True)
        return [v.tolist() for v in vectors]
    
    # TF-IDF fallback: simple bag-of-words overlap scoring
    # Returns dummy vectors — real similarity done in retrieve_relevant_context
    return [[0.0] * 128 for _ in texts]


# ── ChromaDB collections ──────────────────────────────────────────────────────

_chroma_client = None
_collections: dict = {}
COLLECTION_NAMES = ["commits", "attack_paths", "guard_events", "sink_nodes"]
CHROMA_PATH = os.getenv("CHROMA_DB_PATH", "/tmp/vulngraph_chroma")

def _get_chroma():
    global _chroma_client
    if _chroma_client is None:
        try:
            import chromadb
            _chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
            print(f"[RAG] ChromaDB initialized at {CHROMA_PATH}")
        except Exception as e:
            print(f"[RAG] ChromaDB failed: {e}. Using in-memory fallback.")
            try:
                import chromadb
                _chroma_client = chromadb.Client()
            except Exception:
                _chroma_client = None
    return _chroma_client

def _get_collection(name: str):
    client = _get_chroma()
    if client is None:
        return None
    if name not in _collections:
        try:
            _collections[name] = client.get_or_create_collection(
                name=f"tdra_{name}",
                metadata={"hnsw:space": "cosine"}
            )
        except Exception as e:
            print(f"[RAG] Collection {name} error: {e}")
            return None
    return _collections[name]


# ── In-memory fallback store ──────────────────────────────────────────────────

_fallback_docs: list[dict] = []

def _fallback_search(query: str, n: int = 5) -> list[dict]:
    """TF-IDF-style term overlap search for fallback mode."""
    query_terms = set(query.lower().split())
    scored = []
    for doc in _fallback_docs:
        text = doc.get("text", "").lower()
        score = sum(1 for t in query_terms if t in text)
        if score > 0:
            scored.append((score, doc))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [d for _, d in scored[:n]]


# ── Main API: index + retrieve ────────────────────────────────────────────────

def index_tdra_findings(documents: list[dict]) -> dict:
    """
    Index all TDRA documents into ChromaDB.
    documents is the output of tdra_rag_documents.build_all_documents().
    Each doc has: {"text": str, "metadata": dict}
    """
    global _fallback_docs
    _fallback_docs = documents  # always populate fallback

    client = _get_chroma()
    if client is None:
        return {"indexed": len(documents), "mode": "fallback",
                "embed_mode": "tfidf"}

    # Group by doc_type → collection
    by_type: dict[str, list] = {n: [] for n in COLLECTION_NAMES}
    type_map = {
        "commit": "commits",
        "attack_path": "attack_paths",
        "guard_event": "guard_events",
        "sink_node": "sink_nodes",
    }
    for doc in documents:
        coll_name = type_map.get(doc["metadata"].get("doc_type", ""), "sink_nodes")
        by_type[coll_name].append(doc)

    total_indexed = 0
    for coll_name, docs in by_type.items():
        if not docs:
            continue
        collection = _get_collection(coll_name)
        if collection is None:
            continue

        texts = [d["text"] for d in docs]
        ids   = [hashlib.md5(t.encode()).hexdigest() for t in texts]
        metas = [d["metadata"] for d in docs]

        try:
            embeddings = embed_texts(texts)
            collection.upsert(
                documents=texts,
                embeddings=embeddings,
                metadatas=metas,
                ids=ids,
            )
            total_indexed += len(docs)
        except Exception as e:
            print(f"[RAG] Index error in {coll_name}: {e}")

    return {"indexed": total_indexed, "mode": "chromadb",
            "embed_mode": _embed_mode,
            "collections": {k: len(v) for k, v in by_type.items()}}


def retrieve_relevant_context(
    query: str,
    n_results: int = 5,
    severity_filter: Optional[str] = None,
    doc_types: Optional[list[str]] = None,
) -> list[dict]:
    """
    Retrieve the most semantically relevant TDRA documents for a query.
    Returns list of {text, metadata, score, collection} dicts.
    """
    client = _get_chroma()
    
    if client is None:
        # Fallback to TF-IDF in-memory search
        results = _fallback_search(query, n=n_results * 2)
        return [{"text": d["text"], "metadata": d.get("metadata", {}),
                 "score": 1.0, "collection": "fallback"}
                for d in results[:n_results]]

    type_to_coll = {
        "commit": "commits",
        "attack_path": "attack_paths",
        "guard_event": "guard_events",
        "sink_node": "sink_nodes",
    }
    
    target_colls = (
        [type_to_coll[t] for t in doc_types if t in type_to_coll]
        if doc_types else COLLECTION_NAMES
    )

    query_embedding = embed_texts([query])[0]

    all_results = []
    for coll_name in target_colls:
        collection = _get_collection(coll_name)
        if collection is None:
            continue
        
        where = {}
        if severity_filter:
            where["severity"] = {"$eq": severity_filter}
        
        try:
            r = collection.query(
                query_embeddings=[query_embedding],
                n_results=min(n_results, collection.count() or 1),
                where=where if where else None,
                include=["documents", "metadatas", "distances"],
            )
            for doc, meta, dist in zip(
                r["documents"][0],
                r["metadatas"][0],
                r["distances"][0]
            ):
                all_results.append({
                    "text": doc,
                    "metadata": meta,
                    "score": 1.0 - dist,  # cosine: distance → similarity
                    "collection": coll_name,
                })
        except Exception as e:
            print(f"[RAG] Query error in {coll_name}: {e}")

    # Sort by score descending, deduplicate by text hash
    seen = set()
    deduped = []
    for r in sorted(all_results, key=lambda x: x["score"], reverse=True):
        h = hashlib.md5(r["text"].encode()).hexdigest()
        if h not in seen:
            seen.add(h)
            deduped.append(r)

    return deduped[:n_results]


def build_tdra_context_block(results: list[dict]) -> str:
    """
    Format retrieved documents into a structured context block
    for injection into the LLM system prompt.
    """
    if not results:
        return "No relevant TDRA findings retrieved for this query."

    lines = ["=== TDRA SECURITY EVIDENCE (DETERMINISTICALLY PROVEN) ===\n"]
    for i, r in enumerate(results, 1):
        meta = r["metadata"]
        dtype = meta.get("doc_type", "finding")
        score = r["score"]
        lines.append(f"[{i}] {dtype.upper()} (relevance: {score:.2f})")
        lines.append(r["text"])
        lines.append("")

    lines.append("=== END OF EVIDENCE ===")
    lines.append("The above findings were computed by the TDRA graph engine.")
    lines.append("Explain only what the evidence shows. Do not infer or speculate beyond it.")
    return "\n".join(lines)
