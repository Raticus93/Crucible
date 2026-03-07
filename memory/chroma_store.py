"""
Crucible ChromaDB memory layer.

Four focused collections:
  1. environment_constraints — what packages are/aren't available in sandbox
  2. error_fix_patterns      — error type → reliable fix approach
  3. user_preferences        — user-confirmed coding style/library choices
  4. working_templates       — proven-good code patterns for common tasks

All collections use the same underlying ChromaDB client (one PersistentClient).
Retrieval injects the top N lessons as explicit instructions before every model prompt.
"""

import hashlib
import os
import time
from pathlib import Path
from typing import Dict, List, Optional

import chromadb
from chromadb.utils import embedding_functions
from dotenv import load_dotenv

load_dotenv()

CHROMA_PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIR", "./chroma_db")
SOUL_PATH = Path(__file__).parent.parent / "SOUL.md"

_COLLECTIONS = [
    "environment_constraints",
    "error_fix_patterns",
    "user_preferences",
    "working_templates",
]

_client: Optional[chromadb.PersistentClient] = None
_collections: Dict[str, any] = {}


def _get_client() -> chromadb.PersistentClient:
    global _client
    if _client is None:
        _client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)
    return _client


def _get_collection(name: str):
    global _collections
    if name not in _collections:
        ef = embedding_functions.DefaultEmbeddingFunction()
        _collections[name] = _get_client().get_or_create_collection(
            name=name,
            embedding_function=ef,
            metadata={"description": f"Crucible {name} memory"},
        )
    return _collections[name]


def retrieve_lessons(
    query: str,
    n_results: int = 5,
    collection: str = "error_fix_patterns",
) -> List[str]:
    """
    Query a collection for the top N most relevant lessons.
    Returns an empty list if the collection has no documents.
    """
    col = _get_collection(collection)
    count = col.count()
    if count == 0:
        return []
    n = min(n_results, count)
    results = col.query(query_texts=[query], n_results=n)
    docs = results.get("documents", [[]])
    return docs[0] if docs else []


def retrieve_all_relevant(query: str, n_per_collection: int = 2) -> List[str]:
    """
    Query all four collections and return a unified ranked list.
    Useful for injecting a broad lesson set before code generation.
    """
    all_lessons = []
    for col_name in _COLLECTIONS:
        all_lessons.extend(retrieve_lessons(query, n_per_collection, col_name))
    return all_lessons


def save_lesson(
    lesson: str,
    metadata: Optional[dict] = None,
    collection: str = "error_fix_patterns",
) -> None:
    """
    Persist a lesson to the named collection.
    Deduplication is approximate — uses content-hash + timestamp ID.
    """
    # Override collection from metadata if present
    if metadata and "collection" in metadata:
        collection = metadata["collection"]

    col = _get_collection(collection)
    lesson_id = hashlib.md5(f"{lesson}{time.time()}".encode()).hexdigest()
    col.add(
        documents=[lesson],
        ids=[lesson_id],
        metadatas=[metadata or {"source": "crucible", "timestamp": str(time.time())}],
    )


def read_soul() -> str:
    """Return SOUL.md content (Crucible's immutable constraints)."""
    try:
        return SOUL_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        return (
            "SOUL.md not found. Defaults: sandbox all code, never write to host, "
            "never pass credentials through model prompts."
        )
