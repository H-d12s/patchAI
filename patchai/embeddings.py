"""Text embeddings (for meaning-based search) and the reranker.

Real models run through fastembed (small ONNX models, no PyTorch or GPU needed; downloaded
once on first use). If they can't be loaded, a simple hashing embedder is used instead so
PatchAI still works offline. Tests use the hashing embedder via PATCHAI_EMBEDDER=hash.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import warnings
from functools import lru_cache

import numpy as np

from patchai.config import get_config

# Model downloads work fine without symlinks on Windows; hide Hugging Face's warning about it.
os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")


def tokenize(text: str) -> list[str]:
    """Split text into lowercase words; also splits snake_case and camelCase names."""
    words = re.findall(r"[A-Za-z][a-z0-9]*|[A-Z]+(?![a-z])|\d+", text)
    return [w.lower() for w in words if len(w) > 1]


class HashEmbedder:
    """Offline fallback: turns text into a vector by hashing its words (no model needed)."""

    name = "hash"
    dim = 512

    def embed(self, texts: list[str]) -> np.ndarray:
        vectors = np.zeros((len(texts), self.dim), dtype=np.float32)
        for row, text in enumerate(texts):
            for word in tokenize(text):
                bucket = int(hashlib.md5(word.encode(), usedforsecurity=False).hexdigest(), 16) % self.dim
                vectors[row, bucket] += 1.0
        return _normalize(vectors)


class FastEmbedder:
    """A real sentence-embedding model (default: BAAI/bge-small-en-v1.5) run with ONNX."""

    def __init__(self, model_name: str) -> None:
        from fastembed import TextEmbedding

        self.model = TextEmbedding(model_name=model_name)
        self.name = f"fastembed:{model_name}"

    def embed(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, 1), dtype=np.float32)
        return _normalize(np.array(list(self.model.embed(texts)), dtype=np.float32))


class Reranker:
    """A cross-encoder that reads (query, document) pairs together and scores how well they match."""

    def __init__(self, model_name: str) -> None:
        from fastembed.rerank.cross_encoder import TextCrossEncoder

        self.model = TextCrossEncoder(model_name=model_name)
        self.name = model_name

    def score(self, query: str, documents: list[str]) -> list[float]:
        """Relevance between 0 and 1 for each document."""
        logits = list(self.model.rerank(query, documents))
        return [1 / (1 + math.exp(-float(x))) for x in logits]


@lru_cache(maxsize=4)
def get_embedder(name: str | None = None):
    """The embedder named in config.yaml (or `name`), falling back to hashing if it can't load."""
    choice = name or os.environ.get("PATCHAI_EMBEDDER") or get_config()["rag"]["embedder"]
    if choice == "hash":
        return HashEmbedder()
    model_name = choice.split(":", 1)[1] if choice.startswith("fastembed:") else get_config()["rag"]["embedding_model"]
    try:
        return FastEmbedder(model_name)
    except Exception as e:  # missing package, no internet on first download, ...
        warnings.warn(f"Could not load embedding model {model_name} ({e}); using the hashing embedder.")
        return HashEmbedder()


@lru_cache(maxsize=1)
def get_reranker() -> Reranker | None:
    """The reranker from config.yaml, or None when it is turned off or can't load."""
    model_name = get_config()["rag"].get("reranker") or ""
    if not model_name or os.environ.get("PATCHAI_RERANKER", "").lower() in ("off", "0", "false"):
        return None
    try:
        return Reranker(model_name)
    except Exception as e:
        warnings.warn(f"Could not load reranker {model_name} ({e}); continuing without it.")
        return None


def _normalize(vectors: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    return vectors / np.where(norms == 0, 1, norms)
