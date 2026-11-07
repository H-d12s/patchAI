"""Step 2a: build the searchable collections RAG uses.

Three collections:
  guide     sections of the security guides in data/knowledge/*.md
  past_fix  examples of vulnerable code and its fix (data/fix_examples/examples.jsonl)
  code      every function in the project being fixed

Each collection keeps its chunks (as JSON) and their embedding vectors (as .npy) on disk.
Keyword search (BM25) is rebuilt in memory when loaded, which takes milliseconds.
When sources change, only new or changed chunks are embedded again.
"""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from rank_bm25 import BM25Okapi

from patchai.config import path
from patchai.embeddings import get_embedder, tokenize
from patchai.patching import read_text
from patchai.scan import SKIP_DIRS


@dataclass
class Collection:
    """Chunks of text plus their vectors, searchable by meaning and by keywords."""

    name: str
    chunks: list[dict]
    vectors: np.ndarray
    embedder: str
    fingerprint: str
    _bm25: BM25Okapi | None = field(default=None, repr=False)

    @property
    def bm25(self) -> BM25Okapi:
        if self._bm25 is None:
            self._bm25 = BM25Okapi([tokenize(c["title"] + " " + c["text"]) or ["_"] for c in self.chunks])
        return self._bm25

    def save(self, folder: Path) -> None:
        folder.mkdir(parents=True, exist_ok=True)
        meta = {"embedder": self.embedder, "fingerprint": self.fingerprint, "chunks": self.chunks}
        (folder / f"{self.name}.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
        np.save(folder / f"{self.name}.npy", self.vectors)

    @classmethod
    def load(cls, folder: Path, name: str) -> Collection | None:
        meta_file, vec_file = folder / f"{name}.json", folder / f"{name}.npy"
        if not meta_file.exists() or not vec_file.exists():
            return None
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        vectors = np.load(vec_file, allow_pickle=False)
        return cls(name, meta["chunks"], vectors, meta["embedder"], meta["fingerprint"])


# ---------- turning sources into chunks ----------

def chunk_guides(folder: Path) -> list[dict]:
    """One chunk per `## ` section of each guide file."""
    chunks = []
    for file in sorted(folder.glob("*.md")):
        text = file.read_text(encoding="utf-8")
        cwe = file.stem.upper()  # cwe-89.md -> CWE-89
        heading = next((line[2:].strip() for line in text.splitlines() if line.startswith("# ")), cwe)
        for section in text.split("\n## ")[1:]:
            title, _, body = section.partition("\n")
            chunks.append({"title": f"{heading}: {title.strip()}", "text": body.strip(), "cwe": cwe})
    return chunks


def chunk_past_fixes(file: Path) -> list[dict]:
    """One chunk per past fix: the vulnerable code, the fixed code and a short note."""
    chunks = []
    if not file.exists():
        return chunks
    for line in file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        ex = json.loads(line)
        text = f"Vulnerable:\n{ex['vulnerable']}\n\nFixed:\n{ex['fixed']}\n\nWhy: {ex['note']}"
        chunks.append({"title": f"Past fix: {ex['title']}", "text": text, "cwe": ex["cwe"]})
    return chunks


def chunk_code(project_dir: Path) -> list[dict]:
    """One chunk per function or method in the project (tests excluded)."""
    chunks = []
    for file in sorted(project_dir.rglob("*.py")):
        rel = file.relative_to(project_dir)
        if any(part in SKIP_DIRS or part.startswith(".") for part in rel.parts):
            continue
        text = read_text(file)
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        lines = text.splitlines()
        for name, node in _functions(tree):
            start = min([node.lineno] + [d.lineno for d in node.decorator_list])
            body = "\n".join(lines[start - 1: node.end_lineno])
            chunks.append({
                "title": f"{rel.as_posix()}::{name}", "text": body, "symbol": name.split(".")[-1],
                "file_path": rel.as_posix(), "start_line": start, "end_line": node.end_lineno,
            })
    return chunks


def _functions(tree: ast.AST, prefix: str = ""):
    """Yield (qualified name, node) for every function and method."""
    for node in getattr(tree, "body", []):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield prefix + node.name, node
        elif isinstance(node, ast.ClassDef):
            yield from _functions(node, prefix + node.name + ".")


# ---------- building and loading collections ----------

def build_collection(name: str, chunks: list[dict], folder: Path, embedder=None) -> Collection:
    """Embed the chunks (reusing vectors of unchanged chunks) and save the collection."""
    embedder = embedder or get_embedder()
    fingerprint = _add_ids(chunks)

    previous = Collection.load(folder, name)
    reuse = {}
    if previous is not None and previous.embedder == embedder.name:
        reuse = {c["id"]: previous.vectors[i] for i, c in enumerate(previous.chunks)}
    todo = [c for c in chunks if c["id"] not in reuse]
    fresh = embedder.embed([c["title"] + "\n" + c["text"] for c in todo]) if todo else []
    fresh_by_id = {c["id"]: fresh[i] for i, c in enumerate(todo)}

    if chunks:
        vectors = np.stack([reuse.get(c["id"], fresh_by_id.get(c["id"])) for c in chunks]).astype(np.float32)
    else:
        vectors = np.zeros((0, 1), dtype=np.float32)
    collection = Collection(name, chunks, vectors, embedder.name, fingerprint)
    collection.save(folder)
    return collection


def knowledge_collections() -> dict[str, Collection]:
    """The guide and past-fix collections, rebuilt only if their sources changed."""
    folder = path("index")
    sources = {
        "guide": chunk_guides(path("knowledge")),
        "past_fix": chunk_past_fixes(path("fix_examples")),
    }
    return {name: _load_or_build(name, chunks, folder) for name, chunks in sources.items()}


def code_collection(project_dir: str | Path) -> Collection:
    """The code collection for one project, kept under data/index/projects/<id>/."""
    project_dir = Path(project_dir).resolve()
    folder = path("index") / "projects" / hashlib.sha1(str(project_dir).encode()).hexdigest()[:12]
    return _load_or_build("code", chunk_code(project_dir), folder)


def build_index(project_dir: str | Path | None = None) -> dict[str, int]:
    """Build every collection and return how many chunks each has."""
    collections = knowledge_collections()
    if project_dir is not None:
        collections["code"] = code_collection(project_dir)
    return {name: len(c.chunks) for name, c in collections.items()}


def _add_ids(chunks: list[dict]) -> str:
    """Give each chunk an id from its content; return a fingerprint of the whole set."""
    for chunk in chunks:
        chunk["id"] = hashlib.sha1((chunk["title"] + "\n" + chunk["text"]).encode()).hexdigest()[:16]
    return hashlib.sha1("".join(c["id"] for c in chunks).encode()).hexdigest()


def _load_or_build(name: str, chunks: list[dict], folder: Path) -> Collection:
    """Load a saved collection if it is up to date, otherwise (re)build it."""
    embedder = get_embedder()
    fingerprint = _add_ids(chunks)
    existing = Collection.load(folder, name)
    if existing is not None and existing.fingerprint == fingerprint and existing.embedder == embedder.name:
        return existing
    return build_collection(name, chunks, folder, embedder)
