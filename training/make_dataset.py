"""Builds the fine-tuning dataset (data/training/train.jsonl and val.jsonl).

For every generated pair (training/synth.py):
  1. write the vulnerable file and run the real scanners on it   -> a real Finding
  2. extract the code region with patchai.context                 -> the same CodeContext as in real use
  3. retrieve guides and past fixes with patchai.rag_search       -> the same RAG context as in real use
  4. build the prompt with patchai.prompts.build_prompt           -> exactly the prompt the model will see
  5. the answer is the correct fix as FixProposal JSON
Examples the scanners don't detect are dropped, so every example matches a real finding.
About 15% of examples are "retries": the prompt contains an error from a failed attempt.

Run:  python training/make_dataset.py --n 2500
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import tempfile
import textwrap
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "training"))

from patchai.config import get_config  # noqa: E402
from patchai.context import get_context  # noqa: E402
from patchai.models import CodeContext, Finding, FixProposal, RetrievedChunk, cwe_name  # noqa: E402
from patchai.prompts import answer_json, build_prompt  # noqa: E402
from patchai.rag_index import knowledge_collections  # noqa: E402
from patchai.rag_search import search  # noqa: E402
from patchai.scan import scan  # noqa: E402
from synth import Pair, generate  # noqa: E402

OUT_DIR = ROOT / "data" / "training"

# Errors a previous attempt might have produced, used for the "retry" examples.
RETRY_ERRORS = [
    "The safety guard rejected the fix: The fix imports `securelib`, which is not installed. Use the standard library or existing imports.",
    "The safety guard rejected the fix: The fix adds a comment that silences the scanner (e.g. `# nosec`). Fix the code instead.",
    "[rescan] The scanner still reports {cwe} here: the vulnerable pattern is still present.",
    "[security_test] The vulnerability can still be exploited: security_tests::test_attack_is_blocked.",
    "[tests] Tests that now fail: tests::test_normal_use. 1 failed, 9 passed",
    "Your answer could not be read. The answer is not valid FixProposal JSON. Answer with JSON only.",
]


@dataclass
class Prepared:
    """A pair turned into a real finding, its context, the prompt and the correct answer."""

    pair: Pair
    folder: Path  # the folder holding this example's file
    finding: Finding
    context: CodeContext
    messages: list[dict]  # system + user prompt
    answer: FixProposal


def write_cases(pairs: list[Pair], root: Path) -> None:
    """Each pair becomes its own tiny project: root/<id>/module.py"""
    for pair in pairs:
        folder = root / pair.id
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "module.py").write_bytes(pair.module().encode("utf-8"))  # always \n line endings


def prepare(pairs: list[Pair], root: Path, seed: int, rerank: bool = True,
            retry_share: float = 0.15) -> tuple[list[Prepared], Counter]:
    """Scan every case once, then build each example's prompt exactly like the real pipeline."""
    r = random.Random(seed)
    knowledge = knowledge_collections()
    top_k = get_config()["rag"]["top_k"]
    stats: Counter = Counter()
    print(f"Scanning {len(pairs)} generated files (this takes a minute)...")
    by_case: dict[str, list[Finding]] = {}
    for f in scan(root):
        by_case.setdefault(f.file_path.split("/")[0], []).append(f)

    prepared = []
    for i, pair in enumerate(pairs):
        found = by_case.get(pair.id, [])
        matching = [f for f in found if f.cwe == pair.cwe] or (found if pair.status != "fixed" else [])
        if not matching:
            stats[f"dropped_not_detected:{pair.family}"] += 1
            continue
        folder = root / pair.id
        finding = matching[0].model_copy(update={"file_path": "module.py"})
        context = get_context(folder, finding)
        if textwrap.dedent(context.source.replace("\r\n", "\n")).strip() != pair.vulnerable.strip():
            stats[f"dropped_region_mismatch:{pair.family}"] += 1
            continue

        retrieved = retrieve_knowledge(knowledge, finding, context, top_k, rerank)
        if pair.helper and r.random() < 0.8:
            retrieved.insert(top_k["guide"], RetrievedChunk(source="code", title="module.py::helper",
                                                            text=pair.helper, file_path="module.py", score=1.0))
        error = None
        if pair.status == "fixed" and r.random() < retry_share:
            error = r.choice(RETRY_ERRORS).format(cwe=finding.cwe)
        answer = FixProposal(
            status=pair.status,
            fixed_code=pair.fixed if pair.status == "fixed" else "",
            imports_to_add=pair.fix_imports,
            explanation=pair.explanation,
            confidence=round(r.uniform(0.8, 0.95) if pair.status == "fixed" else r.uniform(0.6, 0.85), 2),
        )
        prepared.append(Prepared(pair, folder, finding, context, build_prompt(finding, context, retrieved, error), answer))
        stats[f"kept:{pair.cwe}"] += 1
        if (i + 1) % 250 == 0:
            print(f"  {i + 1}/{len(pairs)} prepared")
    return prepared, stats


def build(n: int, seed: int, val_share: float = 0.1, rerank: bool = True) -> dict:
    """Generate, prepare and save the SFT dataset."""
    pairs = generate(n, seed=seed)
    with tempfile.TemporaryDirectory() as tmp:
        write_cases(pairs, Path(tmp))
        prepared, stats = prepare(pairs, Path(tmp), seed, rerank)

    examples = [{
        "id": p.pair.id, "cwe": p.pair.cwe, "family": p.pair.family, "status": p.pair.status,
        "retry": "previous fix was rejected" in p.messages[-1]["content"],
        "messages": p.messages + [{"role": "assistant", "content": answer_json(p.answer)}],
    } for p in prepared]
    random.Random(seed).shuffle(examples)
    n_val = max(1, int(len(examples) * val_share))
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_jsonl(OUT_DIR / "val.jsonl", examples[:n_val])
    write_jsonl(OUT_DIR / "train.jsonl", examples[n_val:])
    chars = sorted(sum(len(m["content"]) for m in ex["messages"]) for ex in examples)
    info = {
        "generated": len(pairs), "kept": len(examples), "train": len(examples) - n_val, "val": n_val,
        "seed": seed, "approx_tokens_median": chars[len(chars) // 2] // 3 if chars else 0,
        "approx_tokens_max": chars[-1] // 3 if chars else 0,
        "by_cwe": dict(Counter(e["cwe"] for e in examples)),
        "by_family": dict(Counter(e["family"] for e in examples)),
        "retries": sum(e["retry"] for e in examples),
        "false_positives": sum(e["status"] == "false_positive" for e in examples),
        "dropped": {k: v for k, v in stats.items() if k.startswith("dropped")},
    }
    (OUT_DIR / "dataset_info.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
    return info


def retrieve_knowledge(knowledge, finding, context, top_k, rerank: bool) -> list[RetrievedChunk]:
    """The same guide and past-fix retrieval as patchai.rag_search.retrieve (no project code)."""
    same_type = lambda c: c.get("cwe") == finding.cwe  # noqa: E731
    guides = search(knowledge["guide"], "guide",
                    f"How to fix {cwe_name(finding.cwe)} ({finding.cwe}) in Python safely. {finding.message}",
                    top_k["guide"], where=same_type, rerank=rerank)
    past = search(knowledge["past_fix"], "past_fix", context.source, top_k["past_fix"], where=same_type, rerank=rerank)
    return guides + past


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--n", type=int, default=2500, help="how many pairs to generate")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--no-rerank", action="store_true", help="skip the reranker (faster)")
    args = parser.parse_args()
    print(json.dumps(build(args.n, args.seed, rerank=not args.no_rerank), indent=2))
