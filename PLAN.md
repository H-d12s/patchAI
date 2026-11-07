# PatchAI: status and plan

Read [README.md](README.md) first. This file says what is built, what is left, and who does what.

## Status

| Part | Status | Where |
| --- | --- | --- |
| Scanning (Bandit + our Semgrep taint rules) | ✅ Done, tested | `patchai/scan.py`, `data/semgrep_rules.yaml` |
| Code context (ast) | ✅ Done, tested | `patchai/context.py` |
| RAG: 7 guides, 35 past fixes, code index, hybrid search, reranker | ✅ Done, tested | `patchai/rag_*.py`, `patchai/embeddings.py`, `data/` |
| Prompt, model client, fix-and-retry loop | ✅ Done, tested with a scripted model | `patchai/prompts.py`, `llm.py`, `fixer.py` |
| Safety guard, tests, attack test, re-scan | ✅ Done, tested | `patchai/guard.py`, `checks.py` |
| Human review + decisions log | ✅ Done, tested | `patchai/review.py` |
| Review app (Streamlit) | ✅ Built | `app/review_app.py` |
| VS Code extension + local server | ✅ Built, compiles, server tested | `extension/`, `patchai/server.py` |
| Demo shop (7 vulnerabilities, tests, attack tests) | ✅ Done | `demo_projects/vuln_shop/` |
| Training data generator + dataset builder | ✅ Done, checked (all examples detected, every fix passes the scanners) | `training/synth.py`, `make_dataset.py` |
| SFT training, export, DPO scripts | ✅ Written, **not yet run** (needs the GPU) | `training/train.py`, `export.py`, `dpo.py` |
| Benchmark (validated cases) | ✅ Generated | `eval/cases/` |
| Evaluation runner + charts | ✅ Written, charts checked | `eval/run_eval.py`, `report.py` |
| **Model trained** | ⬜ To do | 4060 laptop |
| **Evaluation run with real models** | ⬜ To do | needs Ollama + the trained model |
| **Report, slides, demo rehearsal** | ⬜ To do | |

## What is left, in order

1. **Everyone (day 1):** set up the project (README → Quick start), run `patchai doctor` and `python -m pytest`, try the review app with `qwen2.5-coder:3b`. Read the files you own until you can explain them.
2. **Training (days 1–5):** on the 4060 laptop, follow `training/README.md`: build the dataset, train, export to Ollama as `patchai-3b`. Plan for 2 training runs.
3. **Smoke test (day 3):** `python eval/run_eval.py --split dev --limit 3 --run-name smoke` with the base model, to check the whole evaluation loop on a real model.
4. **Prompt check (days 3–5):** run the dev cases with the base model and read the failures in `eval/results/smoke/full/`. Prompt changes must happen **before** the final training run, because the model is trained on the prompt format.
5. **Evaluation (days 6–8):** `python eval/run_eval.py --run-name final`, then `python eval/report.py --run final`. Split models across laptops if it's slow.
6. **Bonus DPO (days 6–9, only if training went smoothly):** `training/dpo.py`, then add `patchai-3b-dpo` to the evaluation.
7. **Report and demo (days 9–14):** charts from `eval/results/final/`, loss curve from `training/runs/sft/loss.png`, the demo script in the README, and a backup screen recording.

## Team split

| Person | Owns | Explains in the viva |
| --- | --- | --- |
| **A: Training** (the 4060 owner) | `training/*`: dataset, SFT, export, DPO | How the model was trained, the data, the loss curves |
| **B: RAG** | `rag_index.py`, `rag_search.py`, `embeddings.py`, `data/knowledge/`, `data/fix_examples/` | Chunking, hybrid search, rank fusion, reranking |
| **C: Model and fixing** | `prompts.py`, `llm.py`, `fixer.py`, `patching.py`, `pipeline.py` | Prompt design, structured output, the retry loop |
| **D: Detection and checks** | `scan.py`, `context.py`, `guard.py`, `checks.py`, `data/semgrep_rules.yaml`, `demo_projects/` | Scanners, taint rules, the guard, attack tests, fake fixes |
| **E: Interface and evaluation** | `app/`, `extension/`, `server.py`, `review.py`, `eval/`, `metrics.py` | The review flow, the benchmark, the results |

**A and C must agree before the final training run:** the model learns the exact prompt in `prompts.py`.

## Design decisions (and why)

| Decision | Why |
| --- | --- |
| The model returns the whole fixed function, not a diff | Small models often write broken diffs. We splice the function back in and compute the diff ourselves |
| Structured JSON output (enforced by Ollama) | The pipeline can always read the answer. "Unreadable answer" is still measured, because the prompt also asks for it |
| Checks run on a temporary copy | The real project is only changed by `review.approve()` |
| An attack test per vulnerability, plus the re-scan | A scanner can be fooled ("fake fix"); a working attack can't |
| Vectors stored as NumPy files, not a vector database | A few thousand chunks need no server; it's simpler and fully offline |
| fastembed (ONNX) for embeddings and reranking | Real models without PyTorch on every laptop; falls back to an offline embedder |
| Our own Semgrep taint rules for CWE-22 and CWE-79 | Bandit can't see path traversal or reflected XSS; the rules are short and explainable |
| Training templates ≠ evaluation templates | The test measures learning the vulnerability type, not memorising templates |
| DPO pairs = the correct fix vs the model's own failed fix | The "rejected" side is exactly the mistakes the model really makes |
| No servers, databases, queues or cloud | It's a local research prototype; infrastructure adds work but nothing to measure |

## Rules

See [AGENTS.md](AGENTS.md) (for people and AI coding tools alike).
