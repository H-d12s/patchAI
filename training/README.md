# Training our model (patchai-3b)

We fine-tune **Qwen2.5-Coder-3B-Instruct** to do one job well: rewrite a vulnerable function into a small, correct, secure fix, in our exact JSON format.

```
synth.py ─▶ make_dataset.py ─▶ train.py (SFT) ─▶ export.py ─▶ Ollama: patchai-3b
                                    │
                                    └─▶ dpo.py collect ─▶ dpo.py train ─▶ export.py ─▶ patchai-3b-dpo   (bonus)
```

| File | What it does | Where it runs |
| --- | --- | --- |
| `synth.py` | Generates pairs of vulnerable code and its correct fix (20 code patterns × random names and styles, plus some false alarms) | any laptop |
| `make_dataset.py` | Scans each pair with the real scanners, builds the real prompt (with RAG), writes `data/training/train.jsonl` + `val.jsonl` | any laptop |
| `train.py` | QLoRA supervised fine-tuning | GPU laptop |
| `export.py` | Converts the trained model and registers it in Ollama | GPU laptop (or demo laptop with a .gguf) |
| `dpo.py` | Bonus: the model writes fixes, our checks mark the bad ones, the model learns to avoid them | GPU laptop |

## Step by step (on the RTX 4060 laptop)

Use **WSL2 with Ubuntu** on Windows (Unsloth and GGUF export are much easier on Linux). Google Colab (free T4 GPU) also works.

```bash
# 1. Setup
python -m venv .venv && source .venv/bin/activate
pip install torch --index-url https://download.pytorch.org/whl/cu124
pip install -r requirements.txt -r requirements-train.txt
pip install -e .

# 2. Build the dataset (about 10–20 minutes; the reranker downloads once)
python training/make_dataset.py --n 2500

# 3. Fine-tune (about 1–2 hours on a 4060)
python training/train.py
#   Out of memory?  python training/train.py --batch-size 1 --grad-accum 16
#   Still too big?  python training/train.py --base-model unsloth/Qwen2.5-Coder-1.5B-Instruct

# 4. Put it into Ollama
ollama pull qwen2.5-coder:3b         # only used to copy the chat template
python training/export.py --run training/runs/sft --name patchai-3b
#   If GGUF conversion fails:  python training/export.py --run training/runs/sft --name patchai-3b --merged

# 5. Check it
ollama run patchai-3b "hello"
patchai fix demo_projects/vuln_shop --model patchai-3b
```

### Moving the model to the demo laptop

Copy the `.gguf` file from `training/runs/sft/gguf/` to the demo laptop, then:

```bash
python training/export.py --gguf path/to/model.Q4_K_M.gguf --name patchai-3b
```

## Bonus: DPO (learning from its own mistakes)

Only after `patchai-3b` works:

```bash
python training/dpo.py collect --n 400     # 2–3 hours: 4 fixes per case, each one checked
python training/dpo.py train               # about 1 hour
python training/export.py --run training/runs/dpo --name patchai-3b-dpo
```

`collect` uses **new** training cases (a different random seed, never test cases). Every fix the model gets wrong (broken JSON, blocked by the safety guard, or still flagged by the scanner) becomes a "rejected" answer, paired with the correct fix as "chosen". DPO then teaches the model to prefer the chosen answers over its own typical mistakes.

## What to put in the report

- `data/training/dataset_info.json`: dataset size, examples per vulnerability type and per code pattern, retries, false alarms
- `training/runs/sft/loss.png`: the training and validation loss curves
- `training/runs/sft/manifest.json`: every setting and the dataset hashes (reproducibility)
- `data/training/dpo_info.json`: how often the SFT model's own fixes passed or failed each check

## Keeping the evaluation fair

- The training code patterns (`synth.py`) and the evaluation code patterns (`eval/make_cases.py`) are **different**. The test measures whether the model learned to fix the vulnerability type, not whether it memorised our templates.
- The demo shop is never used for training.
- DPO never sees test cases.
- The past fixes in `data/fix_examples/` are only used by RAG, never as training answers.

## Settings and why

| Setting | Value | Why |
| --- | --- | --- |
| Method | QLoRA (4-bit base + LoRA rank 16) | Fits a 3B model in 8 GB of VRAM |
| Max length | 4096 tokens | Our prompts are about 2,000 tokens including RAG context |
| Epochs | 2 | Enough for format and patterns; more risks memorising templates |
| Learning rate | 2e-4 (SFT), 5e-6 (DPO) | Standard values for LoRA fine-tuning and DPO |
| Loss | Answer tokens only | The model learns to write fixes, not to repeat prompts |
