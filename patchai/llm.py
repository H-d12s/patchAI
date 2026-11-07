"""Talks to the local model server (Ollama). This is the only file that calls a model."""

from __future__ import annotations

import time
from dataclasses import dataclass

from patchai.config import get_config
from patchai.models import FixProposal


class LLMError(RuntimeError):
    """The model server is not reachable or the model is missing."""


@dataclass
class LLMReply:
    text: str
    model: str
    tokens_in: int
    tokens_out: int
    seconds: float


def _client():
    import ollama

    return ollama.Client(host=get_config()["ollama_url"])


def list_models() -> list[str]:
    """Names of the models installed in Ollama (empty if Ollama is not running)."""
    try:
        response = _client().list()
    except Exception:
        return []
    names = []
    for m in response.models:
        name = m.model or ""
        names.append(name.removesuffix(":latest"))
    return names


def resolve_model(name: str | None = None) -> str:
    """The model to use: the one asked for, else our fine-tuned model, else the first installed fallback."""
    cfg = get_config()["models"]
    installed = list_models()
    if not installed:
        raise LLMError("Ollama is not running. Install it from https://ollama.com and run `ollama serve`.")
    wanted = name or cfg["default"]
    if _is_installed(wanted, installed):
        return wanted
    if name:  # the caller asked for a specific model that isn't there
        raise LLMError(f"Model `{name}` is not installed. Run `ollama pull {name}`.")
    for fallback in cfg["fallbacks"]:
        if _is_installed(fallback, installed):
            return fallback
    raise LLMError(f"No model installed. Run `ollama pull {cfg['fallbacks'][0]}`.")


def chat(messages: list[dict], model: str, temperature: float | None = None) -> LLMReply:
    """Send a chat to the model. Its answer is forced to match the FixProposal JSON shape."""
    gen = get_config()["generation"]
    started = time.perf_counter()
    try:
        response = _client().chat(
            model=model,
            messages=messages,
            format=FixProposal.model_json_schema(),  # structured output: always valid JSON
            options={
                "temperature": gen["temperature"] if temperature is None else temperature,
                "num_ctx": gen["context_window"],
                "num_predict": gen["max_output_tokens"],
            },
        )
    except Exception as e:
        raise LLMError(f"The model call failed: {e}") from e
    return LLMReply(
        text=response.message.content or "",
        model=model,
        tokens_in=response.prompt_eval_count or 0,
        tokens_out=response.eval_count or 0,
        seconds=time.perf_counter() - started,
    )


def _is_installed(name: str, installed: list[str]) -> bool:
    return name.removesuffix(":latest") in installed
