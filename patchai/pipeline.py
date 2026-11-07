"""Runs the whole pipeline for one finding: context -> RAG -> fix with checks -> result.

The review app, the VS Code extension, the CLI and the evaluation all call fix_finding().
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

from patchai import llm
from patchai.config import get_config
from patchai.context import get_context
from patchai.fixer import EventFn, fix
from patchai.models import Finding, FixResult
from patchai.rag_search import retrieve
from patchai.scan import scan


def scan_project(project_dir: str | Path) -> list[Finding]:
    """Step 1: every supported vulnerability in a project."""
    return scan(project_dir)


def fix_finding(project_dir: str | Path, finding: Finding, model: str | None = None,
                max_attempts: int | None = None, use_rag: bool = True,
                on_event: EventFn | None = None,
                chat_fn: Callable[..., llm.LLMReply] | None = None) -> FixResult:
    """Steps 2-4 for one finding. Never raises: problems are reported in FixResult.error."""
    started = time.perf_counter()
    emit = on_event or (lambda stage, message: None)
    max_attempts = max_attempts or get_config()["repair"]["max_attempts"]
    result = FixResult(finding=finding, model=model or "", verdict="failed")
    try:
        result.model = model if chat_fn else llm.resolve_model(model)

        emit("context", f"Reading `{finding.file_path}` around line {finding.start_line}")
        result.context = get_context(project_dir, finding)

        if use_rag:
            emit("retrieve", "Searching security guides, project code and past fixes")
            result.retrieved = retrieve(project_dir, finding, result.context)

        result.attempts = fix(project_dir, finding, result.context, result.retrieved, result.model,
                              max_attempts=max_attempts, on_event=emit, chat_fn=chat_fn)
    except Exception as e:  # model not running, unreadable file, ...
        result.error = str(e)
        emit("error", str(e))

    final = result.final
    if final is not None:
        result.diff = final.diff
        if final.passed:
            result.verdict = "fixed"
            result.patched_file_text = final.patched_file_text
        elif final.proposal is not None and final.proposal.status in ("cannot_fix", "false_positive"):
            result.verdict = final.proposal.status
    result.seconds = round(time.perf_counter() - started, 2)
    return result
