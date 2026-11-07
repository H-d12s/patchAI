"""Step 5: the human decision. A fix only reaches the real project through approve().

Every decision (approve or reject, who, when, why) is appended to data/decisions.jsonl,
so there is a record of which human accepted each AI change.
"""

from __future__ import annotations

import getpass
import json
from datetime import datetime, timezone
from pathlib import Path

from patchai.config import path
from patchai.models import FixResult
from patchai.patching import read_text, write_text


class ApprovalError(RuntimeError):
    """The fix can't be applied (not verified, or the file changed since it was made)."""


def approve(project_dir: str | Path, result: FixResult, reviewer: str | None = None) -> Path:
    """Write a verified fix into the real project and record the decision."""
    if result.verdict != "fixed" or result.patched_file_text is None:
        raise ApprovalError("Only fixes that passed every check can be applied.")
    target = Path(project_dir) / result.finding.file_path
    # Make sure nobody edited the file after the fix was generated.
    if result.context and result.context.source not in read_text(target):
        raise ApprovalError(f"{result.finding.file_path} changed since the fix was made. Run the fix again.")
    write_text(target, result.patched_file_text)
    record_decision(project_dir, result, "approved", None, reviewer)
    return target


def reject(project_dir: str | Path, result: FixResult, reason: str, reviewer: str | None = None) -> None:
    """Record that a reviewer rejected a fix, and why. Nothing in the project changes."""
    if not reason.strip():
        raise ApprovalError("A reason is required to reject a fix.")
    record_decision(project_dir, result, "rejected", reason, reviewer)


def record_decision(project_dir: str | Path, result: FixResult, decision: str,
                    reason: str | None, reviewer: str | None = None) -> None:
    """Append one decision to the decisions log."""
    log = path("decisions")
    log.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "reviewer": reviewer or getpass.getuser(),
        "decision": decision,
        "reason": reason,
        "project": str(Path(project_dir).resolve()),
        "file": result.finding.file_path,
        "cwe": result.finding.cwe,
        "finding_id": result.finding.id,
        "model": result.model,
        "verdict": result.verdict,
        "attempts": len(result.attempts),
        "diff": result.diff,
    }
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def load_decisions() -> list[dict]:
    """All recorded decisions, oldest first."""
    log = path("decisions")
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]
