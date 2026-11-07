"""Shared data models. Every step of the pipeline passes these objects along."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# The seven vulnerability types PatchAI handles.
CWE_NAMES: dict[str, str] = {
    "CWE-89": "SQL injection",
    "CWE-78": "Command injection",
    "CWE-22": "Path traversal",
    "CWE-79": "Cross-site scripting (XSS)",
    "CWE-798": "Hard-coded secret",
    "CWE-327": "Weak cryptography",
    "CWE-502": "Unsafe deserialization",
}


def cwe_name(cwe: str | None) -> str:
    """Human-readable name for a CWE id, e.g. 'CWE-89' -> 'SQL injection'."""
    return CWE_NAMES.get(cwe or "", cwe or "Unknown vulnerability")


class Finding(BaseModel):
    """A vulnerability reported by a scanner."""

    id: str  # short hash of scanner rule + file + line
    scanner: str  # "bandit" or "semgrep"
    rule_id: str  # e.g. "B608"
    cwe: str | None  # e.g. "CWE-89"
    severity: Literal["low", "medium", "high"]
    file_path: str  # relative to the project folder, forward slashes
    start_line: int
    end_line: int
    message: str
    code: str = ""  # the flagged line(s), for display


class CodeContext(BaseModel):
    """The code region the model is allowed to rewrite (usually one whole function)."""

    file_path: str
    function_name: str | None  # None when the finding is outside any function
    start_line: int  # first line of the region (includes decorators)
    end_line: int
    source: str  # exact original text of the region
    indent: str  # leading whitespace of the region, e.g. "    " for a method
    imports: list[str] = Field(default_factory=list)  # the file's import lines
    calls: list[str] = Field(default_factory=list)  # names of functions the region calls


class RetrievedChunk(BaseModel):
    """One piece of information found by RAG."""

    source: Literal["guide", "code", "past_fix"]
    title: str
    text: str
    file_path: str | None = None
    score: float = 0.0


class FixProposal(BaseModel):
    """What the model returns (always this JSON shape)."""

    status: Literal["fixed", "cannot_fix", "false_positive"]
    fixed_code: str = ""  # the complete rewritten region (e.g. the whole fixed function)
    imports_to_add: list[str] = Field(default_factory=list)  # e.g. ["import subprocess"]
    explanation: str = ""
    confidence: float = Field(0.0, ge=0.0, le=1.0)


class CheckResult(BaseModel):
    """The result of one check on a proposed fix."""

    name: Literal["format", "guard", "tests", "security_test", "rescan"]
    passed: bool
    details: str = ""
    skipped: bool = False  # True when the check could not run (e.g. no security test exists)


class Attempt(BaseModel):
    """One try at fixing a finding: what the model said and how the checks went."""

    number: int
    proposal: FixProposal | None  # None when the model's answer could not be parsed
    raw_output: str = ""
    diff: str = ""
    patched_file_text: str | None = None
    checks: list[CheckResult] = Field(default_factory=list)
    seconds: float = 0.0
    tokens_in: int = 0
    tokens_out: int = 0

    @property
    def passed(self) -> bool:
        """True when the model proposed a fix and every check passed."""
        return (
            self.proposal is not None
            and self.proposal.status == "fixed"
            and bool(self.checks)
            and all(c.passed for c in self.checks)
        )


Verdict = Literal["fixed", "failed", "cannot_fix", "false_positive"]


class FixResult(BaseModel):
    """Everything about fixing one finding: context, retrieval, every attempt, the verdict."""

    finding: Finding
    model: str
    verdict: Verdict
    context: CodeContext | None = None
    retrieved: list[RetrievedChunk] = Field(default_factory=list)
    attempts: list[Attempt] = Field(default_factory=list)
    diff: str = ""  # diff of the final attempt
    patched_file_text: str | None = None  # full new file text, only when verdict == "fixed"
    seconds: float = 0.0
    error: str | None = None  # set when the pipeline itself failed (e.g. model not running)

    @property
    def final(self) -> Attempt | None:
        """The last attempt, which decides the verdict."""
        return self.attempts[-1] if self.attempts else None
