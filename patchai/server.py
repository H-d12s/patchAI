"""A tiny local API so the VS Code extension can use the pipeline.

Run it with:  python -m uvicorn patchai.server:app --port 8765
It only listens on this computer. The only thing it remembers is the latest fix for each
finding, so that the reviewer's decision can be logged with the full details.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from patchai import llm, review
from patchai.config import get_config
from patchai.models import Finding, FixResult
from patchai.pipeline import fix_finding, scan_project

app = FastAPI(title="PatchAI local server")
_recent_fixes: dict[str, FixResult] = {}  # finding id -> latest FixResult


class ScanRequest(BaseModel):
    project_dir: str


class FixRequest(BaseModel):
    project_dir: str
    finding: Finding
    model: str | None = None


class DecisionRequest(BaseModel):
    project_dir: str
    finding_id: str
    decision: Literal["approved", "rejected"]
    reason: str | None = None
    model: str = ""


@app.get("/health")
def health() -> dict:
    models = llm.list_models()
    try:
        default = llm.resolve_model(None)
    except llm.LLMError:
        default = get_config()["models"]["default"]
    return {"ok": True, "models": models, "default_model": default}


@app.post("/scan")
def scan(request: ScanRequest) -> dict:
    project = _project(request.project_dir)
    return {"findings": [f.model_dump() for f in scan_project(project)]}


@app.post("/fix")
def fix(request: FixRequest) -> dict:
    project = _project(request.project_dir)
    result = fix_finding(project, request.finding, model=request.model or None)
    if result.error and not result.attempts:
        raise HTTPException(status_code=503, detail=result.error)
    _recent_fixes[request.finding.id] = result
    return result.model_dump()


@app.post("/decision")
def decision(request: DecisionRequest) -> dict:
    # The extension applies an accepted fix itself (so VS Code can undo it); we only record it.
    result = _recent_fixes.get(request.finding_id)
    if result is None:
        raise HTTPException(status_code=404, detail="No fix with that finding id was made by this server.")
    if request.decision == "rejected" and not (request.reason or "").strip():
        raise HTTPException(status_code=422, detail="A reason is required to reject a fix.")
    review.record_decision(request.project_dir, result, request.decision, request.reason)
    return {"ok": True}


def _project(project_dir: str) -> Path:
    project = Path(project_dir)
    if not project.is_dir():
        raise HTTPException(status_code=400, detail=f"Not a folder: {project_dir}")
    return project
