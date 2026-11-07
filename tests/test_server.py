"""The local API used by the VS Code extension (same contract as extension/src/api.ts)."""

from fastapi.testclient import TestClient
from reference_fixes import GOOD_FIXES

from patchai import server
from patchai.llm import LLMReply
from patchai.pipeline import fix_finding

client = TestClient(server.app)


def test_health_works_without_ollama():
    body = client.get("/health").json()
    assert body["ok"] is True and isinstance(body["models"], list) and body["default_model"]


def test_scan_returns_findings(shop):
    findings = client.post("/scan", json={"project_dir": str(shop)}).json()["findings"]
    assert {f["cwe"] for f in findings} == set(GOOD_FIXES)
    assert set(findings[0]) >= {"id", "scanner", "rule_id", "cwe", "severity", "file_path", "start_line", "end_line", "message"}


def test_scan_rejects_a_missing_folder(tmp_path):
    response = client.post("/scan", json={"project_dir": str(tmp_path / "nope")})
    assert response.status_code == 400 and "detail" in response.json()


def test_fix_and_decision(shop, shop_findings, monkeypatch):
    finding = next(f for f in shop_findings if f.cwe == "CWE-89")
    answer = GOOD_FIXES["CWE-89"].model_dump_json()

    def fake_fix(project, f, model=None):
        return fix_finding(project, f, model="fake", use_rag=False,
                           chat_fn=lambda m, model: LLMReply(answer, model, 0, 0, 0.0))

    monkeypatch.setattr(server, "fix_finding", fake_fix)
    body = client.post("/fix", json={"project_dir": str(shop), "finding": finding.model_dump(), "model": None}).json()
    assert body["verdict"] == "fixed" and body["patched_file_text"] and body["attempts"][0]["checks"]

    rejected = client.post("/decision", json={"project_dir": str(shop), "finding_id": finding.id,
                                              "decision": "rejected", "reason": "", "model": "fake"})
    assert rejected.status_code == 422  # a reason is required
    ok = client.post("/decision", json={"project_dir": str(shop), "finding_id": finding.id,
                                        "decision": "approved", "reason": None, "model": "fake"})
    assert ok.json() == {"ok": True}
