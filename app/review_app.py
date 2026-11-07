"""PatchAI review app (step 5: the human decision).

Run:  streamlit run app/review_app.py

Tabs:
  Fix          scan a project, fix a vulnerability, see the evidence, approve or reject
  Compare      run the same vulnerability through several models side by side
  Results      charts from the evaluation (eval/run_eval.py)
  Decisions    every approve / reject recorded so far
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from patchai import llm, metrics, review  # noqa: E402
from patchai.config import get_config  # noqa: E402
from patchai.context import get_context  # noqa: E402
from patchai.models import CWE_NAMES, Finding, FixResult, cwe_name  # noqa: E402
from patchai.pipeline import fix_finding, scan_project  # noqa: E402

st.set_page_config(page_title="PatchAI", page_icon="🛡️", layout="wide")

CHECK_LABELS = {
    "format": "Valid answer",
    "guard": "Safety guard",
    "tests": "Project tests",
    "security_test": "Security test (attack)",
    "rescan": "Re-scan",
}
SOURCE_LABELS = {"guide": "📘 Security guide", "code": "🧩 Project code", "past_fix": "🩹 Similar past fix"}
VERDICT_STYLE = {
    "fixed": ("success", "✅ Fixed and verified"),
    "failed": ("error", "❌ Not fixed: no attempt passed every check"),
    "cannot_fix": ("warning", "🤷 The model said it cannot fix this safely"),
    "false_positive": ("info", "🔎 The model thinks this is a false alarm"),
}
SEVERITY_ICON = {"high": "🔴", "medium": "🟠", "low": "🟡"}


# ---------------- sidebar ----------------

def sidebar() -> tuple[Path, str | None, str]:
    st.sidebar.title("🛡️ PatchAI")
    st.sidebar.caption("AI security fixes with a fine-tuned model + RAG. Nothing changes without your approval.")
    project = Path(st.sidebar.text_input("Project folder", str(ROOT / "demo_projects" / "vuln_shop")))

    installed = llm.list_models()
    if not installed:
        st.sidebar.error("Ollama is not running. Start it with `ollama serve`.")
        model = None
    else:
        default = get_config()["models"]["default"]
        options = sorted(installed, key=lambda m: (not m.startswith("patchai"), m))
        index = options.index(default) if default in options else 0
        model = st.sidebar.selectbox("Model", options, index=index,
                                     format_func=lambda m: f"{m} (ours, fine-tuned)" if m.startswith("patchai") else m)
    reviewer = st.sidebar.text_input("Reviewer name", value="reviewer")
    st.sidebar.divider()
    st.sidebar.markdown("**How it works**\n\n1. Scanner finds the bug\n2. RAG gathers guides, code, past fixes\n"
                        "3. Our model writes the fix\n4. Guard, tests, attack test, re-scan\n5. You approve or reject")
    return project, model, reviewer


# ---------------- shared pieces ----------------

def finding_label(f: Finding) -> str:
    return f"{SEVERITY_ICON[f.severity]} {f.cwe} {cwe_name(f.cwe)}  ·  {f.file_path}:{f.start_line}"


def run_fix(project: Path, finding: Finding, model: str | None) -> FixResult:
    """Run the pipeline and show live progress."""
    with st.status(f"Fixing {cwe_name(finding.cwe)} with {model}...", expanded=True) as status:
        def on_event(stage: str, message: str) -> None:
            status.write(f"**{stage}** · {message}")

        result = fix_finding(project, finding, model=model, on_event=on_event)
        state = "complete" if result.verdict == "fixed" else "error"
        status.update(label=f"Done in {result.seconds:.0f}s: {result.verdict}", state=state, expanded=False)
    return result


def show_checks(attempt) -> None:
    for c in attempt.checks:
        icon = "⏭️" if c.skipped else ("✅" if c.passed else "❌")
        st.markdown(f"{icon} **{CHECK_LABELS[c.name]}**: {c.details}")


def show_result(result: FixResult, compact: bool = False) -> None:
    """Verdict, explanation, diff, checks per attempt, and what RAG retrieved."""
    if result.error:
        st.error(result.error)
    kind, text = VERDICT_STYLE[result.verdict]
    getattr(st, kind)(f"{text}  ·  {result.model}  ·  {len(result.attempts)} attempt(s)  ·  {result.seconds:.0f}s")

    final = result.final
    if final and final.proposal:
        st.markdown(f"**Explanation:** {final.proposal.explanation or '-'}")
        st.progress(final.proposal.confidence, text=f"Model confidence: {final.proposal.confidence:.0%}")
    if result.diff:
        st.code(result.diff, language="diff")

    for attempt in result.attempts:
        ok = attempt.passed
        title = f"Attempt {attempt.number}: {'passed' if ok else 'failed'} ({attempt.seconds:.0f}s)"
        with st.expander(title, expanded=(attempt is final and not compact)):
            show_checks(attempt)
            if attempt is not final and attempt.diff:
                st.code(attempt.diff, language="diff")
            if attempt.proposal is None and attempt.raw_output:
                st.caption("Raw model output:")
                st.code(attempt.raw_output[:2000])

    if result.retrieved and not compact:
        st.subheader("What the AI read (RAG)")
        for source, label in SOURCE_LABELS.items():
            chunks = [c for c in result.retrieved if c.source == source]
            if not chunks:
                continue
            st.markdown(f"**{label}**")
            for c in chunks:
                with st.expander(f"{c.title}  ·  relevance {c.score:.2f}"):
                    st.code(c.text, language="python" if source != "guide" else "markdown")


# ---------------- tabs ----------------

def fix_tab(project: Path, model: str | None, reviewer: str) -> None:
    left, right = st.columns([3, 1])
    left.header("Find and fix vulnerabilities")
    if right.button("🔍 Scan project", type="primary", width="stretch"):
        with st.spinner("Running Bandit and Semgrep..."):
            st.session_state.findings = scan_project(project)
            st.session_state.results = {}

    findings: list[Finding] = st.session_state.get("findings", [])
    if not findings:
        st.info("Scan a project to see its vulnerabilities. The demo shop has one of each of the seven types.")
        return

    table = pd.DataFrame([{
        "Severity": f"{SEVERITY_ICON[f.severity]} {f.severity}", "Type": f"{f.cwe} {cwe_name(f.cwe)}",
        "File": f"{f.file_path}:{f.start_line}", "Scanner": f"{f.scanner} {f.rule_id}", "Message": f.message,
    } for f in findings])
    st.dataframe(table, hide_index=True, width="stretch")

    finding = st.selectbox("Choose a vulnerability", findings, format_func=finding_label)
    try:
        context = get_context(project, finding)
        st.caption(f"Code the AI may rewrite: `{context.function_name or 'statement'}` "
                   f"(lines {context.start_line}-{context.end_line}). Flagged line: `{finding.code.splitlines()[0].strip() if finding.code else ''}`")
        st.code(context.source, language="python", line_numbers=True)
    except Exception as e:
        st.warning(f"Could not read the code: {e}")

    results: dict[str, FixResult] = st.session_state.setdefault("results", {})
    if st.button("🛡️ Fix with AI", type="primary", disabled=model is None):
        results[finding.id] = run_fix(project, finding, model)

    result = results.get(finding.id)
    if result is None:
        return
    show_result(result)

    st.subheader("Your decision")
    if result.verdict == "fixed":
        approve_col, reject_col = st.columns(2)
        if approve_col.button("✅ Approve and apply", type="primary", width="stretch"):
            try:
                target = review.approve(project, result, reviewer)
                st.success(f"Applied to {target}. Rescanning...")
                st.session_state.findings = scan_project(project)
                del results[finding.id]
                st.rerun()
            except review.ApprovalError as e:
                st.error(str(e))
        with reject_col:
            reject_form(project, result, reviewer)
    else:
        st.caption("This fix was not verified, so it can't be applied. You can reject it with a reason, or try another model.")
        reject_form(project, result, reviewer)


def reject_form(project: Path, result: FixResult, reviewer: str) -> None:
    with st.form(f"reject-{result.finding.id}"):
        reason = st.selectbox("Reason", ["Wrong fix", "Breaks behaviour", "Too large a change",
                                         "Not a real vulnerability", "Other"])
        note = st.text_input("Details (optional)")
        if st.form_submit_button("❌ Reject"):
            review.reject(project, result, f"{reason}: {note}" if note else reason, reviewer)
            st.session_state.results.pop(result.finding.id, None)
            st.toast("Rejected and recorded.")
            st.rerun()


def compare_tab(project: Path) -> None:
    st.header("Compare models on the same vulnerability")
    findings: list[Finding] = st.session_state.get("findings", [])
    if not findings:
        st.info("Scan a project first (Fix tab).")
        return
    installed = llm.list_models()
    finding = st.selectbox("Vulnerability", findings, format_func=finding_label, key="compare_finding")
    wanted = [m for m in get_config()["models"]["compare"] if m in installed] or installed[:2]
    chosen = st.multiselect("Models", installed, default=wanted)
    if st.button("⚖️ Run comparison", type="primary", disabled=not chosen):
        st.session_state.comparison = [run_fix(project, finding, m) for m in chosen]
    comparison: list[FixResult] = st.session_state.get("comparison", [])
    if comparison:
        for column, result in zip(st.columns(len(comparison)), comparison):
            with column:
                st.markdown(f"### {result.model}")
                show_result(result, compact=True)


def results_tab() -> None:
    st.header("Evaluation results")
    files = sorted((ROOT / "eval" / "results").glob("*/results.jsonl"))
    if not files:
        st.info("No evaluation results yet. Run `python eval/run_eval.py` (see eval/README.md).")
        return
    run = st.selectbox("Evaluation run", files, format_func=lambda p: p.parent.name, index=len(files) - 1)
    records = [json.loads(line) for line in run.read_text(encoding="utf-8").splitlines() if line.strip()]
    summary = metrics.summarize(records)

    st.subheader("Fix rate per model")
    cols = st.columns(len(summary))
    for col, (model, s) in zip(cols, summary.items()):
        col.metric(model, f"{s['fix_rate']:.0%}", help=f"95% CI {s['fix_rate_low']:.0%}–{s['fix_rate_high']:.0%}, n={s['cases']}")
    st.bar_chart(pd.DataFrame({m: {"Fix rate": s["fix_rate"]} for m, s in summary.items()}).T)

    st.subheader("All measures")
    st.dataframe(pd.DataFrame(summary).T.style.format("{:.2f}"), width="stretch")

    st.subheader("Fix rate per vulnerability type")
    by_cwe = pd.DataFrame(metrics.fix_rate_by_cwe(records))
    by_cwe.index = [f"{c} {CWE_NAMES.get(c, '')}" for c in by_cwe.index]
    st.dataframe(by_cwe.style.format("{:.0%}").background_gradient(cmap="Greens", vmin=0, vmax=1), width="stretch")

    st.subheader("Why unfixed cases failed")
    st.dataframe(pd.DataFrame(metrics.failure_reasons(records)).fillna(0).astype(int), width="stretch")

    charts = sorted(run.parent.glob("*.png"))
    if charts:
        st.subheader("Report charts")
        for chart in charts:
            st.image(str(chart), caption=chart.stem)


def decisions_tab() -> None:
    st.header("Decisions log")
    decisions = review.load_decisions()
    if not decisions:
        st.info("No decisions yet.")
        return
    table = pd.DataFrame(decisions)[["time", "reviewer", "decision", "reason", "cwe", "file", "model", "attempts"]]
    st.dataframe(table.iloc[::-1], hide_index=True, width="stretch")


def main() -> None:
    project, model, reviewer = sidebar()
    fix, compare, results, decisions = st.tabs(["🛡️ Fix", "⚖️ Compare models", "📊 Results", "📜 Decisions"])
    with fix:
        fix_tab(project, model, reviewer)
    with compare:
        compare_tab(project)
    with results:
        results_tab()
    with decisions:
        decisions_tab()


main()
