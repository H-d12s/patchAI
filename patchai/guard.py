"""Step 4a: fast safety checks on a proposed fix, before any code runs.

The guard catches the typical mistakes of AI-written patches: syntax errors, imports of
packages that don't exist (hallucinations), dangerous calls, comments that silence the
scanner, changing the function's signature, and edits that are far too large.
"""

from __future__ import annotations

import ast
import importlib.util
import re
import sys
import textwrap
from collections import Counter
from pathlib import Path

from patchai.config import get_config
from patchai.models import CheckResult, CodeContext, FixProposal
from patchai.patching import PatchedFile, changed_line_count, make_diff

# Calls a security fix must never add.
DANGEROUS_CALLS = {
    "eval", "exec", "compile", "__import__",
    "os.system", "os.popen", "pickle.loads", "pickle.load", "marshal.loads",
    "yaml.load", "yaml.unsafe_load", "subprocess.getoutput", "subprocess.getstatusoutput",
}
SUPPRESSION = re.compile(r"#.*\b(nosec|nosemgrep|noqa|type:\s*ignore)\b", re.IGNORECASE)


def check_fix(original_text: str, patched: PatchedFile, proposal: FixProposal,
              context: CodeContext, project_dir: str | Path) -> CheckResult:
    """Run every guard rule. The fix passes only if no rule is broken."""
    problems: list[str] = []
    old_region = context.source.replace("\r\n", "\n")
    new_lines = patched.text.splitlines()
    new_region = "\n".join(new_lines[patched.start_line - 1: patched.end_line])

    # 1. The fix must change something.
    if textwrap.dedent(old_region).strip() == textwrap.dedent(new_region).strip():
        problems.append("The fix does not change the code.")

    # 2. The patched file must still be valid Python.
    try:
        new_tree = ast.parse(patched.text)
    except SyntaxError as e:
        problems.append(f"Syntax error on line {e.lineno}: {e.msg}.")
        return _result(problems)

    # 3. The patch must stay small.
    limit = get_config()["guard"]["max_changed_lines"]
    changed = changed_line_count(make_diff(original_text, patched.text, context.file_path))
    if changed > limit:
        problems.append(f"The fix changes {changed} lines; the limit is {limit}. Make a smaller change.")

    # 4. The function keeps its name and parameters.
    if context.function_name:
        old_sig = _signature(ast.parse(textwrap.dedent(old_region)), context.function_name)
        new_sig = _signature(ast.parse(textwrap.dedent(new_region)), context.function_name)
        if new_sig is None:
            problems.append(f"The fixed code no longer defines `{context.function_name}`.")
        elif old_sig is not None and new_sig != old_sig:
            problems.append(f"The parameters of `{context.function_name}` changed from {old_sig} to {new_sig}. Keep the same signature.")

    # 5. No new dangerous calls or shell=True.
    old_calls = _dangerous_calls(ast.parse(textwrap.dedent(old_region)))
    new_calls = _dangerous_calls(ast.parse(textwrap.dedent(new_region)))
    for call, count in (new_calls - old_calls).items():
        problems.append(f"The fix adds a dangerous call: {call} (x{count}).")

    # 6. No comments that silence the scanner.
    old_suppressions = len(SUPPRESSION.findall(old_region))
    if len(SUPPRESSION.findall(new_region)) > old_suppressions:
        problems.append("The fix adds a comment that silences the scanner (e.g. `# nosec`). Fix the code instead.")

    # 7. Every import must exist (catches hallucinated packages).
    for module in _new_imported_modules(original_text, new_tree):
        if not _module_exists(module, Path(project_dir), context.file_path):
            problems.append(f"The fix imports `{module}`, which is not installed. Use the standard library or existing imports.")

    return _result(problems)


def _result(problems: list[str]) -> CheckResult:
    if problems:
        return CheckResult(name="guard", passed=False, details=" ".join(problems))
    return CheckResult(name="guard", passed=True, details="All safety rules passed.")


def _signature(tree: ast.AST, name: str) -> list[str] | None:
    """Parameter names of function `name` in a piece of code."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            a = node.args
            params = [p.arg for p in a.posonlyargs + a.args + a.kwonlyargs]
            if a.vararg:
                params.append("*" + a.vararg.arg)
            if a.kwarg:
                params.append("**" + a.kwarg.arg)
            return params
    return None


def _dangerous_calls(tree: ast.AST) -> Counter[str]:
    """Count dangerous calls (and shell=True arguments) in a piece of code."""
    found: Counter[str] = Counter()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted_name(node.func)
        if name in DANGEROUS_CALLS:
            found[name] += 1
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                found["shell=True"] += 1
    return found


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted_name(node.value)}.{node.attr}"
    return ""


def _new_imported_modules(original_text: str, new_tree: ast.AST) -> set[str]:
    """Top-level module names imported by the new file but not by the old one."""
    return _imported_modules(new_tree) - _imported_modules(ast.parse(original_text))


def _imported_modules(tree: ast.AST) -> set[str]:
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module.split(".")[0])
    return modules


def _module_exists(module: str, project_dir: Path, file_path: str) -> bool:
    """True if a module is in the standard library, installed, or part of the project."""
    if module in sys.stdlib_module_names:
        return True
    if (project_dir / module).is_dir() or (project_dir / f"{module}.py").exists():
        return True
    folder = (project_dir / file_path).parent
    if (folder / module).is_dir() or (folder / f"{module}.py").exists():
        return True
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False
