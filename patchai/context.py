"""Finds the code region around a finding (usually the whole function) using Python's ast module.

This region is what the model sees and the only part it is allowed to rewrite.
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from patchai.models import CodeContext, Finding
from patchai.patching import read_text


def get_context(project_dir: str | Path, finding: Finding) -> CodeContext:
    """Return the function (or statement) that contains the finding's line."""
    text = read_text(Path(project_dir) / finding.file_path)
    lines = text.splitlines(keepends=True)
    tree = ast.parse(text)

    node = _innermost_function(tree, finding.start_line)
    if node is not None:
        start = min([node.lineno] + [d.lineno for d in node.decorator_list])
        end = node.end_lineno or node.lineno
        name = node.name
    else:
        # Not inside a function (e.g. a module-level API_KEY = "..."): use the statement itself.
        stmt = _statement_at(tree, finding.start_line)
        start = stmt.lineno if stmt else finding.start_line
        end = (stmt.end_lineno or stmt.lineno) if stmt else finding.end_line
        name = None

    source = "".join(lines[start - 1:end])
    first_line = lines[start - 1]
    indent = first_line[: len(first_line) - len(first_line.lstrip())]
    return CodeContext(
        file_path=finding.file_path,
        function_name=name,
        start_line=start,
        end_line=end,
        source=source,
        indent=indent,
        imports=_imports(tree, text),
        calls=sorted(_called_names(ast.parse(textwrap.dedent(source)))),
    )


def _innermost_function(tree: ast.AST, line: int) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """The deepest function or method whose body covers `line`."""
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = min([node.lineno] + [d.lineno for d in node.decorator_list])
            if start <= line <= (node.end_lineno or node.lineno):
                if best is None or node.lineno > best.lineno:
                    best = node
    return best


def _statement_at(tree: ast.Module, line: int) -> ast.stmt | None:
    """The top-level statement that covers `line`."""
    for stmt in tree.body:
        if stmt.lineno <= line <= (stmt.end_lineno or stmt.lineno):
            return stmt
    return None


def _imports(tree: ast.Module, text: str) -> list[str]:
    """The file's top-level import lines, as written."""
    return [
        ast.get_source_segment(text, stmt) or ""
        for stmt in tree.body
        if isinstance(stmt, (ast.Import, ast.ImportFrom))
    ]


def _called_names(tree: ast.AST) -> set[str]:
    """Names of the functions called inside a piece of code (used to find helper functions)."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                names.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                names.add(node.func.attr)
    return names
