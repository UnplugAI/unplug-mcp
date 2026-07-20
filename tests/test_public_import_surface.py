"""Regression: production code must not import private unplug paths."""

from __future__ import annotations

import ast
from pathlib import Path

_FORBIDDEN_PREFIXES = (
    "unplug.core",
    "unplug.ml",
    "unplug.scanners",
    "unplug.pipelines",
    "unplug.models",
)

_SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "unplug_mcp"


def _module_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Import):
        return node.names[0].name
    if isinstance(node, ast.ImportFrom) and node.module:
        return node.module
    return None


def _collect_imports(path: Path) -> list[tuple[str, int]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    hits: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        mod = _module_name(node)
        if mod is None:
            continue
        if any(mod == prefix or mod.startswith(f"{prefix}.") for prefix in _FORBIDDEN_PREFIXES):
            hits.append((mod, node.lineno))
    return hits


def test_production_code_uses_only_public_unplug_imports() -> None:
    violations: list[str] = []
    for path in sorted(_SRC_ROOT.rglob("*.py")):
        for mod, lineno in _collect_imports(path):
            rel = path.relative_to(_SRC_ROOT.parent.parent)
            violations.append(f"{rel}:{lineno}: {mod}")
    assert not violations, "Private unplug imports found:\n" + "\n".join(violations)
