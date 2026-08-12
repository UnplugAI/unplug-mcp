# Unplug MCP

MCP server exposing Unplug scanning as tools for LLM agents.

## Commands

```bash
uv sync --all-extras
uv run pytest -v
uv run ruff check . && uv run ruff format --check .
```

## Conventions

- Python 3.11+, uv, ruff, pytest
- `from __future__ import annotations` in every file
- SDK is a pip dependency (`unplug-ai>=0.5.2,<0.7`)
