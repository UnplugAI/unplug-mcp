"""MCP server exposing Unplug scanning tools."""

from __future__ import annotations

import os
from typing import Any

from mcp.server.fastmcp import FastMCP
from unplug import Guard

mcp = FastMCP("unplug")
_guard: Guard | None = None


def _get_guard() -> Guard:
    global _guard
    if _guard is None:
        mode = os.environ.get("UNPLUG_MODE", "local")
        _guard = Guard(
            mode=mode,
            server_url=os.environ.get("UNPLUG_SERVER_URL"),
            server_api_key=os.environ.get("UNPLUG_API_KEY"),
        )
    return _guard


@mcp.tool()
def scan_text(
    text: str,
    source: str = "user",
    document_id: str | None = None,
) -> dict[str, Any]:
    """Scan arbitrary text for prompt injection and related threats."""
    guard = _get_guard()
    if document_id:
        guard.context.document_id = document_id
    result = guard.scan(text, source=source)
    return {
        "safe": result.safe,
        "action": result.action.value,
        "risk_score": result.risk_score,
        "findings": [f.model_dump() for f in result.findings],
        "redacted_text": result.redacted_text,
    }


@mcp.tool()
def scan_tool_result(text: str) -> dict[str, Any]:
    """Scan tool output before the agent processes it."""
    result = _get_guard().scan_output(text)
    return {
        "safe": result.safe,
        "action": result.action.value,
        "risk_score": result.risk_score,
        "findings": [f.model_dump() for f in result.findings],
    }


@mcp.tool()
def check_destructive(tool_name: str, arguments_json: str = "{}") -> dict[str, Any]:
    """Verify a proposed tool call is safe to execute."""
    import json

    args = json.loads(arguments_json) if arguments_json else {}
    result = _get_guard().check_tool_call(tool_name, args)
    return {
        "safe": result.safe,
        "action": result.action.value,
        "risk_score": result.risk_score,
        "findings": [f.model_dump() for f in result.findings],
    }


def main() -> None:
    mcp.run()
