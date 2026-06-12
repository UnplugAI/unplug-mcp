"""MCP server exposing Unplug scanning tools."""

from __future__ import annotations

from typing import Any

from unplug.api.enums import Source
from unplug.api.types import ScanRequest

from unplug_mcp.boundary import (
    notify_taint_source as _notify_taint_source,
)
from unplug_mcp.boundary import (
    reset_session_taint as _reset_session_taint,
)
from unplug_mcp.boundary import (
    session_status,
)
from unplug_mcp.boundary import (
    wrap_untrusted_content as _wrap_untrusted_content,
)
from unplug_mcp.guard_factory import get_guard
from unplug_mcp.response import format_scan_response

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover
    msg = "Install mcp: uv sync"
    raise ImportError(msg) from exc

mcp = FastMCP("unplug")


def _track_session_taint(source: str | Source) -> bool:
    """Untrusted sources share Guard session state for side-effect review gates."""
    src = Source(source) if isinstance(source, str) else source
    return src in (Source.RETRIEVED, Source.TOOL_OUTPUT)


@mcp.tool()
def scan_text(
    text: str,
    source: str = "user",
    document_id: str | None = None,
    redact: bool = True,
) -> dict[str, Any]:
    """Scan user or retrieved text for prompt injection and related threats.

    Returns safe/action/risk_score, span findings with tags, and redacted_text
    (malicious spans replaced with [BLOCKED:category] when redact=true).
    """
    guard = get_guard()
    if document_id:
        guard.context.document_id = document_id
    request = ScanRequest(text=text, source=source, redact=redact, document_id=document_id)
    result = guard.scan_request(request, isolated=not _track_session_taint(source))
    body = format_scan_response(result, source_text=text)
    body["session"] = session_status()
    return body


@mcp.tool()
def scan_tool_result(text: str, redact: bool = True) -> dict[str, Any]:
    """Scan tool output before the agent processes it (source=tool_output)."""
    guard = get_guard()
    request = ScanRequest(text=text, source=Source.TOOL_OUTPUT, redact=redact)
    result = guard.scan_output_request(request, isolated=False)
    body = format_scan_response(result, source_text=text)
    body["session"] = session_status()
    return body


@mcp.tool()
def check_destructive(tool_name: str, arguments_json: str = "{}") -> dict[str, Any]:
    """Verify a proposed tool call is safe to execute."""
    import json

    args = json.loads(arguments_json) if arguments_json else {}
    result = get_guard().check_tool_call(tool_name, args)
    body = format_scan_response(result)
    body["session"] = session_status()
    return body


@mcp.tool()
def notify_taint_source(tool_name: str, origin: str = "") -> dict[str, Any]:
    """Mark session tainted after a taint-source tool (web_fetch, read_file, browser, …)."""
    return _notify_taint_source(tool_name, origin=origin)


@mcp.tool()
def reset_session_taint() -> dict[str, Any]:
    """Clear session taint after a trusted-only user turn."""
    return _reset_session_taint()


@mcp.tool()
def wrap_untrusted_content(
    text: str,
    source: str = "retrieved",
    sanitize: bool = True,
    scan: bool = True,
    redact: bool = True,
) -> dict[str, Any]:
    """Sanitize spoofed markers, scan, and wrap untrusted content for agent context."""
    return _wrap_untrusted_content(
        text,
        source=source,  # type: ignore[arg-type]
        sanitize=sanitize,
        scan=scan,
        redact=redact,
    )


def main() -> None:
    mcp.run()
