"""MCP server exposing Unplug scanning tools."""

from __future__ import annotations

import logging
from typing import Any

from unplug.api.enums import Action, Source
from unplug.api.types import Finding, ScanRequest, ScanResult

from unplug_mcp.boundary import (
    notify_taint_source as _notify_taint_source,
)
from unplug_mcp.boundary import (
    reset_session_taint as _reset_session_taint,
)
from unplug_mcp.boundary import (
    resolve_scan_source,
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

_log = logging.getLogger(__name__)

mcp = FastMCP("unplug")


def _track_session_taint(source: str | Source) -> bool:
    """Untrusted sources share Guard session state for side-effect review gates."""
    src = resolve_scan_source(source) if isinstance(source, str) else source
    return src in (Source.RETRIEVED, Source.TOOL_OUTPUT)


def _blocked_body(exc: Exception, *, source_text: str | None = None) -> dict[str, Any]:
    """Fail-closed MCP payload — any tool error blocks instead of raising.

    A raised exception would read to an agent as "scanner unavailable, proceed";
    returning a BLOCK result keeps the contract fail-closed.
    """
    result = ScanResult(
        safe=False,
        action=Action.BLOCK,
        risk_score=1.0,
        findings=[
            Finding(
                category="mcp",
                subcategory="tool_error",
                stage="error",
                span_start=0,
                span_end=0,
                score=1.0,
                evidence=f"Tool failed: {type(exc).__name__}",
            )
        ],
        latency_ms=0.0,
    )
    try:
        body = format_scan_response(result, source_text=source_text)
    except Exception:  # pragma: no cover - the fail-closed path must never raise
        # Last-resort hardcoded BLOCK body so an agent can never read this error
        # path as "proceed", even if the formatter itself fails.
        body = {
            "safe": False,
            "action": Action.BLOCK.value,
            "risk_score": 1.0,
            "finding_count": 0,
            "findings": [],
            "redacted_text": None,
            "stages_run": ["error"],
            "latency_ms": 0.0,
            "has_redaction": False,
            "error": "tool_error",
        }
    try:
        body["session"] = session_status()
    except Exception:  # pragma: no cover - status is best-effort on the error path
        body["session"] = {}
    return body


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
    try:
        scan_source = resolve_scan_source(source)
        guard = get_guard()
        if document_id:
            guard.context.document_id = document_id
        request = ScanRequest(text=text, source=scan_source, redact=redact, document_id=document_id)
        result = guard.scan_request(request, isolated=not _track_session_taint(scan_source))
        body = format_scan_response(result, source_text=text)
        body["session"] = session_status()
        return body
    except Exception as exc:
        _log.error("scan_text failed: %s", type(exc).__name__)
        return _blocked_body(exc, source_text=text)


@mcp.tool()
def scan_tool_result(text: str, redact: bool = True) -> dict[str, Any]:
    """Scan tool output before the agent processes it (source=tool_output)."""
    try:
        guard = get_guard()
        request = ScanRequest(text=text, source=Source.TOOL_OUTPUT, redact=redact)
        result = guard.scan_output_request(request, isolated=False)
        body = format_scan_response(result, source_text=text)
        body["session"] = session_status()
        return body
    except Exception as exc:
        _log.error("scan_tool_result failed: %s", type(exc).__name__)
        return _blocked_body(exc, source_text=text)


@mcp.tool()
def check_destructive(tool_name: str, arguments_json: str = "{}") -> dict[str, Any]:
    """Verify a proposed tool call is safe to execute."""
    import json

    try:
        try:
            args = json.loads(arguments_json) if arguments_json else {}
        except (json.JSONDecodeError, TypeError) as exc:
            # Malformed arguments are unverifiable — block rather than proceed.
            _log.error("check_destructive could not parse arguments_json: %s", type(exc).__name__)
            return _blocked_body(exc)
        if not isinstance(args, dict):
            args = {"_raw": args}
        result = get_guard().check_tool_call(tool_name, args)
        body = format_scan_response(result)
        body["session"] = session_status()
        return body
    except Exception as exc:
        _log.error("check_destructive failed: %s", type(exc).__name__)
        return _blocked_body(exc)


@mcp.tool()
def notify_taint_source(tool_name: str, origin: str = "") -> dict[str, Any]:
    """Mark session tainted after a taint-source tool (web_fetch, read_file, browser, …)."""
    try:
        return _notify_taint_source(tool_name, origin=origin)
    except Exception as exc:
        # Conservative on failure: report tainted so side-effect gates stay closed.
        _log.error("notify_taint_source failed: %s", type(exc).__name__)
        return {
            "error": type(exc).__name__,
            "session_tainted": True,
            "tool_name": tool_name,
        }


@mcp.tool()
def reset_session_taint() -> dict[str, Any]:
    """Clear session taint after a trusted-only user turn."""
    try:
        return _reset_session_taint()
    except Exception as exc:
        # Failing to clear leaves the session tainted, which is the safe direction.
        _log.error("reset_session_taint failed: %s", type(exc).__name__)
        return {"error": type(exc).__name__, "session_tainted": True}


@mcp.tool()
def wrap_untrusted_content(
    text: str,
    source: str = "retrieved",
    sanitize: bool = True,
    scan: bool = True,
    redact: bool = True,
) -> dict[str, Any]:
    """Sanitize spoofed markers, scan, and wrap untrusted content for agent context."""
    try:
        return _wrap_untrusted_content(
            text,
            source=source,  # type: ignore[arg-type]
            sanitize=sanitize,
            scan=scan,
            redact=redact,
        )
    except Exception as exc:
        # Block on failure rather than handing back unscanned untrusted content.
        _log.error("wrap_untrusted_content failed: %s", type(exc).__name__)
        body = _blocked_body(exc, source_text=text)
        body["wrapped_text"] = None
        body["sanitized"] = False
        body["source"] = source
        return body


def main() -> None:
    mcp.run()
