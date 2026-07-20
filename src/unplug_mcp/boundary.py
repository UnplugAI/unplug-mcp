"""Agent boundary helpers — wrap, taint notify, session status."""

from __future__ import annotations

from typing import Any, Literal

from unplug.api.boundaries import (
    SourceKind,
    sanitize_boundary_markers,
    wrap_external_content,
)
from unplug.api.enums import Action, Source
from unplug.api.types import Finding, ScanRequest, ScanResult

from unplug_mcp.guard_factory import get_guard, guard_session_lock
from unplug_mcp.response import format_scan_response

SourceArg = Literal["retrieved", "tool_output", "external", "web_fetch", "email", "file"]

_TAINT_SOURCES = frozenset({Source.RETRIEVED.value, Source.TOOL_OUTPUT.value})

# Untrusted boundary labels an agent may pass (web_fetch, file, email, …) are
# not Source enum members. Map every external-origin label onto RETRIEVED so a
# scan request never crashes on an unknown source; unknown/blank falls back to
# the most cautious untrusted value rather than USER.
_SOURCE_LABEL_MAP: dict[str, Source] = {
    "user": Source.USER,
    "system": Source.SYSTEM,
    "retrieved": Source.RETRIEVED,
    "tool_output": Source.TOOL_OUTPUT,
    "tool": Source.TOOL_OUTPUT,
    "external": Source.RETRIEVED,
    "web_fetch": Source.RETRIEVED,
    "web": Source.RETRIEVED,
    "email": Source.RETRIEVED,
    "file": Source.RETRIEVED,
}


def resolve_scan_source(source: str | Source) -> Source:
    """Map an arbitrary source label to a valid scan Source (fail-safe untrusted)."""
    if isinstance(source, Source):
        return source
    if not isinstance(source, str):
        # None (e.g. a JSON null from an MCP client) or any non-string type maps
        # to the most cautious untrusted source instead of raising.
        return Source.RETRIEVED
    try:
        return Source(source)
    except ValueError:
        return _SOURCE_LABEL_MAP.get(source.strip().lower(), Source.RETRIEVED)


def _session_status_locked(guard) -> dict[str, Any]:
    return {
        "session_tainted": guard.context.is_session_tainted,
        "taint_triggers": list(guard.context.taint_triggers),
        "tool_call_count": len(guard.context.tool_calls),
    }


def session_status() -> dict[str, Any]:
    with guard_session_lock():
        guard = get_guard()
        return _session_status_locked(guard)


def notify_taint_source(tool_name: str, *, origin: str = "") -> dict[str, Any]:
    """Mark session tainted after a taint-source tool runs (web_fetch, read_file, …)."""
    with guard_session_lock():
        guard = get_guard()
        guard.notify_taint_source(tool_name, origin=origin)
        status = _session_status_locked(guard)
    status["tool_name"] = tool_name
    if origin:
        status["origin"] = origin
    return status


def reset_session_taint() -> dict[str, Any]:
    """Clear session taint (internal/tests only — not an MCP agent tool)."""
    with guard_session_lock():
        guard = get_guard()
        guard.reset_session_taint()
        return _session_status_locked(guard)


def notify_trusted_user_turn(*, confirm_trusted_user_turn: bool = False) -> dict[str, Any]:
    """Host-only: clear session taint after a real user message.

    MCP hosts (Cursor, Claude Desktop, etc.) should wire this to user-turn hooks
    and must not expose it in agent tool lists. Agents must never call this after
    reading untrusted content — prompt injection may instruct them to do so.

    Fail-closed: without ``confirm_trusted_user_turn=True`` the session stays tainted.
    """
    with guard_session_lock():
        guard = get_guard()
        if not confirm_trusted_user_turn:
            status = _session_status_locked(guard)
            status["reset"] = False
            status["reason"] = "confirm_trusted_user_turn_required"
            return status
        guard.reset_session_taint()
        status = _session_status_locked(guard)
        status["reset"] = True
        return status


def _scan_content(
    text: str,
    *,
    source: SourceArg,
    redact: bool,
) -> dict[str, Any]:
    scan_source = resolve_scan_source(source)
    with guard_session_lock():
        guard = get_guard()
        if scan_source == Source.TOOL_OUTPUT:
            request = ScanRequest(text=text, source=Source.TOOL_OUTPUT, redact=redact)
            result = guard.scan_output_request(request, isolated=False)
        else:
            request = ScanRequest(text=text, source=scan_source, redact=redact)
            result = guard.scan_request(request, isolated=scan_source.value not in _TAINT_SOURCES)
    return format_scan_response(result, source_text=text, guard=guard)


def _scan_disabled_block(text: str) -> dict[str, Any]:
    result = ScanResult(
        safe=False,
        action=Action.BLOCK,
        risk_score=1.0,
        findings=[
            Finding(
                category="mcp",
                subcategory="scan_disabled",
                stage="boundary",
                span_start=0,
                span_end=len(text),
                score=1.0,
                evidence="scan=false is not allowed for untrusted content wrapping",
            )
        ],
        latency_ms=0.0,
    )
    return format_scan_response(result, source_text=text, guard=get_guard())


def wrap_untrusted_content(
    text: str,
    *,
    source: SourceArg = "retrieved",
    sanitize: bool = True,
    scan: bool = True,
    redact: bool = True,
) -> dict[str, Any]:
    """Sanitize spoofed markers, optionally scan, then wrap for agent context."""
    body = text
    sanitized = False
    if sanitize:
        body, sanitized = sanitize_boundary_markers(text)
    kind: SourceKind = source
    wrapped = wrap_external_content(body, source=kind, sanitize=False)
    out: dict[str, Any] = {
        "wrapped_text": wrapped.text,
        "marker_id": wrapped.marker_id,
        "source": wrapped.source,
        "sanitized": sanitized,
        "session": session_status(),
    }
    if not scan:
        scan_out = _scan_disabled_block(body)
        out["scan"] = scan_out
        out["safe"] = False
        out["action"] = Action.BLOCK.value
        out["wrapped_text"] = wrap_external_content(
            scan_out["redacted_text"],
            source=kind,
            marker_id=wrapped.marker_id,
            sanitize=False,
        ).text
        return out

    scan_out = _scan_content(body, source=source, redact=redact)
    out["scan"] = scan_out
    out["safe"] = scan_out["safe"]
    out["action"] = scan_out["action"]
    out["session"] = session_status()
    body_text = scan_out.get("redacted_text") if scan_out.get("redacted_text") is not None else body
    rescanned = wrap_external_content(
        body_text,
        source=kind,
        marker_id=wrapped.marker_id,
        sanitize=False,
    )
    out["wrapped_text"] = rescanned.text
    return out
