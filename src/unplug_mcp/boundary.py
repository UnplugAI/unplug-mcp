"""Agent boundary helpers — wrap, taint notify, session status."""

from __future__ import annotations

from typing import Any, Literal

from unplug.api.enums import Source
from unplug.api.types import ScanRequest
from unplug.core.agent.boundaries import (
    SourceKind,
    sanitize_boundary_markers,
    wrap_external_content,
)

from unplug_mcp.guard_factory import get_guard
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


def session_status() -> dict[str, Any]:
    guard = get_guard()
    return {
        "session_tainted": guard.context.is_session_tainted,
        "taint_triggers": list(guard.context.taint_triggers),
        "tool_call_count": len(guard.context.tool_calls),
    }


def notify_taint_source(tool_name: str, *, origin: str = "") -> dict[str, Any]:
    """Mark session tainted after a taint-source tool runs (web_fetch, read_file, …)."""
    guard = get_guard()
    guard.notify_taint_source(tool_name, origin=origin)
    status = session_status()
    status["tool_name"] = tool_name
    if origin:
        status["origin"] = origin
    return status


def reset_session_taint() -> dict[str, Any]:
    """Clear session taint (e.g. new trusted user turn)."""
    get_guard().reset_session_taint()
    return session_status()


def _scan_content(
    text: str,
    *,
    source: SourceArg,
    redact: bool,
) -> dict[str, Any]:
    guard = get_guard()
    scan_source = resolve_scan_source(source)
    if scan_source == Source.TOOL_OUTPUT:
        request = ScanRequest(text=text, source=Source.TOOL_OUTPUT, redact=redact)
        result = guard.scan_output_request(request, isolated=False)
    else:
        request = ScanRequest(text=text, source=scan_source, redact=redact)
        result = guard.scan_request(request, isolated=scan_source.value not in _TAINT_SOURCES)
    return format_scan_response(result, source_text=text)


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
