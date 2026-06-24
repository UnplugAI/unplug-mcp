"""Normalize scan results for MCP tool responses."""

from __future__ import annotations

import re
from typing import Any

from unplug.api.types import Finding, ScanResult

_SENSITIVE_FINDING_CATEGORIES = {"leakage", "secrets"}
_SECRET_PATTERNS = (
    re.compile(r"\bup_live_[A-Za-z0-9_\-]{4,}\b"),
    re.compile(r"\bup_test_[A-Za-z0-9_\-]{4,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}\b"),
    re.compile(r"\b[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b"),
)


def _redact_secret_text(value: str) -> str:
    out = value
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub("[REDACTED]", out)
    return out


def _redact_secrets(value: Any) -> Any:
    if isinstance(value, str):
        return _redact_secret_text(value)
    if isinstance(value, list):
        return [_redact_secrets(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_secrets(item) for key, item in value.items()}
    return value


def format_finding(
    finding: Finding,
    *,
    source_text: str | None = None,
    include_span_text: bool = False,
) -> dict[str, Any]:
    payload = finding.model_dump(mode="json")
    if include_span_text and source_text and finding.span_end > finding.span_start:
        start = max(0, min(finding.span_start, len(source_text)))
        end = max(start, min(finding.span_end, len(source_text)))
        payload["span_text"] = (
            "[REDACTED]"
            if finding.category in _SENSITIVE_FINDING_CATEGORIES
            else source_text[start:end]
        )
    if finding.replacement:
        payload["tag"] = finding.replacement
    elif finding.category:
        payload["tag"] = f"[BLOCKED:{finding.category}]"
    return payload


def format_scan_response(
    result: ScanResult,
    *,
    source_text: str | None = None,
    include_original: bool = False,
    include_span_text: bool = False,
    guard: Any | None = None,
) -> dict[str, Any]:
    """Stable MCP payload — findings, tags, and redacted body for agents."""
    findings = [
        format_finding(f, source_text=source_text, include_span_text=include_span_text)
        for f in result.findings
    ]
    stages = list(result.stages_run)
    if not stages:
        stages = sorted({f.category for f in result.findings})

    body: dict[str, Any] = {
        "safe": result.safe,
        "action": result.action.value,
        "risk_score": round(float(result.risk_score), 4),
        "finding_count": len(findings),
        "findings": findings,
        "redacted_text": result.redacted_text,
        "stages_run": stages,
        "latency_ms": round(float(result.latency_ms), 2),
        "degraded": getattr(result, "degraded", False),
        "degraded_layers": list(getattr(result, "degraded_layers", [])),
        "ml_degraded": bool(getattr(guard, "ml_degraded", False)) if guard is not None else False,
        "ml_model_loaded": bool(getattr(guard, "ml_model_loaded", False))
        if guard is not None
        else False,
        "has_redaction": result.redacted_text is not None
        and result.redacted_text != (source_text or ""),
    }
    if result.safe is False and body["redacted_text"] is None:
        body["redacted_text"] = "[BLOCKED:unsafe_content]"
        body["has_redaction"] = True
    if include_original and source_text is not None:
        body["original_text"] = source_text
    if result.approval is not None:
        approval = result.approval.model_dump(mode="json")
        approval["arguments"] = _redact_secrets(approval.get("arguments", {}))
        body["approval"] = approval
    return body
