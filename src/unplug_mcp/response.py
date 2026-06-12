"""Normalize scan results for MCP tool responses."""

from __future__ import annotations

from typing import Any

from unplug.api.types import Finding, ScanResult


def format_finding(finding: Finding, *, source_text: str | None = None) -> dict[str, Any]:
    payload = finding.model_dump(mode="json")
    if source_text and finding.span_end > finding.span_start:
        start = max(0, min(finding.span_start, len(source_text)))
        end = max(start, min(finding.span_end, len(source_text)))
        payload["span_text"] = source_text[start:end]
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
) -> dict[str, Any]:
    """Stable MCP payload — findings, tags, and redacted body for agents."""
    findings = [format_finding(f, source_text=source_text) for f in result.findings]
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
        "has_redaction": result.redacted_text is not None
        and result.redacted_text != (source_text or ""),
    }
    if include_original and source_text is not None:
        body["original_text"] = source_text
    if result.approval is not None:
        body["approval"] = result.approval.model_dump(mode="json")
    return body
