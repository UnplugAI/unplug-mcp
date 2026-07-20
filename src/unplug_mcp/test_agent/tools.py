"""Tool dispatch for the LLM test agent."""

from __future__ import annotations

from typing import Any

from unplug_mcp.boundary import (
    notify_taint_source,
    wrap_untrusted_content,
)
from unplug_mcp.server import (
    check_destructive,
    notify_trusted_user_turn,
    scan_text,
    scan_tool_result,
)
from unplug_mcp.test_agent.probes import run_fp_probe_suite
from unplug_mcp.test_agent.sdk_suite import get_guard_status, run_sdk_integration_suite

__all__ = [
    "dispatch_tool",
    "get_guard_status",
    "run_fp_probe_suite",
    "run_sdk_integration_suite",
    "tool_definitions",
]


def tool_definitions() -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": "scan_text",
                "description": (
                    "Scan user or retrieved text for prompt injection. "
                    "Returns safe, action, risk_score, findings with span_text/tags, redacted_text."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string"},
                        "source": {
                            "type": "string",
                            "enum": ["user", "retrieved", "tool_output", "external"],
                            "default": "retrieved",
                        },
                        "redact": {"type": "boolean", "default": True},
                    },
                    "required": ["text"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "scan_tool_result",
                "description": "Scan tool output before an agent consumes it.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string"},
                        "redact": {"type": "boolean", "default": True},
                    },
                    "required": ["text"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "check_destructive",
                "description": "Check if a proposed tool call is safe (SQL, shell, etc.).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "tool_name": {"type": "string"},
                        "arguments_json": {"type": "string", "default": "{}"},
                    },
                    "required": ["tool_name"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_guard_status",
                "description": (
                    "Report Guard wiring: scanners, ML, checkpoint, session taint state."
                ),
                "parameters": {"type": "object", "properties": {}},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "notify_taint_source",
                "description": (
                    "Mark session tainted after web_fetch/read_file/browser pulls untrusted data."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "tool_name": {"type": "string"},
                        "origin": {"type": "string", "default": ""},
                    },
                    "required": ["tool_name"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "notify_trusted_user_turn",
                "description": (
                    "Host-only: clear session taint after a real user message. "
                    "Requires confirm_trusted_user_turn=true."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "confirm_trusted_user_turn": {
                            "type": "boolean",
                            "default": False,
                            "description": (
                                "Must be true to clear taint. "
                                "Hosts wire this to user-turn hooks only."
                            ),
                        },
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "wrap_untrusted_content",
                "description": (
                    "Sanitize spoofed boundary markers, scan, and wrap external content "
                    "for safe agent context injection."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string"},
                        "source": {
                            "type": "string",
                            "enum": [
                                "retrieved",
                                "tool_output",
                                "external",
                                "web_fetch",
                                "email",
                                "file",
                            ],
                            "default": "retrieved",
                        },
                        "sanitize": {"type": "boolean", "default": True},
                        "scan": {"type": "boolean", "default": True},
                        "redact": {"type": "boolean", "default": True},
                    },
                    "required": ["text"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "run_sdk_integration_suite",
                "description": (
                    "Run deterministic SDK + span-model integration checks "
                    "(attack/benign/probes/scanner filter/destructive gate)."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "require_ml": {"type": "boolean", "default": True},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "run_fp_probe_suite",
                "description": "Run the built-in false-positive / true-positive probe battery.",
                "parameters": {"type": "object", "properties": {}},
            },
        },
    ]


def dispatch_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "scan_text":
        return scan_text(
            text=str(arguments["text"]),
            source=str(arguments.get("source", "retrieved")),
            redact=bool(arguments.get("redact", True)),
        )
    if name == "scan_tool_result":
        return scan_tool_result(
            text=str(arguments["text"]),
            redact=bool(arguments.get("redact", True)),
        )
    if name == "check_destructive":
        return check_destructive(
            tool_name=str(arguments["tool_name"]),
            arguments_json=str(arguments.get("arguments_json", "{}")),
        )
    if name == "run_fp_probe_suite":
        return run_fp_probe_suite()
    if name == "get_guard_status":
        return get_guard_status()
    if name == "notify_taint_source":
        return notify_taint_source(
            str(arguments["tool_name"]),
            origin=str(arguments.get("origin", "")),
        )
    if name == "notify_trusted_user_turn":
        return notify_trusted_user_turn(
            confirm_trusted_user_turn=bool(arguments.get("confirm_trusted_user_turn", False)),
        )
    if name == "wrap_untrusted_content":
        return wrap_untrusted_content(
            text=str(arguments["text"]),
            source=str(arguments.get("source", "retrieved")),  # type: ignore[arg-type]
            sanitize=bool(arguments.get("sanitize", True)),
            scan=bool(arguments.get("scan", True)),
            redact=bool(arguments.get("redact", True)),
        )
    if name == "run_sdk_integration_suite":
        return run_sdk_integration_suite(require_ml=bool(arguments.get("require_ml", True)))
    msg = f"Unknown tool: {name}"
    raise ValueError(msg)
