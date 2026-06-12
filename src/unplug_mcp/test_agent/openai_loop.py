"""OpenAI chat loop with tool calling for Unplug QA."""

from __future__ import annotations

import json
import os
from typing import Any

import httpx

from unplug_mcp.test_agent.tools import dispatch_tool, tool_definitions

DEFAULT_MODEL = "gpt-5.4-nano"
DEFAULT_BASE_URL = "https://api.openai.com/v1"


def _resolve_model() -> str:
    return os.environ.get("OPENAI_TEST_AGENT_MODEL", DEFAULT_MODEL)


def _resolve_base_url() -> str:
    return os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL).rstrip("/")


def _api_key() -> str:
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        msg = "Set OPENAI_API_KEY"
        raise ValueError(msg)
    return key


def run_agent(
    *,
    system: str,
    user: str,
    max_turns: int = 24,
    temperature: float = 0.4,
    max_tokens: int = 4096,
) -> dict[str, Any]:
    """Run tool-calling agent until the model returns a final message."""
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    tools = tool_definitions()
    tool_calls_log: list[dict[str, Any]] = []
    model = _resolve_model()
    headers = {"Authorization": f"Bearer {_api_key()}", "Content-Type": "application/json"}

    with httpx.Client(timeout=120.0) as client:
        for turn in range(max_turns):
            payload: dict[str, Any] = {
                "model": model,
                "messages": messages,
                "tools": tools,
                "tool_choice": "auto",
                "temperature": temperature,
                "max_completion_tokens": max_tokens,
            }
            resp = client.post(f"{_resolve_base_url()}/chat/completions", json=payload, headers=headers)
            resp.raise_for_status()
            body = resp.json()
            choice = body["choices"][0]
            message = choice["message"]
            messages.append(message)

            tool_calls = message.get("tool_calls") or []
            if not tool_calls:
                return {
                    "model": model,
                    "turns": turn + 1,
                    "final_message": message.get("content") or "",
                    "tool_calls": tool_calls_log,
                    "usage": body.get("usage"),
                    "messages": messages,
                }

            for call in tool_calls:
                fn = call["function"]
                name = fn["name"]
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                try:
                    result = dispatch_tool(name, args)
                except Exception as exc:
                    result = {"error": f"{type(exc).__name__}: {exc}"}
                tool_calls_log.append({"name": name, "arguments": args, "result": result})
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call["id"],
                        "content": json.dumps(result, ensure_ascii=False),
                    }
                )

    return {
        "model": model,
        "turns": max_turns,
        "final_message": "",
        "tool_calls": tool_calls_log,
        "error": "max_turns_exceeded",
        "messages": messages,
    }
