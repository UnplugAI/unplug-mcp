"""Ensure host-only tools are not registered for agent MCP exposure."""

from __future__ import annotations

from unplug_mcp.server import mcp


def test_notify_trusted_user_turn_not_registered_as_mcp_tool() -> None:
    names = {tool.name for tool in mcp._tool_manager.list_tools()}
    assert "notify_trusted_user_turn" not in names
