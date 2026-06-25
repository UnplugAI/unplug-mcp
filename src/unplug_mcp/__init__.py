"""Unplug MCP — Model Context Protocol server for LLM defense."""

from __future__ import annotations

__version__ = "0.1.3"

from unplug_mcp.server import mcp

__all__ = ["mcp", "__version__"]
