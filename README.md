# Unplug MCP

Model Context Protocol server for [Unplug](https://github.com/chiruu12/unplug) — LLM defense layer.

Integrates with Claude Code, Cursor, Windsurf, and any MCP-compatible client.

## Installation

```bash
pip install unplug-mcp
```

## Usage

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "unplug": {
      "command": "unplug-mcp",
      "args": []
    }
  }
}
```
