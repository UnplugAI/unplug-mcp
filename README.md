# Unplug MCP

Model Context Protocol server for [Unplug](https://github.com/chiruu12/unplug) — LLM defense layer.

Integrates with Claude Code, Cursor, Windsurf, and any MCP-compatible client.

## Installation

```bash
pip install unplug-mcp
```

## Usage

### Local mode (default)

```bash
pip install unplug-mcp "unplug-ai[ml]"
```

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

### Hosted server mode

Point at your Unplug API (same wire format as `Guard(mode="server")`):

```json
{
  "mcpServers": {
    "unplug": {
      "command": "unplug-mcp",
      "env": {
        "UNPLUG_MODE": "server",
        "UNPLUG_SERVER_URL": "https://api.example.com",
        "UNPLUG_API_KEY": "up_live_xxx"
      }
    }
  }
}
```
