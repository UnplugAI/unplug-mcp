# Unplug MCP

Model Context Protocol server for [Unplug](https://github.com/UnplugAI/Unplug) — LLM defense layer.

Integrates with Claude Code, Cursor, Windsurf, and any MCP-compatible client.

## Installation

```bash
pip install unplug-mcp "unplug-ai>=0.3.0"
```

Optional ML span scanner:

```bash
pip install unplug-mcp "unplug-ai[ml]>=0.3.0"
```

## Usage

### Local mode (default)

Add to your MCP client configuration:

**Cursor** — `.cursor/mcp.json` or Settings → MCP:

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

**Claude Desktop** — `claude_desktop_config.json`:

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

## Tools

| Tool | Purpose |
|------|---------|
| `scan_text` | Scan user or retrieved content for injection/leakage |
| `scan_tool_result` | Scan tool output before the agent reads it |
| `check_destructive` | Gate side-effect tool calls |
| `wrap_untrusted_content` | Boundary markers + scan for RAG/web content |
| `session_status` | Session taint state for agent hardening |

## CI

- `ci.yml` — lint + pytest against PyPI `unplug-ai`
- `pr-scan.yml` — regex Guard scan on changed agent/MCP config files (via `unplug-scan-pr`)

## Development

```bash
uv sync --extra dev
uv run pytest -q
uv run unplug-mcp
```

Local SDK path override (monorepo): `tool.uv.sources` in `pyproject.toml`.
