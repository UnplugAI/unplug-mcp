# Unplug MCP

[![CI](https://github.com/UnplugAI/unplug-mcp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/UnplugAI/unplug-mcp/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/unplug-mcp)](https://pypi.org/project/unplug-mcp/)
[![License](https://img.shields.io/badge/License-Apache_2.0-9ca3af)](LICENSE)

Model Context Protocol server for [Unplug](https://github.com/UnplugAI/Unplug) — LLM defense layer.

Integrates with Claude Code, Cursor, Windsurf, and any MCP-compatible client.

## Installation

```bash
pip install unplug-mcp
```

Optional ML span scanner:

```bash
pip install "unplug-mcp[ml]"
```

Run without a prior install (recommended for MCP clients):

```bash
uvx unplug-mcp
```

See [`examples/mcp.json`](examples/mcp.json) for copy-paste client configs.

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

**With uvx** (no pip install):

```json
{
  "mcpServers": {
    "unplug": {
      "command": "uvx",
      "args": ["unplug-mcp"]
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
        "UNPLUG_SERVER_URL": "https://api.unplug-ai.org/v1",
        "UNPLUG_API_KEY": "up_live_xxx"
      }
    }
  }
}
```

### Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `UNPLUG_MODE` | `local` | `local` or `server` |
| `UNPLUG_CONFIG` | — | Path to Unplug TOML config |
| `UNPLUG_SERVER_URL` | — | Hosted API base URL (server mode) |
| `UNPLUG_API_KEY` | — | API key (server mode) |
| `UNPLUG_ACTIVE_MODEL` | — | ML model name override |
| `UNPLUG_MODEL_PATH` | — | Local ML checkpoint path |

## Tools

| Tool | Purpose |
|------|---------|
| `scan_text` | Scan user or retrieved content for injection/leakage |
| `scan_tool_result` | Scan tool output before the agent reads it |
| `check_destructive` | Gate side-effect tool calls |
| `wrap_untrusted_content` | Boundary markers + scan for RAG/web content |
| `session_status` | Session taint state for agent hardening |
| `notify_taint_source` | Record an untrusted content source in session state |
| `reset_session_taint` | Clear session taint tracking |

All tools **fail closed**: scan failures return `safe=false` and `action=block` so agents never proceed on errors. `session_status` and taint helpers conservatively mark the session tainted when they cannot read state.

## CI

- `ci.yml` — lint + pytest against PyPI `unplug-ai`
- `pr-scan.yml` — regex Guard scan on changed agent/MCP config files (via `UnplugAI/unplug-scan-action@v1`)
- `publish-pypi.yml` — PyPI release on GitHub Release or manual dispatch

## Development

```bash
uv sync --extra dev
uv run pytest -q
uv run unplug-mcp
```

Local SDK path override (monorepo): `tool.uv.sources` in `pyproject.toml`.

## Distribution

See [`MARKETPLACE.md`](MARKETPLACE.md) for MCP registry listing steps and [`PUBLISH.md`](PUBLISH.md) for PyPI release workflow.

## Related

- [unplug-ai](https://pypi.org/project/unplug-ai/) — Python SDK
- [unplug-scan-action](https://github.com/UnplugAI/unplug-scan-action) — GitHub Actions agent scan
- [unplug-server](https://github.com/UnplugAI/unplug-server) — hosted scan API

## License

Apache-2.0 — see [LICENSE](LICENSE).
