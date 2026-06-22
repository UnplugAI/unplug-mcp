# MCP distribution checklist

## PyPI (done)

- Package: [`unplug-mcp`](https://pypi.org/project/unplug-mcp/)
- Entry point: `unplug-mcp`
- Install: `pip install unplug-mcp` or `uvx unplug-mcp`

## Cursor / Claude / Windsurf

1. Copy config from [`examples/mcp.json`](examples/mcp.json)
2. Prefer `uvx unplug-mcp` for zero-install setup
3. For hosted scans, set `UNPLUG_MODE=server` + API URL/key (see README)

## Smithery (optional)

1. Add `smithery.yaml` when ready for [smithery.ai](https://smithery.ai) listing
2. Point install command at `uvx unplug-mcp`

## GitHub

- Tag releases (`v0.1.x`) with CHANGELOG excerpt
- Attach release notes from [`CHANGELOG.md`](CHANGELOG.md)
- Link from [unplug-ai.org](https://unplug-ai.org) docs when site copy is updated

## Post-release verification

```bash
pip install unplug-mcp==0.1.1
python -c "import unplug_mcp; print(unplug_mcp.__version__)"
```

Configure MCP client with `examples/mcp.json` and confirm tools respond.
