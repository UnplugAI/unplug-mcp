# Changelog

## [Unreleased]

## [0.1.2] — 2026-06-16

- Distribution docs: CHANGELOG, MARKETPLACE, PUBLISH, examples/mcp.json
- README: PyPI badges, uvx install, env vars, all MCP tools
- Tighten deps to unplug-ai>=0.3.1,<0.4 and mcp>=1.0,<2

## [0.1.1] — 2026-06-13

- Initial PyPI release
- MCP tools: `scan_text`, `scan_tool_result`, `check_destructive`, `wrap_untrusted_content`, `session_status`, `notify_taint_source`, `reset_session_taint`
- Local and server Guard modes via environment variables
- Fail-closed tool error handling
- CI against PyPI `unplug-ai>=0.3.1`
