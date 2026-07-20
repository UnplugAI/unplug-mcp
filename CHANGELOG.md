# Changelog

## [0.1.6] — 2026-07-20

- Pin `unplug-ai>=0.5.2,<0.7` so SDK 0.6.x resolves alongside `unplug-mcp`

## [0.1.5] — 2026-07-20

- Fail-closed: `scan_text` defaults `source` to untrusted for session taint tracking
- Replace agent-callable `reset_session_taint` with host-only `notify_trusted_user_turn`
  (requires `confirm_trusted_user_turn=true`; fail-closed without it)

## [0.1.4] — 2026-07-20

- Pin `unplug-ai>=0.5.2,<0.6`; migrate imports to `unplug.api.*`
- Align PR scan workflow with SDK 0.5.x
- Document fail-closed tool semantics; add `session_status` tests

## [0.1.3] — 2026-06-24

- Bump `unplug-ai` dependency to `>=0.4.0,<0.5`

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
