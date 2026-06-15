# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Unplug MCP, please report it responsibly.

**Preferred:** [GitHub Security Advisories](https://github.com/UnplugAI/unplug-mcp/security/advisories/new) (private disclosure).

**Email:** [security@unplug-ai.org](mailto:security@unplug-ai.org)

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof of concept
- Affected versions (e.g. `unplug-mcp==0.1.1`)

Do **not** open a public GitHub issue for security vulnerabilities.

## Response Timeline

- **Acknowledgment** within 3 business days
- **Initial assessment** within 7 business days
- **Fix or mitigation plan** communicated as soon as a path is identified

We will coordinate disclosure timing with you and credit reporters who wish to be named.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest on PyPI | Yes |
| Older releases | Best effort |

## Scope

In scope:

- The `unplug-mcp` MCP server package
- Official CI workflows and release artifacts

Out of scope:

- The underlying `unplug-ai` SDK (report to the [SDK repository](https://github.com/UnplugAI/unplug))
- Third-party MCP hosts and clients (Claude Code, Cursor, etc.) unless this server introduces the vulnerability
- Hosted services (report to the respective operator)
