# Publish unplug-mcp to PyPI

Package: **`unplug-mcp`** | Entry point: **`unplug-mcp`**

## One-time setup

1. Create a [PyPI account](https://pypi.org/account/register/) (org account recommended).
2. Create an API token (account-scoped for first publish; project-scoped after `unplug-mcp` exists).
3. In [UnplugAI/unplug-mcp](https://github.com/UnplugAI/unplug-mcp) → **Settings → Environments → `pypi`**, add:

   | Secret       | Value        |
   |--------------|--------------|
   | `PYPI_TOKEN` | `pypi-...`   |

## Publish

**CI (recommended):** Actions → **Publish to PyPI** → Run workflow  
Or create a GitHub Release (`v0.1.x`) — workflow runs on `release: published`.

Before tagging:

1. Bump version in `pyproject.toml` and `src/unplug_mcp/__init__.py`
2. Add entry to `CHANGELOG.md`
3. Run locally:

```bash
uv sync --extra dev --no-sources
uv run --no-sources pytest -q
uv build --no-sources
```

## After publish

- Verify: `pip install unplug-mcp` → https://pypi.org/project/unplug-mcp/
- Update `MARKETPLACE.md` / site install docs if needed
- Rotate to a project-scoped PyPI token when possible
