# Releasing agentcomms

The Python distribution is named `agentcomms-secure` because the unrelated
`agentcomms` name is already taken on PyPI. The installed modules and console
commands are `agentcomms`, `agentcomms-v2`, and `agentcomms-mcp`.

## One-time PyPI setup

1. Create or sign in to the maintainer's PyPI account.
2. Add a pending trusted publisher for a new project:
   - PyPI project name: `agentcomms-secure`
   - GitHub owner: `web3wes`
   - GitHub repository: `agentcomms`
   - Workflow filename: `publish.yml`
   - Environment name: leave blank

No PyPI API token is required. The release workflow uses GitHub Actions OIDC.

## Release

1. Ensure the version matches in `pyproject.toml`, `agentcomms_mcp.py`, and
   `server.json`.
2. Run `python -m unittest discover -s tests -v`.
3. Run `python -m build` and inspect the wheel.
4. Create and publish a GitHub release for the matching tag, for example
   `v0.3.0`.

The workflow publishes the wheel and source archive to PyPI, waits for the
package to become visible, verifies `server.json`, authenticates to the MCP
Registry as `io.github.web3wes/*` with GitHub OIDC, and publishes the server.

Do not add the server to `modelcontextprotocol/registry/data/seed.json`; that
file is only development seed data and is not the publishing path.
