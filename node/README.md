# @rafter-security/cli

Node.js CLI for [Rafter](https://rafter.so) — the security toolkit for AI coding agents and developers. Secret scanning, command interception, policy enforcement, extension auditing, and audit logging. Local features run offline with no account required; remote SAST/SCA via `RAFTER_API_KEY` when needed.

> **Full documentation lives in the repo root:** [README.md](https://github.com/Raftersecurity/rafter-cli/blob/main/README.md). This page is the package-level entry on npm and only covers Node-specific install and build notes — everything else (commands, flags, exit codes, recipes, CI integrations, MCP server) is in the root README and [`shared-docs/CLI_SPEC.md`](https://github.com/Raftersecurity/rafter-cli/blob/main/shared-docs/CLI_SPEC.md).

## Install

```bash
# Global CLI (recommended)
npm install -g @rafter-security/cli
pnpm add -g @rafter-security/cli
yarn global add @rafter-security/cli

# One-off, no install
npx @rafter-security/cli --help
```

After install, the `rafter` binary is on your `PATH`. Verify with `rafter --version`.

## Quickstart

```bash
# Find hardcoded secrets in the current directory
rafter secrets .

# Install Rafter into your AI coding agents (Claude Code, Codex, Cursor, etc.)
rafter agent init --all

# Scan a remote repo (needs RAFTER_API_KEY)
rafter run https://github.com/owner/repo
```

See the [root README](https://github.com/Raftersecurity/rafter-cli/blob/main/README.md) for the full command reference, supported platforms, and integration recipes.

## Building from source

```bash
git clone https://github.com/Raftersecurity/rafter-cli
cd rafter-cli/node
pnpm install
pnpm run build       # TypeScript -> dist/
pnpm test            # Vitest
node dist/index.js --help
```

The published package contains the compiled `dist/` only. `pnpm pack` produces the npm tarball; CI publishes via the workflow in `.github/workflows/`.

## Python sibling

A feature-equivalent Python implementation is published as `rafter-cli` on PyPI. Both implementations share the same CLI surface and JSON output contract — see [`shared-docs/CLI_SPEC.md`](https://github.com/Raftersecurity/rafter-cli/blob/main/shared-docs/CLI_SPEC.md).

## License

MIT — see [LICENSE](https://github.com/Raftersecurity/rafter-cli/blob/main/LICENSE).
