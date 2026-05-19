# Rafter CLI

[![npm version](https://img.shields.io/npm/v/@rafter-security/cli)](https://www.npmjs.com/package/@rafter-security/cli) [![PyPI version](https://img.shields.io/pypi/v/rafter-cli)](https://pypi.org/project/rafter-cli/) [![Scanned by Rafter](https://img.shields.io/badge/scanned_by-Rafter-2ea44f)](https://github.com/Raftersecurity/rafter-cli) [![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

<p>
  <a href="docs/supported-platforms.md"><img alt="Claude Code supported" src="https://img.shields.io/badge/Claude%20Code-supported-d97757?style=flat&labelColor=141413&logo=claude&logoColor=faf9f5"></a>
  <a href="docs/supported-platforms.md"><img alt="Codex supported" src="https://img.shields.io/badge/Codex-supported-f5f5f5?style=flat&labelColor=000000"></a>
  <a href="docs/supported-platforms.md"><img alt="Gemini CLI supported" src="https://img.shields.io/badge/Gemini%20CLI-supported-4285f4?style=flat&labelColor=202124&logo=googlegemini&logoColor=8e75b2"></a>
  <a href="docs/supported-platforms.md"><img alt="OpenClaw supported" src="https://img.shields.io/badge/OpenClaw-supported-e8662a?style=flat&labelColor=1a1a1a"></a>
  <a href="docs/supported-platforms.md"><img alt="Cursor supported" src="https://img.shields.io/badge/Cursor-supported-d4d4d4?style=flat&labelColor=1c1c1c&logo=cursor&logoColor=white"></a>
  <a href="docs/supported-platforms.md"><img alt="Windsurf supported" src="https://img.shields.io/badge/Windsurf-supported-00c4b4?style=flat&labelColor=0a0a0a"></a>
  <a href="docs/supported-platforms.md"><img alt="Continue.dev supported" src="https://img.shields.io/badge/Continue.dev-supported-7c3aed?style=flat&labelColor=1e1b2e"></a>
  <a href="docs/supported-platforms.md"><img alt="Aider supported" src="https://img.shields.io/badge/Aider-supported-10b981?style=flat&labelColor=111827"></a>
</p>

Multi-language CLI for [Rafter](https://rafter.so) — the security toolkit built for AI coding agents and the developers who use them. Local secret scanning, command interception, policy enforcement, audit logging, and an MCP server all run offline with no account required. Optional remote SAST/SCA/agentic analysis is available via `RAFTER_API_KEY`. Stable output contracts, deterministic results, structured JSON — pipe to `jq`, feed to an orchestrator, or read it yourself.

> **Free forever for individuals and open source. No account required. No telemetry.**

## 90-Second Quickstart

See what Rafter does before reading another word.

**1. Scan a directory for leaked credentials**

```sh
# Drop a .env file with a fake AWS key in a test repo
echo "AWS_ACCESS_KEY_ID=AKIA${SAMPLE_AWS_TAIL}" > .env  # e.g. AKIA followed by IOSFODNN7EXAMPLE

rafter secrets .
# → CRITICAL  .env:1  aws-access-key-id  AKIA***AMPLE
# → exit 1
```

**2. Install the pre-commit hook**

```sh
rafter agent init                          # interactive: previews changes, then installs detected integrations
# → For agents/CI: rafter agent init --all (non-interactive, all detected) or --dry-run (preview only)
```

> **Prerequisite:** `rafter agent init` only installs hooks/skills for agent tools you *already have* (Claude Code, Codex CLI, Cursor, Windsurf, Continue.dev, Aider, Gemini CLI, OpenClaw). On a fresh machine with none of them installed, init prints `No agent environments detected.` and exits cleanly — that's expected, not an error. Install your editor/agent first; the pre-commit hook still works through `rafter agent install-hook`.
>
> Preview every file Rafter would touch with `rafter agent init --dry-run` before committing to changes. Confirm a finished install at any time with `rafter agent verify`.

**3. Try to commit — the hook blocks it**

```sh
git add . && git commit -m 'add config'
# → [rafter] Scanning staged files for secrets...
# → CRITICAL  .env:1  aws-access-key-id
# → Commit blocked. Remove secrets or use git commit --no-verify to bypass.
```

**4. Review the audit log**

```sh
rafter agent audit --last 3
# → 2026-02-27T...  secret_detected  .env  aws-access-key-id
```

That's the core loop: scan → protect → audit. Everything works offline, no API key needed.

## What's Free?

| Feature | Free (individuals & OSS) | Enterprise |
|---------|:------------------------:|:----------:|
| Secret scanning (21+ patterns) | **Yes** | Yes |
| Pre-commit hooks | **Yes** | Yes |
| Command interception | **Yes** | Yes |
| Skill/extension auditing | **Yes** | Yes |
| Audit logging | **Yes** | Yes |
| MCP server | **Yes** | Yes |
| CI/CD integration | **Yes** | Yes |
| Remote SAST/SCA/Agentic analysis (API) | Free tier | Higher limits |
| Dashboards ([rafter.so](https://rafter.so)) | **Yes** | Yes |

No account. No telemetry. No data collection. The CLI is MIT-licensed and all local features work without network access.

## Installation

```sh
# Node.js
npm install -g @rafter-security/cli
# or pnpm add -g @rafter-security/cli

# Python (3.10+)
pip install rafter-cli
```

Both implementations have full feature parity. See [`docs/installation.md`](docs/installation.md) for verification, `npx`, and other install methods.

## Global Options

| Flag | Description |
|------|-------------|
| `-a, --agent` | Plain output (no colors, no emoji). Useful when piping or driving Rafter from an automated system. |

## Where to go next

- [docs/installation.md](docs/installation.md) — install across platforms
- [docs/local-toolkit.md](docs/local-toolkit.md) — setup, secret scanning, pre-commit, policy enforcement, skills, audit log, configuration, custom rules, CI/CD setup, MCP server
- [docs/remote-analysis.md](docs/remote-analysis.md) — `rafter run` against the Rafter API
- [docs/supported-platforms.md](docs/supported-platforms.md) — agent IDE integrations (Claude Code, Codex, Cursor, Windsurf, Gemini, Aider, OpenClaw, Continue.dev)
- [docs/exit-codes.md](docs/exit-codes.md) — stable exit-code contract
- [docs/file-locations.md](docs/file-locations.md) — where Rafter writes config and logs
- [docs/development.md](docs/development.md) — building from source, contributing, badges
- [docs/adding-a-platform.md](docs/adding-a-platform.md) — contract for adding a new agent IDE
- [`shared-docs/CLI_SPEC.md`](shared-docs/CLI_SPEC.md) — canonical output contract
- [`recipes/`](recipes/) — per-platform copy-paste setup recipes
- [Full docs site](https://docs.rafter.so)

## License

[MIT](LICENSE)
