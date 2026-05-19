# Supported Platforms

[← Back to README](../README.md)

| Platform | Integration | Detection | Config installed to |
|----------|-------------|-----------|---------------------|
| Claude Code | Hooks + Skills | `~/.claude` | `~/.claude/skills/rafter/` and `rafter-agent-security/` |
| Codex CLI | Skills | `~/.codex` | `~/.agents/skills/rafter/` and `rafter-agent-security/` |
| OpenClaw | Skills | `~/.openclaw` | `~/.openclaw/skills/rafter-security.md` |
| Gemini CLI | MCP server | `~/.gemini` | `~/.gemini/settings.json` |
| Cursor | MCP server | `~/.cursor` | `~/.cursor/mcp.json` |
| Windsurf | MCP server | `~/.codeium/windsurf` | `~/.codeium/windsurf/mcp_config.json` |
| Continue.dev | MCP server | `~/.continue` | `~/.continue/config.json` |
| Aider | MCP server | `~/.aider.conf.yml` | `~/.aider.conf.yml` |

`rafter agent init` auto-detects which platforms are installed. Use `--with-*` flags or `--all` to install integrations.

## Skill-based platforms

Claude Code, Codex, and OpenClaw get the full Rafter skill set:

- **`rafter`** — CYOA router for detection (remote + local scanning, audit log, policy).
- **`rafter-code-review`** — Structured OWASP / MITRE / ASVS walkthrough during PR review or refactoring.
- **`rafter-secure-design`** — Shift-left threat modeling at feature kickoff (auth, data, API, ingestion, deployment, dependencies).
- **`rafter-skill-review`** — Guided review of third-party skills before install.

Install, remove, or audit them at any time with `rafter skill list/install/uninstall/review`.

## MCP-based platforms

Gemini, Cursor, Windsurf, Continue.dev, and Aider connect to the Rafter MCP server (`rafter mcp serve`), which exposes `scan_secrets`, `evaluate_command`, `read_audit_log`, and `get_config` tools. See individual setup recipes in [`recipes/`](../recipes/).

## See also

- [README](../README.md) — top-level overview
- [docs/local-toolkit.md](local-toolkit.md) — setup walkthrough and skill management
- [docs/adding-a-platform.md](adding-a-platform.md) — contract for adding a new agent IDE
- [`recipes/`](../recipes/) — per-platform copy-paste setup recipes
