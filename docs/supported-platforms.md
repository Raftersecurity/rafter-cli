# Supported Platforms

[← Back to README](../README.md)

| Platform     | Integration surface                                             | Detection                    | Primary install paths |
|--------------|-----------------------------------------------------------------|------------------------------|------------------------|
| Claude Code  | Skills + sub-agent + hooks + MCP + CLAUDE.md                    | `~/.claude`                  | `~/.claude/skills/<skill>/SKILL.md`, `~/.claude/agents/rafter.md`, `~/.claude/settings.json`, `.mcp.json` (project) |
| Codex CLI    | Skills + hooks + AGENTS.md                                      | `~/.codex`                   | `~/.agents/skills/<skill>/SKILL.md`, `~/.codex/hooks.json`, `AGENTS.md` |
| Gemini CLI   | Skills + hooks + MCP + GEMINI.md                                | `~/.gemini`                  | `~/.agents/skills/<skill>/SKILL.md` (+ `gemini skills link`), `~/.gemini/settings.json`, `GEMINI.md` |
| Cursor       | Per-skill rules + sub-agent + hooks + MCP                       | `~/.cursor`                  | `~/.cursor/rules/<skill>.mdc`, `~/.cursor/agents/rafter.md`, `~/.cursor/hooks.json`, `~/.cursor/mcp.json` |
| Windsurf     | Per-skill rules + AGENTS.md + MCP                               | `~/.codeium/windsurf`        | `<project>/.windsurf/rules/<skill>.md`, `<project>/AGENTS.md`, `~/.codeium/windsurf/mcp_config.json` |
| Continue.dev | Per-skill rules + MCP                                           | `~/.continue`                | `<project>/.continue/rules/<skill>.md`, `~/.continue/config.json` |
| Aider        | Read-only context (`RAFTER.md` injected via `.aider.conf.yml`)  | `~/.aider.conf.yml` or local | `<root>/RAFTER.md`, `<root>/.aider.conf.yml` (`read:` entry) |
| OpenClaw     | ClawHub skill                                                   | `~/.openclaw`                | `~/.openclaw/workspace/skills/rafter-security/SKILL.md` |

`rafter agent init` auto-detects installed platforms. Use `--with-<platform>` flags, `--all`, or `--local` for project-scope installs (Claude Code, Codex, Gemini, Cursor, Windsurf, Continue.dev, and Aider support project-local installs; OpenClaw is user-scope only).

## Skills, rules, and the four shipped templates

The same four `resources/skills/<name>/SKILL.md` templates drive every platform's
"skill-like" surface:

- **`rafter`** — CYOA router for detection (remote + local scanning, audit log, policy).
- **`rafter-code-review`** — Structured OWASP / MITRE / ASVS walkthrough during PR review or refactoring.
- **`rafter-secure-design`** — Shift-left threat modeling at feature kickoff (auth, data, API, ingestion, deployment, dependencies).
- **`rafter-skill-review`** — Guided review of third-party skills before install.

Platforms with a native SKILL.md primitive (Claude Code, Codex, Gemini, OpenClaw)
install the templates verbatim. Platforms with a rules primitive (Cursor,
Windsurf, Continue.dev) ship per-skill rule files generated from
`resources/<platform>-rules/`. Aider injects `RAFTER.md` via the `.aider.conf.yml`
`read:` list — there's no skill primitive in Aider.

Install, remove, or audit individual skill files at any time with `rafter skill list/install/uninstall/review`. For per-component lifecycle (hooks, MCP, rules, sub-agents, instruction files) use `rafter agent list / enable <id> / disable <id>`.

## MCP server

Claude Code, Cursor, Windsurf, Continue.dev, and Gemini connect to the Rafter
MCP server (`rafter mcp serve`), which exposes `scan_secrets`,
`evaluate_command`, `read_audit_log`, and `get_config` tools plus
`rafter://config` and `rafter://policy` resources over stdio. Codex, Aider, and
OpenClaw do not have native MCP support — they rely on the other surfaces
listed above.

## See also

- [README](../README.md) — top-level overview
- [docs/local-toolkit.md](local-toolkit.md) — setup walkthrough and skill management
- [docs/adding-a-platform.md](adding-a-platform.md) — contract for adding a new agent IDE
- [`recipes/`](../recipes/) — per-platform copy-paste setup recipes
- [`shared-docs/PLATFORM_PARITY_AUDIT.md`](../shared-docs/PLATFORM_PARITY_AUDIT.md) — full parity matrix and gap log
