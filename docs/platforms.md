# Supported Platforms

`rafter agent init` auto-detects which platforms are installed.
Use `--with-<platform>` flags or `--all` to install integrations.

## Integration table

| Platform | Integration | Detection | Config installed to |
|-------|-------------|-----------|-------------------|
| Claude Code | Hooks + Skills | `~/.claude` | `~/.claude/skills/rafter/` and `rafter-agent-security/` |
| Codex CLI | Skills | `~/.codex` | `~/.agents/skills/rafter/` and `rafter-agent-security/` |
| OpenClaw | Skills | `~/.openclaw` | `~/.openclaw/skills/rafter-security.md` |
| Gemini CLI | MCP server | `~/.gemini` | `~/.gemini/settings.json` |
| Cursor | MCP server | `~/.cursor` | `~/.cursor/mcp.json` |
| Windsurf | MCP server | `~/.codeium/windsurf` | `~/.codeium/windsurf/mcp_config.json` |
| Continue.dev | MCP server | `~/.continue` | `~/.continue/config.json` |
| Aider | MCP server | `~/.aider.conf.yml` | `~/.aider.conf.yml` |

## Skill-based platforms

Claude Code, Codex CLI, and OpenClaw get the full Rafter skill set:

| Skill | When to use |
|-------|-------------|
| `rafter` | CYOA router — detection (`rafter scan` / `rafter run`) and day-to-day usage |
| `rafter-code-review` | OWASP / MITRE / ASVS-style structured code review during PR / refactor |
| `rafter-secure-design` | Shift-left design-phase threat modeling at feature kickoff |
| `rafter-skill-review` | Guided security review of third-party skills before install |

Manage skills at any time:

```sh
rafter skill list                              # show installed + available skills
rafter skill install rafter-code-review        # install one
rafter skill install --all                     # install all four
rafter skill uninstall rafter-secure-design    # remove one
```

## MCP-based platforms

Gemini, Cursor, Windsurf, Continue.dev, and Aider connect to the Rafter MCP server
(`rafter mcp serve`). See [docs/mcp.md](mcp.md) and the per-platform recipes in [`recipes/`](../recipes/).

## Auditing untrusted skills

**Treat third-party agent skill ecosystems as hostile by default.** There have been reports of
malware distributed through AI agent skill marketplaces.

```sh
rafter skill review ./path/to/skill           # local file or directory
rafter skill review github:owner/repo         # remote shorthand (also gitlab:, npm:)
rafter skill review --installed               # audit every skill already on disk
rafter skill review --installed --summary     # terse table across all agents
```

Quick scan detects: embedded secrets, external URLs, high-risk commands (`curl|sh`, `eval()`),
obfuscation signals, and binary/suspicious file inventory.
