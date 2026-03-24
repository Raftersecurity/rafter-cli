# Directory & Registry Outreach Plan

Submission plan for getting Rafter listed in MCP server directories, Claude Code skill registries, and AI coding tool lists.

---

## Rafter Listing Metadata

Use this metadata across all submissions. Tailor per directory as needed.

### Short Description (one-liner)
> Security agent for AI coding workflows — secret scanning, command interception, audit logging, and SAST/SCA via MCP server. Works with Claude Code, Cursor, Windsurf, Gemini CLI, Codex, Aider, Continue.dev, and OpenClaw.

### MCP Server Details

**Command:** `rafter mcp serve`

**Config:**
```json
{
  "rafter": {
    "command": "rafter",
    "args": ["mcp", "serve"]
  }
}
```

**Tools exposed:**
| Tool | Description |
|------|-------------|
| `scan_secrets` | Scan files or directories for hardcoded secrets (21+ patterns: AWS, GitHub, Google, Slack, Stripe, private keys, JWTs, etc.) |
| `evaluate_command` | Check if a shell command is allowed by the active security policy (risk-tiered: low/medium/high/critical) |
| `read_audit_log` | Read and filter security audit log entries |
| `get_config` | Read current Rafter configuration and effective policy |

**Resources exposed:**
| Resource | Description |
|----------|-------------|
| `rafter://config` | Current Rafter configuration |
| `rafter://policy` | Active security policy (merged project `.rafter.yml` + global config) |

### Key Differentiators
- **8-platform support** — Claude Code, Codex CLI, OpenClaw, Gemini CLI, Cursor, Windsurf, Continue.dev, Aider
- **Zero-friction setup** — `rafter agent init --all` auto-detects installed agents
- **No API key required** for local security features (secret scanning, command interception, audit logging)
- **MCP server** for any MCP-compatible client
- **Dual implementation** — Node.js (`@rafter-security/cli`) and Python (`rafter-cli`) with full feature parity
- **Stable output contract** — documented exit codes, consistent JSON schemas, deterministic results
- **Pre-commit hook** — blocks secrets before they enter git history
- **Delegation primitive** — other agents defer security decisions to Rafter and trust the structured output

### Links
- **Website:** https://rafter.so
- **GitHub:** https://github.com/Raftersecurity/rafter-cli
- **npm:** `@rafter-security/cli`
- **PyPI:** `rafter-cli`

### Categories
Security, Code Analysis, Secret Scanning, DevSecOps, Pre-commit Hooks, Agent Security

---

## 1. punkpeye/awesome-mcp-servers

**Priority:** Highest — ~84K stars, the dominant MCP server list

**URL:** https://github.com/punkpeye/awesome-mcp-servers

**Maintainer:** [@punkpeye](https://github.com/punkpeye)

**Submission process:** Fork the repo, add entry to `README.md` under the correct category (alphabetical order), submit PR.

**Category:** Security (or DevTools > Security if subcategorized)

**Proposed entry:**
```markdown
- [Rafter](https://github.com/Raftersecurity/rafter-cli) - Security agent for AI coding workflows. Secret scanning (21+ patterns), command risk assessment, audit logging, and configuration management. Works offline, no API key needed.
```

**PR title:** `Add Rafter MCP server (security scanning & command interception)`

**PR body:**
```
Adding Rafter — a security-focused MCP server for AI coding agents.

**What it does:**
- `scan_secrets` — Scans files for hardcoded secrets (AWS keys, GitHub tokens, private keys, etc.)
- `evaluate_command` — Risk-assesses shell commands before execution (blocks `rm -rf /`, flags `sudo` operations)
- `read_audit_log` — Retrieves security event history
- `get_config` — Reads active security policy

**Why it belongs here:**
Rafter is purpose-built for the AI agent workflow. It's the security layer that agents like Cursor, Windsurf, and Claude Code use to prevent secrets from leaking and dangerous commands from executing. Auto-detects 8 agent platforms with `rafter agent init --all`.

Available on npm (`@rafter-security/cli`) and PyPI (`rafter-cli`). No API key required for local features.
```

**Notes:** The repo supports automated PRs — adding `robot robot robot` to the PR title fast-tracks merging. Consider using this if submitting programmatically.

---

## 2. Official MCP Registry (modelcontextprotocol/registry)

**Priority:** Highest — the canonical registry backed by Anthropic, GitHub, PulseMCP, Microsoft

**URL:** https://github.com/modelcontextprotocol/registry
**Live site:** https://registry.modelcontextprotocol.io

**Maintainers:** Adam Jones (Anthropic), Tadas Antanavicius (PulseMCP), Toby Padilla (GitHub), Radoslav Dimitrov (Stacklok). Lead: David Soria Parra.

**Submission process:** Use the CLI publisher tool:
```bash
git clone https://github.com/modelcontextprotocol/registry
cd registry
make publisher
./bin/mcp-publisher
```
Requires namespace ownership verification via one of:
- GitHub OAuth (interactive)
- GitHub OIDC (for CI)
- DNS TXT record verification
- HTTP `.well-known` verification

**Registry entry fields:**
```json
{
  "name": "rafter",
  "description": "Security agent for AI coding workflows — secret scanning, command interception, audit logging",
  "repository": {
    "url": "https://github.com/Raftersecurity/rafter-cli",
    "source": "github"
  },
  "version_detail": {
    "version": "0.6.5"
  },
  "packages": [
    {
      "registry_name": "npm",
      "name": "@rafter-security/cli"
    },
    {
      "registry_name": "pypi",
      "name": "rafter-cli"
    }
  ],
  "remotes": [
    {
      "transport_type": "stdio",
      "command": "rafter",
      "args": ["mcp", "serve"]
    }
  ]
}
```

**Notes:** API is frozen at v0.1 — stable surface. This is where Claude Desktop and other first-party clients will look for servers.

---

## 3. hesreallyhim/awesome-claude-code

**Priority:** High — ~32K stars, primary Claude Code ecosystem list

**URL:** https://github.com/hesreallyhim/awesome-claude-code

**Maintainer:** [@hesreallyhim](https://github.com/hesreallyhim)

**Submission process:** Fork and PR. No formal CONTRIBUTING.md — follow existing entry format.

**Proposed entry (under Security or Hooks/Skills section):**
```markdown
- [Rafter](https://github.com/Raftersecurity/rafter-cli) - Security agent with PreToolUse/PostToolUse hooks and two Claude Code skills. Secret scanning, command interception, audit logging. Supports 8 AI coding platforms. `rafter agent init --with-claude-code` to install.
```

**PR title:** `Add Rafter — security agent with hooks and skills for Claude Code`

**PR body:**
```
Rafter provides security tooling specifically designed for Claude Code:

**Claude Code integration:**
- 2 skills installed to `~/.claude/skills/` — one for backend SAST/SCA scanning (auto-invocable), one for local security (user-invoked)
- PreToolUse hook intercepts Bash and Write/Edit commands for risk assessment
- PostToolUse hook logs all tool usage to audit trail
- MCP server (`rafter mcp serve`) as an additional integration path

**What it protects against:**
- Secrets committed to git (21+ patterns: AWS, GitHub, Stripe, private keys, etc.)
- Dangerous command execution (risk-tiered assessment)
- Unaudited agent actions (full audit logging)

**Setup:** `npm i -g @rafter-security/cli && rafter agent init --with-claude-code`

Also works with Cursor, Windsurf, Gemini CLI, Codex CLI, Continue.dev, Aider, and OpenClaw.
```

---

## 4. travisvn/awesome-claude-skills

**Priority:** High — ~10K stars, focused on Claude skills specifically

**URL:** https://github.com/travisvn/awesome-claude-skills

**Maintainer:** [@travisvn](https://github.com/travisvn)

**Submission process:** Fork and PR. Skills should include proper SKILL.md with frontmatter.

**Proposed entry (under Security or Developer Tools):**
```markdown
- [Rafter Security](https://github.com/Raftersecurity/rafter-cli) - Two-skill security suite: (1) auto-invocable SAST/SCA scanning skill for backend code analysis, (2) user-invoked local security skill for secret scanning, command interception, and audit logging. Install with `rafter agent init --with-claude-code`.
```

**PR title:** `Add Rafter security skills (scanning + agent protection)`

**PR body:**
```
Rafter installs two complementary skills to `~/.claude/skills/`:

1. **Rafter Security Audits** (`rafter/SKILL.md`) — Auto-invocable. Triggers remote SAST/SCA code analysis on GitHub repos. Returns structured vulnerability reports. Safe for automatic invocation (read-only API calls).

2. **Agent Security** (`rafter-agent-security/SKILL.md`) — User-invoked. Local-first security:
   - `rafter scan local .` — scan for secrets (21+ patterns)
   - `rafter agent exec <cmd>` — risk-assess commands before running
   - `rafter agent audit` — view security event log
   - `rafter agent audit-skill <path>` — audit extensions/skills for safety

Also installs PreToolUse/PostToolUse hooks for transparent command interception and audit logging.

Works with 8 platforms total. Install: `npm i -g @rafter-security/cli && rafter agent init --all`
```

---

## 5. VoltAgent/awesome-agent-skills

**Priority:** High — ~13K stars, cross-platform agent skills

**URL:** https://github.com/VoltAgent/awesome-agent-skills

**Maintainer:** [@VoltAgent](https://github.com/VoltAgent) (org)

**Submission process:** Fork and PR.

**Proposed entry:**
```markdown
- [Rafter Security](https://github.com/Raftersecurity/rafter-cli) - Security agent skills for Claude Code, Codex CLI, Gemini CLI, Cursor, Windsurf, Continue.dev, Aider, and OpenClaw. Secret scanning (21+ patterns), command risk assessment, audit logging, and SAST/SCA code analysis. Auto-detects installed agents with `rafter agent init --all`.
```

**PR title:** `Add Rafter — security skills for 8 AI coding platforms`

**PR body:**
```
Rafter provides security skills and MCP server integration for 8 AI coding platforms.

**Skill-based platforms** (Claude Code, Codex, OpenClaw): Two skills installed per agent — backend SAST/SCA scanning and local agent security (secret scanning, command interception, audit logging).

**MCP-based platforms** (Cursor, Windsurf, Gemini CLI, Continue.dev, Aider): MCP server with `scan_secrets`, `evaluate_command`, `read_audit_log`, and `get_config` tools.

Zero-friction: `npm i -g @rafter-security/cli && rafter agent init --all`
No API key needed for local security features.
```

---

## 6. mcp.so

**Priority:** Medium-high — ~19K servers indexed, community-driven

**URL:** https://mcp.so
**GitHub:** https://github.com/chatmcp/mcpso

**Maintainer:** [@chatmcp](https://github.com/chatmcp) (org)

**Submission process:** Create a GitHub issue on `chatmcp/mcpso` or use the Submit button on mcp.so (which links to GitHub issues).

**Issue title:** `[New Server] Rafter — Security scanning & command interception for AI agents`

**Issue body:**
```
**Server Name:** Rafter

**Description:** Security agent for AI coding workflows. Provides secret scanning (21+ patterns including AWS, GitHub, Stripe, private keys), command risk assessment, audit logging, and configuration management via MCP.

**MCP Tools:**
- `scan_secrets` — Scan files/directories for hardcoded secrets
- `evaluate_command` — Risk-assess shell commands before execution
- `read_audit_log` — Read security audit log entries
- `get_config` — Read current security configuration

**MCP Resources:**
- `rafter://config` — Current configuration
- `rafter://policy` — Active security policy

**Install:**
```
npm i -g @rafter-security/cli
```

**Config:**
```json
{
  "rafter": {
    "command": "rafter",
    "args": ["mcp", "serve"]
  }
}
```

**Links:**
- GitHub: https://github.com/Raftersecurity/rafter-cli
- Website: https://rafter.so
- npm: @rafter-security/cli
- PyPI: rafter-cli

**Category:** Security

**Notes:** Works with 8 AI coding platforms (Claude Code, Cursor, Windsurf, Gemini CLI, Codex CLI, Continue.dev, Aider, OpenClaw). No API key needed for local features. Available in both Node.js and Python.
```

---

## 7. PulseMCP

**Priority:** Medium-high — 12K+ servers, updated daily, co-maintained with official registry

**URL:** https://www.pulsemcp.com/servers

**Maintainer:** Tadas Antanavicius (also a maintainer of the official MCP Registry)

**Submission process:** Use the Submit button at https://www.pulsemcp.com/submit

**Submission details:**
- **Server name:** Rafter
- **Description:** Security agent for AI coding workflows — secret scanning, command risk assessment, audit logging, and configuration management
- **GitHub URL:** https://github.com/Raftersecurity/rafter-cli
- **Category:** Security / DevTools
- **Transport:** stdio
- **Command:** `rafter mcp serve`

**Notes:** PulseMCP also publishes a newsletter — reaching out to Tadas about a potential feature in "THE MCP newsletter" could provide additional visibility. Since he's also an official registry maintainer, a positive relationship here helps with the registry submission too.

---

## 8. Smithery.ai

**Priority:** Medium — 7K+ servers, marketplace with analytics

**URL:** https://smithery.ai
**Publishing docs:** https://smithery.ai/docs/build/publish

**Maintainer:** Smithery AI (company)

**Submission process:**
1. Go to https://smithery.ai/new
2. Enter the server's public HTTPS URL
3. Smithery scans the server to extract metadata (tools, prompts, resources)
4. Complete the publishing workflow

**Requirements:**
- Server must support Streamable HTTP transport (Smithery proxies requests)
- If scanning fails, provide a static `/.well-known/mcp/server-card.json`
- OAuth if authentication is needed (Smithery handles client registration)

**Action needed:** Rafter currently uses stdio transport. Smithery requires Streamable HTTP. Two options:
1. Add HTTP transport to `rafter mcp serve` (e.g., `rafter mcp serve --transport http --port 3000`)
2. Skip Smithery for now and revisit when/if HTTP transport is added

**Notes:** Smithery provides analytics and a hosted execution environment. Worth pursuing if HTTP transport is added to the MCP server.

---

## 9. Glama.ai

**Priority:** Medium — auto-indexes from GitHub, large user base

**URL:** https://glama.ai/mcp/servers

**Maintainer:** Glama (company)

**Submission process:** Glama auto-indexes MCP servers from GitHub. No manual submission required in most cases. If the repo isn't picked up automatically:
- Check if the repo has proper MCP metadata (package.json with keywords, README with MCP documentation)
- Contact via Discord for manual inclusion

**Action items:**
- Ensure `package.json` has `"mcp"` and `"mcp-server"` keywords
- Verify README clearly documents MCP server usage
- Monitor https://glama.ai/mcp/servers for automatic inclusion
- If not indexed within 2 weeks, reach out via Glama's Discord

---

## 10. appcypher/awesome-mcp-servers

**Priority:** Medium — ~5K stars, another well-known MCP list

**URL:** https://github.com/appcypher/awesome-mcp-servers

**Maintainer:** [@appcypher](https://github.com/appcypher)

**Submission process:** Fork and PR. Follow awesome-list guidelines (alphabetical, one PR per suggestion, check for duplicates).

**Proposed entry:**
```markdown
- [Rafter](https://github.com/Raftersecurity/rafter-cli) - Security scanning and command interception for AI coding agents. Secret detection (21+ patterns), risk-tiered command evaluation, audit logging.
```

**PR title:** `Add Rafter security MCP server`

---

## 11. ai-for-developers/awesome-ai-coding-tools

**Priority:** Low-medium — ~1.6K stars, broader AI coding tools list

**URL:** https://github.com/ai-for-developers/awesome-ai-coding-tools

**Maintainer:** [@ai-for-developers](https://github.com/ai-for-developers) (org)

**Submission process:** Fork and PR.

**Proposed entry (under Security or Extensions/Plugins section):**
```markdown
- [Rafter](https://github.com/Raftersecurity/rafter-cli) - Security agent for AI coding workflows. Secret scanning, command interception, and audit logging for Claude Code, Cursor, Windsurf, Gemini CLI, and more. MCP server included.
```

---

## Submission Priority & Execution Order

| Order | Directory | Method | Est. Effort |
|-------|-----------|--------|-------------|
| 1 | Official MCP Registry | CLI publisher tool | Medium (namespace verification) |
| 2 | punkpeye/awesome-mcp-servers | GitHub PR | Low |
| 3 | hesreallyhim/awesome-claude-code | GitHub PR | Low |
| 4 | travisvn/awesome-claude-skills | GitHub PR | Low |
| 5 | VoltAgent/awesome-agent-skills | GitHub PR | Low |
| 6 | PulseMCP | Web form | Low |
| 7 | mcp.so | GitHub issue | Low |
| 8 | appcypher/awesome-mcp-servers | GitHub PR | Low |
| 9 | Glama.ai | Auto-indexed (verify) | Minimal |
| 10 | ai-for-developers/awesome-ai-coding-tools | GitHub PR | Low |
| 11 | Smithery.ai | Web form (needs HTTP transport) | Blocked |

**Quick wins (can submit today):** #2-8, #10 — all are simple PR or issue submissions.
**Requires setup:** #1 — namespace verification for the official registry.
**Blocked:** #11 — Smithery requires HTTP transport, which Rafter's MCP server doesn't support yet.
**Passive:** #9 — Glama auto-indexes; just verify keywords are in package.json.
