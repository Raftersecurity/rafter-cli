# Show HN Draft

> **Status:** Draft — needs founder review before posting.
> **Target:** Hacker News "Show HN" — post between 8-9am ET, Tue-Thu.
> **Bead:** rc-9g6

---

## Title options (pick one)

1. **Show HN: Rafter – Zero-setup security for AI coding agents (8 platforms)**
2. **Show HN: Rafter – Secret scanning and guardrails for Claude Code, Cursor, Codex, and 5 more**
3. **Show HN: Rafter – One CLI that adds security to any AI coding agent**

## Post body

Hi HN, I'm [NAME] and I built Rafter, an open-source security CLI for AI coding agents.

**The problem:** AI agents write and execute code autonomously. They commit secrets, run destructive commands, and install unvetted extensions — and most developers don't have guardrails in place because each agent has a different config format.

**What Rafter does:**

- **Secret scanning** — 21+ patterns (AWS, GitHub, Stripe, etc.), pre-commit hooks, CI integration. Dual engine: tries Gitleaks first, falls back to built-in regex with zero dependencies.
- **Command interception** — 4-tier risk classification (critical/high/medium/low). Blocks `rm -rf /`, requires approval for `sudo rm`, allows `npm install`.
- **Skill auditing** — Scans third-party agent extensions for embedded secrets, suspicious URLs, and obfuscated commands.
- **8-platform coverage** — Claude Code, Codex CLI, OpenClaw, Gemini CLI, Cursor, Windsurf, Continue.dev, Aider. One `rafter agent init --all` configures all of them.
- **MCP server** — `rafter mcp serve` exposes tools to any MCP-compatible client.

**What's different:**

No other tool covers all 8 platforms. Knostic Kirin does 4, GitGuardian MCP does 2, GitHub MCP does 1. Rafter also combines secrets + command interception + skill audit + MCP + CI in one package.

**Free and local:** No API key, no account, no telemetry for agent security features. MIT licensed. Everything runs on your machine.

**Technical decisions:**
- Dual implementation (TypeScript + Python) for maximum reach
- Deterministic scanning — same inputs, same outputs across versions
- UNIX philosophy — JSON to stdout, status to stderr, documented exit codes
- Stable output contract — orchestrators can rely on the schema

Install: `npm i -g @rafter-security/cli` or `pip install rafter-cli`

GitHub: https://github.com/Raftersecurity/rafter-cli

Would love feedback on the pattern library, risk classification tiers, and which platforms to prioritize next.

---

## Comment strategy

Founder should be in comments within 5 minutes of posting. Prepared answers for likely questions:

**Q: "Why not just use Gitleaks directly?"**
A: Rafter uses Gitleaks when available but adds command interception, skill auditing, multi-agent config, and MCP. It's the integration layer, not a replacement.

**Q: "How is this different from pre-commit hooks?"**
A: Pre-commit catches secrets at commit time. Rafter also intercepts live commands, audits agent extensions, and works at runtime — not just commit time.

**Q: "8 platforms sounds like spread too thin"**
A: Each adapter is ~50-100 lines. The core logic (scanning, interception, audit) is shared. Platform adapters just know where to write config files.

**Q: "What's the business model?"**
A: CLI is free and MIT. Enterprise adds dashboards, policy management, and compliance reporting.

**Q: "Can I trust a security tool built with AI?"**
A: We use AI for development but every change goes through automated tests (600+), secret scanning (Rafter scans itself), and human review. We note AI involvement in commits.
