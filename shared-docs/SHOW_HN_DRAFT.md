# Show HN Draft

> **Status:** Draft — needs founder review before posting.
> **Target:** Hacker News "Show HN" — post between 8-9am ET, Tue-Thu.
> **Bead:** rc-9g6

---

## Title options (pick one)

1. **Show HN: Rafter – Security toolkit for developers (agents are devs too)**
2. **Show HN: Rafter – Secret scanning, policy enforcement, and custom rules in one CLI**
3. **Show HN: Rafter – One security CLI for 8 dev platforms (Claude Code, Cursor, Codex, etc.)**

## Post body

Hi HN, I'm [NAME] and I built Rafter, an open-source security toolkit for developers. Agents are developers too — they read code, write code, run commands, and commit. They deserve the same security tooling.

**The problem:** Developers now work across 8+ tools — terminal, IDE, Claude Code, Cursor, Codex — and each has a different security story. Secrets leak in commits, destructive commands run without checks, and third-party extensions go unvetted. You shouldn't need a different security setup for each tool.

**What Rafter does:**

- **Secret scanning** — 21+ built-in patterns (AWS, GitHub, Stripe, etc.), pre-commit hooks, CI integration. Dual engine: tries Gitleaks first, falls back to built-in regex. Deterministic — same inputs, same findings. JSON output you can pipe to `jq` or feed to any tool.
- **Custom rules** — Define your own patterns in `.rafter.yml`. They work exactly like built-in rules — same JSON output, same audit log, same pre-commit enforcement.
- **Policy enforcement** — 4-tier risk classification (critical/high/medium/low). Blocks `rm -rf /`, requires approval for `sudo rm`, allows `npm install`. Same rules for every developer.
- **Extension auditing** — Scans third-party extensions for embedded secrets, suspicious URLs, and obfuscated commands before you install them.
- **8 platforms** — Claude Code, Codex CLI, OpenClaw, Gemini CLI, Cursor, Windsurf, Continue.dev, Aider. One `rafter agent init --all` configures all of them.
- **MCP server** — `rafter mcp serve` exposes tools to any MCP-compatible client.

**What's different:**

Agents are developers. They scan, commit, push, and deploy — so they need the same security primitives any developer does. Rafter provides one set of tools (scan, enforce, audit) that work identically across all 8 platforms. Structured JSON output, documented exit codes, and a stable contract mean any developer can act on findings without parsing prose.

No other tool covers all 8 platforms. Rafter also combines scanning + policy enforcement + custom rules + extension audit + MCP + CI in one package.

**Free and local:** No API key, no account, no telemetry. MIT licensed. Everything runs on your machine.

**Technical decisions:**
- Dual implementation (TypeScript + Python) for maximum reach
- Deterministic scanning — same inputs, same outputs across versions
- UNIX philosophy — JSON to stdout, status to stderr, documented exit codes
- Stable output contract — any developer can rely on the schema

Install: `npm i -g @rafter-security/cli` or `pip install rafter-cli`

GitHub: https://github.com/Raftersecurity/rafter-cli

Would love feedback on the pattern library, custom rule authoring, and which platforms to prioritize next.

---

## Comment strategy

Founder should be in comments within 5 minutes of posting. Prepared answers for likely questions:

**Q: "Why not just use Gitleaks directly?"**
A: Rafter uses Gitleaks when available but adds policy enforcement, custom rules, extension auditing, multi-platform config, and MCP. It's the integration layer, not a replacement.

**Q: "How is this different from pre-commit hooks?"**
A: Pre-commit catches secrets at commit time. Rafter also enforces policy on live commands, audits extensions, and works at runtime — not just commit time.

**Q: "8 platforms sounds like spread too thin"**
A: Each adapter is ~50-100 lines. The core logic (scanning, policy enforcement, audit) is shared. Platform adapters just know where to write config files.

**Q: "What's the business model?"**
A: CLI is free and MIT. Enterprise adds dashboards, policy management, and compliance reporting.

**Q: "Can I trust a security tool built with AI?"**
A: We use AI for development but every change goes through automated tests (600+), secret scanning (Rafter scans itself), and human review. We note AI involvement in commits.
