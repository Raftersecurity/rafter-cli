# Show HN FAQ -- Pre-written Comment Responses

Responses written in founder voice. Adapt as needed based on the actual question.

---

## "How is this different from gitleaks / trufflehog?"

Rafter actually wraps gitleaks when it's available -- if the binary is on your PATH, we use it as the primary scanner because it's excellent. Our built-in regex engine (21+ patterns) is the fallback for zero-dependency environments.

The difference is everything around the scan. Gitleaks and trufflehog are standalone secret scanners. Rafter adds command interception (blocking `curl | bash` before your agent runs it), audit logging of agent sessions, MCP integration so the agent itself can check for secrets, pre-commit hooks, and one-command setup for 8 different AI platforms. If you're just scanning repos for secrets, gitleaks is great and you don't need us. If you're running AI coding agents and want guardrails around the whole session, that's what Rafter is for.

---

## "Why would I need this if my IDE already has security extensions?"

IDE security extensions cover the IDE. They don't cover Claude Code running in your terminal, Codex CLI, Aider, or any other non-IDE agent. And even for IDE-based agents like Cursor and Windsurf, the security extensions typically scan files on save -- they don't intercept commands before the agent executes them.

Rafter gives you one config (`.rafter.yml`) that works across all 8 platforms. Switch between Cursor and Claude Code during the day, same policies apply.

---

## "Is the remote scanning sending my code somewhere?"

Only if you explicitly use the remote SAST/SCA API, which requires an API key you have to go get and configure. Every local feature -- secret scanning, command interception, audit logging, MCP server, pre-commit hooks -- runs entirely on your machine. No network calls, no telemetry, no phone-home. You can verify this yourself; it's MIT-licensed.

---

## "Why dual implementation (Node.js and Python)?"

Some agent ecosystems are Python-native (Aider, many MCP setups), others are Node-native (Cursor extensions, npm-based toolchains). If we only shipped one, half our users would be installing a runtime they don't otherwise need just to run a security tool. Both implementations follow the same spec (`shared-docs/CLI_SPEC.md`), same exit codes, same JSON output schemas, same version numbers. CI enforces parity. No second-class citizens.

---

## "What's the business model?"

Free for individuals and open source. Forever. No bait-and-switch -- the CLI is MIT-licensed and fully functional without any account or API key.

The enterprise tier (not launched yet) will be dashboards, centralized policy management, compliance reporting, and team-wide audit aggregation. The stuff a CISO needs that an individual developer doesn't. The local CLI stays free regardless.

---

## "Why not just use .gitignore?"

`.gitignore` prevents files from being tracked. It doesn't help when an AI agent writes `AWS_SECRET_ACCESS_KEY=AKIA...` inline in your Python file, puts a database password in a config object, or generates a `.env` file and then references it in committed code. Agents generate code with hardcoded secrets all the time because they're optimizing for "make it work" not "make it secure."

Rafter scans the actual content of files and staged changes, not just filenames.

---

## "How does it compare to Snyk / Semgrep?"

Different problem space. Snyk and Semgrep are broad AppSec platforms -- vulnerability databases, SAST rule engines, dependency analysis, the works. They're designed for CI pipelines and developer workflows.

Rafter specifically targets the gap that AI coding agents create: commands being executed without review, secrets appearing in generated code, no audit trail of what the agent did during a session, no way to enforce policies across 8 different agent platforms with one config. We're complementary -- you'd run Semgrep in CI for deep static analysis and Rafter locally to keep your AI agent from leaking your AWS keys or running `chmod 777 /` while you're getting coffee.
