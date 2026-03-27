# Show HN: Rafter -- zero-setup security for AI coding agents (8 platforms, free)

If you use Claude Code, Codex CLI, Cursor, Gemini CLI, or similar tools, your AI agent can leak secrets, run dangerous commands, and generate code with hardcoded credentials. Rafter is a security CLI that sits between you and your AI agent to catch these problems.

**What it does:**

- **Secret scanning**: 21+ built-in regex patterns plus optional Gitleaks integration. Deterministic for a given version. Stable exit codes for CI.
- **Command interception**: Classifies commands into risk tiers (critical/high/medium/low) and enforces approval policies before execution.
- **Audit logging**: JSONL trail of every command your agent runs and every secret scan result.
- **MCP server**: 4 tools (`scan_secrets`, `evaluate_command`, `read_audit_log`, `get_config`) so AI agents can query security status natively.
- **Pre-commit hooks**: Block secrets before they hit git history.
- **Skill/extension auditing**: Inspect what third-party agent plugins actually do.

**8 platforms**: Claude Code, Codex CLI, OpenClaw, Gemini CLI, Cursor, Windsurf, Continue.dev, Aider. One `.rafter.yml` config works across all of them.

**Dual implementation**: Full Node.js and Python CLIs with feature parity. Install whichever fits your stack:

```
npm install -g @rafter-security/cli
pip install rafter-cli
```

Everything runs locally. No account, no telemetry, no API key needed. Nothing leaves your machine unless you explicitly opt into the remote SAST/SCA API for deeper analysis.

Free and MIT-licensed for individuals and open source. Forever.

I built this because I kept finding API keys in AI-generated code and watching agents run `rm -rf` without asking. Existing tools like gitleaks and Semgrep are great at what they do, but none of them understood the AI agent workflow -- intercepting commands before execution, auditing agent sessions, or integrating via MCP.

GitHub: https://github.com/raftersecurity/rafter-cli
