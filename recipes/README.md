# Rafter Recipes

Integration snippets for adding Rafter security to your development workflow. Each recipe is self-contained — stable exit codes, deterministic output, and structured JSON work the same across all surfaces.

| Recipe | What it does |
|--------|-------------|
| [GitHub Actions](github-actions.yml) | CI secret scanning on push/PR |
| [Pre-commit Hook](pre-commit.md) | Block secrets before they enter git |
| [Policy File](rafter-policy.yml) | Per-project security rules (`.rafter.yml`) |
| [Claude Code](claude-code.md) | Hook + skill setup for Claude Code |
| [Codex CLI](codex-cli.md) | Skill + policy setup for OpenAI Codex |
| [Gemini CLI](gemini-cli.md) | MCP server setup for Google Gemini CLI |
| [Cursor](cursor.md) | MCP server setup for Cursor |
| [Windsurf](windsurf.md) | MCP server setup for Windsurf (Codeium) |
| [Continue.dev](continue-dev.md) | MCP server setup for Continue.dev |
| [Aider](aider.md) | MCP server setup for Aider |
| [OpenClaw](openclaw.md) | Skill setup for OpenClaw agents |
| [Homebrew Formula](homebrew-formula.rb) | `brew install rafter` tap formula |

## Quick start

```sh
# Install (pick one)
npm install -g @rafter-security/cli
pip install rafter-cli

# One-command setup: config, gitleaks, agent skills
rafter agent init
```

All local security features work offline with no API key. Remote code analysis (`rafter run`) requires a key from [rafter.so](https://rafter.so).
