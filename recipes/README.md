# Rafter Recipes

Copy-paste integration snippets for common setups. Each recipe is self-contained and ready to drop into your project.

| Recipe | What it does |
|--------|-------------|
| [GitHub Actions](github-actions.yml) | CI secret scanning on push/PR |
| [Pre-commit Hook](pre-commit.md) | Block secrets before they enter git |
| [Policy File](rafter-policy.yml) | Per-project security rules (`.rafter.yml`) |
| [Claude Code](claude-code.md) | Hook + skill setup for Claude Code |
| [Codex CLI](codex-cli.md) | Skill + policy setup for OpenAI Codex |
| [OpenClaw](openclaw.md) | Skill setup for OpenClaw agents |

## Quick start

```sh
# Install (pick one)
npm install -g @rafter-security/cli
pip install rafter-cli

# One-command setup: config, gitleaks, agent skills
rafter agent init
```

All agent security features work offline with no API key. Backend scanning (`rafter run`) requires a key from [rafter.so](https://rafter.so).
