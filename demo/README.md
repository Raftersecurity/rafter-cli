# Rafter CLI — Interactive Demo

This directory is a self-contained demo project for showcasing all Rafter CLI features.

## Quick Start

```bash
cd demo
# In Claude Code, run:
/rafter-showcase
```

The `/rafter-showcase` skill walks through all 9 core features with live commands:

1. Secret scanning (21+ patterns, JSON output, staged/diff modes)
2. Command interception (4 risk tiers)
3. Policy-as-code (`.rafter.yml`)
4. Audit logging (JSONL trail)
5. Pre-commit hooks
6. CI/CD integration (GitHub Actions)
7. MCP server (4 tools, 2 resources)
8. Skill auditing
9. Remote SAST/SCA (requires API key)

## What's in here

- `.env.example` — Fake AWS, Stripe, GitHub, Slack credentials
- `src/config.js` — JS config with hardcoded secrets
- `src/app.py` — Python app with hardcoded secrets + private key
- `src/deploy.sh` — Shell commands across all 4 risk tiers
- `.rafter.yml` — Example policy file
- `.claude/commands/demo.md` — The demo skill

All secrets are well-known example/fake values — they exist to trigger rafter's detectors.

## Prerequisites

```bash
npm install -g @rafter-security/cli   # or: pip install rafter-cli
rafter agent init                     # initialize rafter
```

For Act 9 (remote scanning), set `RAFTER_API_KEY` in your environment.
