# Installation

## Node.js

```sh
npm install -g @rafter-security/cli
# or
pnpm add -g @rafter-security/cli
```

## Python

```sh
pip install rafter-cli
```

Requires Python 3.10+. Full feature parity with Node.js including local security toolkit and MCP server.

## Verify

```sh
rafter --version
```

## Setup integrations

```sh
rafter agent init --all                    # install all detected integrations
rafter agent init --with-claude-code       # install specific one
rafter agent init --local                  # write config to ./.rafter (not ~/.rafter)
rafter agent list                          # show detected integrations + status
rafter agent enable claude-code            # opt a single platform in
rafter agent disable gemini                # opt a single platform out
```

`rafter agent init` auto-detects Claude Code, Codex CLI, OpenClaw, Gemini, Cursor, Windsurf,
Continue.dev, and Aider. With `--all` it installs Betterleaks (the gitleaks successor) for
enhanced secret scanning, falling back to the built-in 21-pattern scanner.

## File locations

```
~/.rafter/
├── config.json        # Configuration
├── audit.jsonl        # Security event log (JSON lines)
├── bin/betterleaks    # Betterleaks binary
├── patterns/          # Custom patterns (reserved)
└── git-hooks/         # Global pre-commit hook (if --global)
```
