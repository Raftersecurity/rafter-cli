# Rafter CLI

Multi-language CLI for [Rafter](https://rafter.so) — zero-setup security for AI builders.

**Two things in one package:**
1. **Rafter Security Audits** — Trigger remote SAST/SCA scans via Rafter API
2. **Agent Security** — Local secret detection, command interception, and skill auditing for AI agents (Claude Code, Codex CLI, OpenClaw)

## Installation

### Python
```sh
pip install rafter-cli
```

### Node.js
```sh
npm install -g @rafter-security/cli
```

## Rafter Security Audits

Analyze remote repositories for vulnerabilities. Requires a [Rafter API key](https://rafter.so). See [docs.rafter.so](https://docs.rafter.so) for full documentation.

```sh
export RAFTER_API_KEY="your-key"

rafter run                                    # scan current repo
rafter scan --repo myorg/myrepo --branch main # scan specific repo
rafter get SCAN_ID                            # retrieve results
rafter usage                                  # check quota
```

Output goes to stdout (pipe-friendly):
```sh
rafter get SCAN_ID | jq '.vulnerabilities[] | select(.level=="critical")'
```

## Agent Security

Local security features for autonomous AI agents. **No API key required.**

```sh
rafter agent init                  # setup (auto-detects Claude Code, Codex, OpenClaw)
rafter agent scan .                # scan files for secrets (21+ patterns)
rafter agent scan --staged         # scan git staged files only
rafter agent exec "git push"       # execute with risk assessment
rafter agent audit-skill skill.md  # audit a skill/extension for malware
rafter agent audit                 # view security event logs
rafter agent install-hook          # pre-commit hook for secret scanning
rafter agent config show           # view configuration
```

### Supported Agents

| Agent | Detection | Skills installed to |
|-------|-----------|-------------------|
| Claude Code | `~/.claude` | `~/.claude/skills/rafter/` |
| Codex CLI | `~/.codex` | `~/.agents/skills/rafter/` |
| OpenClaw | `~/.openclaw` | `~/.openclaw/skills/` |

`rafter agent init` auto-detects installed agents and installs appropriate skills.

### Skill Auditing

**Treat third-party skill ecosystems as hostile by default.** There have been reports of malware distributed via AI agent skill marketplaces, using social-engineering instructions to run obfuscated shell commands.

```sh
rafter agent audit-skill path/to/untrusted-skill.md
```

Analyzes 12 security dimensions: trust/attribution, network security, command execution, file system access, credential handling, input validation, data exfiltration, obfuscation, scope alignment, error handling, dependencies, environment manipulation.

### Command Interception

| Risk | Action | Examples |
|------|--------|----------|
| Critical | Blocked | `rm -rf /`, fork bombs |
| High | Approval required | `sudo rm`, `curl\|bash`, `git push --force` |
| Medium | Approval on moderate+ | `sudo`, `chmod`, `kill -9` |
| Low | Allowed | `npm install`, `git commit` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error / secrets found |
| 2 | Scan not found |
| 3 | Quota exhausted |

## Documentation

- **Node.js CLI**: See [`node/README.md`](node/README.md) for full command reference
- **Python CLI**: See [`python/`](python/) for Python-specific usage
- **CLI Spec**: See [`shared-docs/CLI_SPEC.md`](shared-docs/CLI_SPEC.md) for flags and output formats
- **Full docs**: [docs.rafter.so](https://docs.rafter.so)

## License

[MIT](LICENSE)