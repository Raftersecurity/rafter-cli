# OpenClaw Setup

Rafter integrates with OpenClaw as a **security skill** for secret scanning, command interception, and skill auditing. OpenClaw also powers Rafter's deep skill analysis (12-dimension security review).

## Automatic setup

```sh
rafter agent init
```

This auto-detects `~/.openclaw` and installs the security skill. Done.

## Manual setup

### 1. Skill file

Copy or symlink the Rafter security skill to OpenClaw's skill directory:

```sh
# If installed via npm
cp "$(npm root -g)/@rafter-security/cli/resources/rafter-security-skill.md" \
   ~/.openclaw/skills/rafter-security.md

# If installed via pip
cp "$(python -c 'import rafter_cli; print(rafter_cli.__path__[0])')/resources/rafter-security-skill.md" \
   ~/.openclaw/skills/rafter-security.md
```

The skill file includes OpenClaw frontmatter:

```yaml
---
openclaw:
  skillKey: rafter-security
  primaryEnv: RAFTER_API_KEY
  emoji: 🛡️
  always: false
  requires:
    bins: [rafter]
---
```

### 2. Slash commands provided

| Command | What it does |
|---------|-------------|
| `/rafter-scan [path]` | Scan files for hardcoded secrets |
| `/rafter-bash <cmd>` | Run command through risk-assessment layer |
| `/rafter-audit-skill <path>` | Security audit of a skill/extension file |
| `/rafter-audit` | View recent security audit log entries |

### 3. Deep skill analysis

When OpenClaw is available, `rafter agent audit-skill` uses it for a 12-dimension security review covering trust/attribution, network security, command execution, file system access, credential handling, input validation, data exfiltration, obfuscation, scope alignment, error handling, dependencies, and environment manipulation.

Without OpenClaw, Rafter falls back to a deterministic quick scan and outputs an LLM-ready review prompt.

## Verify

```sh
rafter agent verify
```

Confirms the OpenClaw skill is installed and accessible.
