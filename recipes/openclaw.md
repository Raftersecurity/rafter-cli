# OpenClaw Setup

Rafter integrates with OpenClaw as a **ClawHub-shaped skill** that OpenClaw
auto-discovers from its workspace skills directory. The skill provides
secret scanning, policy enforcement, and extension auditing via the rafter
CLI.

> rafter ≤ 0.7.7 wrote a single markdown file at
> `~/.openclaw/skills/rafter-security.md` — that path was never read by
> OpenClaw at runtime. ClawHub auto-discovers skills from
> `<workspace>/skills/<name>/SKILL.md`. Reinstalling on top of an old
> layout strips the legacy file and migrates to the canonical path
> (rf-zgwj).

## Automatic setup

```sh
rafter agent init --with-openclaw
# or, install all detected integrations
rafter agent init --all
```

`--with-openclaw` writes the skill at
`~/.openclaw/workspace/skills/rafter-security/SKILL.md` and removes any
legacy `~/.openclaw/skills/rafter-security.md` left by older rafter
versions. OpenClaw auto-discovers the skill on the next session start.

## Manual setup

### 1. Skill file

Place a `SKILL.md` at OpenClaw's canonical workspace skills path:

```sh
mkdir -p ~/.openclaw/workspace/skills/rafter-security

# If rafter is installed via npm:
cp "$(npm root -g)/@rafter-security/cli/resources/rafter-security-skill.md" \
   ~/.openclaw/workspace/skills/rafter-security/SKILL.md

# If rafter is installed via pip:
cp "$(python -c 'import rafter_cli; print(rafter_cli.__path__[0])')/resources/rafter-security-skill.md" \
   ~/.openclaw/workspace/skills/rafter-security/SKILL.md
```

The skill file ships with the ClawHub-required frontmatter:

```yaml
---
name: rafter-security
description: Security toolkit for AI workflows. Use when scanning code...
version: 0.7.7
metadata:
  openclaw:
    skillKey: rafter-security
    primaryEnv: RAFTER_API_KEY
    emoji: 🛡️
    requires:
      bins: [rafter]
---
```

`requires.bins: [rafter]` gates the skill on the `rafter` CLI being on
`$PATH` — OpenClaw only surfaces the skill if the binary is available.

### 2. Optional: API key for remote SAST

The `RAFTER_API_KEY` env var unlocks `rafter run` (remote SAST + SCA +
agentic deep-dive). Without it, `rafter secrets <path>` (offline secrets
scan) still works. The skill's frontmatter declares this as an optional
`envVar`, so OpenClaw can prompt for it but won't require it.

## Restart and verify

Restart OpenClaw so it picks up the new skill on session start.

```sh
rafter agent verify
```

Reports `OpenClaw: Rafter skill installed (vX.Y.Z)` when the canonical
SKILL.md is in place. If a legacy `~/.openclaw/skills/rafter-security.md`
is detected without the canonical install, verify reports a warning with
the migration command to run.
