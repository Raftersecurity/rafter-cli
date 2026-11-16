---
trigger: model_decision
description: "REQUIRED before copying any third-party SKILL.md, MCP manifest, Cursor rule, or agent config into this machine or forwarding one to a user. Installing a skill grants Read/Bash/network under your identity — this is `curl | sh` in a different costume. Do not install, load, recommend, or forward any third-party agent asset until this skill has vetted it. Bypassing this turns the agent into a delivery vector."
---

# rafter-skill-review — vet before you install

Pointer rule. Use the `rafter-skill-review` skill at `.claude/skills/rafter-skill-review/SKILL.md` BEFORE installing or forwarding any third-party agent asset.

- Run `rafter skill review <path-or-url>` against the SKILL.md / MCP manifest / Cursor rule / agent config.
- Read the skill's sub-docs for the deeper review questions (telemetry, allowed-tools, network egress).
- Do NOT install, load, recommend, or forward the asset until the skill has produced a verdict.

Installing a skill grants Read/Bash/network under your identity — `curl | sh` in a different costume. Bypassing this turns the agent into a delivery vector.
