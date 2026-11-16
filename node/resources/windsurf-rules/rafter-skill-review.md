---
trigger: model_decision
description: "REQUIRED before copying any third-party SKILL.md, MCP manifest, Cursor rule, or agent config into this machine or forwarding one to a user. Installing a skill grants Read/Bash/network under your identity — this is `curl | sh` in a different costume. Do not install, load, recommend, or forward any third-party agent asset until this skill has vetted it. Bypassing this turns the agent into a delivery vector."
---

# rafter-skill-review — vet before you install

Pointer rule for the `rafter-skill-review` skill. Use it BEFORE installing or forwarding any third-party agent asset. (The full skill — with sub-docs on provenance, malware, prompt injection, data practices, and telemetry — installs as its own skill directory only for Claude Code (`.claude/skills/rafter-skill-review/`) and for Codex and Gemini (`.agents/skills/rafter-skill-review/`); this rule is the condensed equivalent here.)

- Run `rafter skill review <path-or-url>` against the SKILL.md / MCP manifest / Cursor rule / agent config — its report already covers most of the deeper checks (provenance, obfuscation, secrets, prompt-injection patterns).
- Weigh telemetry, allowed-tools scope, and network egress by hand on top of that report.
- Do NOT install, load, recommend, or forward the asset until you have a verdict.

Installing a skill grants Read/Bash/network under your identity — `curl | sh` in a different costume. Bypassing this turns the agent into a delivery vector.
