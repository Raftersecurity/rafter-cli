---
name: rafter-skill-review
description: "Security review of a skill, plugin, or agent extension before you install it. Router skill: pick (a) installing a brand-new skill, (b) updating an already-installed skill, or (c) investigating one that looks suspicious, and Read the matching sub-doc. Pairs with `rafter skill review <path-or-url>` which emits a deterministic JSON report (secrets, URLs, high-risk shell, obfuscation signals). Run this BEFORE copying any third-party SKILL.md, MCP server manifest, Cursor rule, or agent config into your machine. No installation is safe until it has passed."
version: 0.1.0
allowed-tools: [Bash, Read, Grep, Glob, WebFetch]
---

# Rafter Skill Review — Vet Before You Install

Skills are executable context. Installing one gives it Read, sometimes Bash, sometimes network — with your identity and your files. Treat installation the way you treat `curl | sh`: don't.

Before you copy any third-party `SKILL.md`, MCP manifest, Cursor rule, or agent extension into your machine, run this skill.

> This skill replaces `rafter agent audit-skill` (still usable but deprecated — emits a stderr warning and aliases to `rafter skill review`).

---

## Step 0: Always run the deterministic pass first

```bash
rafter skill review <path-or-git-url>            # emits JSON to stdout
rafter skill review <path> --format text         # human-readable summary
```

The command:
- pulls the skill (if a URL, does a shallow clone into a temp dir),
- runs `rafter scan local` over the tree,
- extracts URLs, high-risk shell patterns, obfuscation signals,
- reads `SKILL.md` frontmatter (`allowed-tools`, `version`, etc.),
- prints a structured JSON report — see `shared-docs/CLI_SPEC.md` §`rafter skill review`.

Exit code `0` means the deterministic pass found nothing. **That does NOT mean the skill is safe.** LLM prompt injection, sneaky data practices, and authorship fraud are invisible to regex. Always follow up with the Choose-Your-Adventure branch below.

---

## Choose Your Adventure

Pick exactly one branch. Read only that sub-doc — do not flood your context with all six.

### (a) I am installing a brand-new skill

Use this when: you've never had this skill on this machine, and you want to know if it's safe to install for the first time.

**Walk in order:**

1. **`Read docs/authorship-provenance.md`** — who wrote it, how old, how signed, how widely installed. Stop early if provenance is weak.
2. **`Read docs/malware-indicators.md`** — grep for obfuscation, binary blobs, postinstall scripts, known-bad URL patterns.
3. **`Read docs/prompt-injection.md`** — scan prose for hidden instructions, zero-width characters, conflicting directives in long files.
4. **`Read docs/data-practices.md`** — which files/paths does it read and write, what network calls, does it silently escalate via `allowed-tools`.
5. **`Read docs/telemetry.md`** — phone-home URLs, analytics SDKs, anonymous-but-trackable IDs.

Sign off only when every branch has a file:line answer. Partial confidence = don't install.

### (b) I am updating a skill I already have installed

Use this when: a new version of a skill you already trust is out and you're about to overwrite the installed copy.

- **`Read docs/changelog-review.md`** — focuses on *what changed*: diff between old and new SKILL.md + sub-docs, new URLs, new shell, new tool grants, version-bump semantics. Provenance shifts (new maintainer, transferred repo, republished package) get their own checklist here.
- If the diff touches prompts, tools, or network → also walk `docs/prompt-injection.md` and `docs/data-practices.md` on the changed sections only.

### (c) I am investigating a skill that already looks suspicious

Use this when: something smells wrong (someone reported it, the name is a typo-squat, it showed up uninstalled, a finding from step 0 alarmed you).

- **`Read docs/malware-indicators.md`** first — prioritize obfuscation and binary-blob checks.
- **`Read docs/prompt-injection.md`** — the skill may be weaponized against the installer, not the end user.
- **`Read docs/authorship-provenance.md`** — map the real author (not the claimed one), check other artifacts from the same account.
- **`Read docs/telemetry.md`** and **`docs/data-practices.md`** in parallel — data exfil is often what the attacker wants.

If any branch yields a concrete indicator: do not install. File the finding with `rafter issues create from-text`, or attach to an existing PR / ticket with file:line evidence.

---

## What this skill will NOT do

- It will not tell you a skill is "safe". There is no global safe list. Trust is per-install, per-machine, per-version.
- It will not replace `rafter scan`. The JSON report from step 0 is the evidence floor, not the ceiling.
- It will not evaluate skills you've already installed and run — by that point the exfil already happened. This is pre-install gating only.

---

## Fast path — copy-paste

```bash
# Local path
rafter skill review ./third-party-skill/ --json > report.json

# Git URL (shallow-cloned into temp dir; removed after review)
rafter skill review https://github.com/acme/their-skill.git --json > report.json

# Human-readable
rafter skill review ./third-party-skill/
```

If the command exits 1 → findings present → walk branch (a) or (c) above.
If exit 0 → deterministic pass clean → still walk branch (a) for a new install.

## Decision rule

Install only if **all three** are true:

1. `rafter skill review` exit 0 (or every finding is explained and accepted).
2. The branch you walked has no unanswered questions.
3. `allowed-tools` is narrower than or equal to what the skill's stated purpose requires.

If in doubt, don't install. Re-evaluating later is cheap; removing a backdoor is not.
