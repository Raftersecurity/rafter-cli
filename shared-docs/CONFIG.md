# Rafter Configuration Reference

Canonical, code-verified reference for Rafter's two configuration files and every
toggle they expose. Both the Node and Python implementations follow this spec.

Sources of truth in code:
- Global config schema — `node/src/core/config-schema.ts` (`RafterConfig`) /
  `python/rafter_cli/core/config_schema.py`.
- Project policy schema — `node/src/core/policy-loader.ts` (`PolicyFile`) /
  `python/rafter_cli/core/policy_loader.py`.
- Hook off-switch resolver — `node/src/core/hook-control.ts` / `python/rafter_cli/core/hook_control.py`.

---

## Two config layers

| | Global config | Project policy |
|---|---|---|
| **Path** | `~/.rafter/config.json` | `.rafter.yml` (also `.rafter.yaml`, `.rafter/config.yml`, `.rafter/config.yaml`) |
| **Format** | JSON | YAML |
| **Scope** | Whole machine / user | One repository |
| **Written by** | `rafter agent init`, `rafter agent config set` | You (commit it to the repo) |
| **Discovery** | Fixed path under `$HOME` | Walk from `cwd` up to the git root; first hit wins |
| **Trust** | **Trusted** — only the machine owner writes it | **Untrusted** — it ships inside the repo, so a repo author controls it |

**Precedence:** when both files set the same key, the project policy overrides the
global config — *for the keys the policy schema supports* (see the matrix). The
project policy is a deliberately **narrow subset**: it can tune scanning and command
strictness, but it **cannot** disable a security control (see *Trust boundary* below).

---

## What each layer can set

### `.rafter.yml` (project policy) — the complete key set

```yaml
version: "1"                      # optional, informational
riskLevel: moderate               # minimal | moderate | aggressive
commandPolicy:
  mode: approve-dangerous         # allow-all | approve-dangerous | deny-list
  blockedPatterns: ["rm -rf /"]   # replaces (not appends) the defaults
  requireApproval: ["git push --force"]
scan:
  excludePaths: ["dist/**", "*.lock"]
  customPatterns:
    - name: Internal Token
      regex: "intl_[a-z0-9]{32}"
      severity: high
  autoUpdateBetterleaks: true     # false to opt out (e.g. CI provisions its own binary)
ignore:                           # suppress findings (top-level, NOT under scan:)
  - paths: ["tests/fixtures/**"]
    rules: ["AWS Access Key ID"]  # omit to suppress all rules for those paths
    reason: "test fixtures, not real keys"
audit:
  retentionDays: 30
  logLevel: info                  # debug | info | warn | error
  logPath: ".rafter/audit.jsonl"  # repo-local audit log
docs: [ ... ]                     # repo security docs (see CLI_SPEC)
```

Backend-compatibility: top-level `exclude_paths:` / `custom_patterns:` (the flat
snake_case shape the hosted scanner also reads — it looks for `.rafter.yml` first,
then `.rafter/config.yml`) are also accepted; nested `scan.*` wins on collision.
Keys accept either `camelCase` or `snake_case` on every engine. The hosted scanner
honours `scan.excludePaths` and `ignore:` but never suppresses a must-fix or
secret-scanner finding; what it hid, kept, or could not match is written to
`suppressed.json` beside the scan's `findings.json` (see CLI_SPEC, *Ignore rules*).

> `.rafter.yml` does **not** contain `environments`, `components`, `outputFiltering`,
> `skills`, `notifications`, or `hooks` — those are global-only (by design for `hooks`).

### `~/.rafter/config.json` (global) — additional keys

Everything in the policy file, plus: `backend.{apiKey,endpoint}`,
`agent.environments.<platform>.enabled`, `agent.components`, `agent.skills.*`,
`agent.outputFiltering.*`, `agent.notifications.*`, and **`agent.hooks.*`** (the
hook off-switch). Global JSON uses `camelCase`.

---

## Toggle matrix — what you can turn on/off, and where it is honored

Every row below was verified against the code that *reads* the setting.

| Feature | How to toggle | Honored from | Enforced? |
|---|---|---|---|
| **Hook — whole** | `RAFTER_DISABLE_HOOKS=1` or `agent.hooks.enabled: false` | env, **global only** | ✅ `hook-control.ts` |
| **Hook — secret scan only** | `RAFTER_DISABLE_SECRET_SCAN=1` or `agent.hooks.secretScan: false` | env, **global only** | ✅ |
| **Hook — command policy only** | `RAFTER_DISABLE_COMMAND_POLICY=1` or `agent.hooks.commandPolicy: false` | env, **global only** | ✅ |
| Command-blocking strictness | `commandPolicy.mode` (`allow-all` = no blocking) | global + `.rafter.yml` | ✅ `command-interceptor` |
| Blocked / approval command lists | `commandPolicy.blockedPatterns` / `requireApproval` | global + `.rafter.yml` | ✅ |
| Risk threshold | `riskLevel` | global + `.rafter.yml` | ✅ |
| Secret-scan suppression | `ignore:` rules / `.rafterignore` | global + `.rafter.yml` | ✅ |
| Secret-scan path exclusion | `scan.excludePaths` | global + `.rafter.yml` | ✅ |
| Custom secret patterns | `scan.customPatterns` | global + `.rafter.yml` | ✅ |
| Betterleaks auto-update | `scan.autoUpdateBetterleaks` / `--no-auto-update` | global + `.rafter.yml` + flag | ✅ |
| Audit logging on/off | `audit.logAllActions` | global | ✅ `audit-logger` |
| Audit retention | `audit.retentionDays` | global + `.rafter.yml` | ✅ |
| Skill auto-update / backup | `skills.autoUpdate` / `skills.backupBeforeUpdate` | global | ✅ `skill-manager` |
| Webhook notifications | `notifications.webhook` / `RAFTER_NOTIFY_WEBHOOK` | global + env | ✅ |
| **Output redaction** | `outputFiltering.redactSecrets` / `blockPatterns` | global | ⚠️ **not enforced — see sable-y2z** |

> ⚠️ `agent.outputFiltering.redactSecrets` / `blockPatterns` are accepted and
> validated but currently **have no runtime effect** — the PostToolUse hook always
> redacts. Setting them to `false` is a silent no-op until that gap is closed.

---

## The hook off-switch (in depth)

Two precedence-ordered, **trusted** sources. **Env wins over global config.** Default
is enabled; a missing/corrupt config or an unrecognized value fails safe to enabled.

```bash
# Turn the whole hook off for this shell session
export RAFTER_DISABLE_HOOKS=1            # 1|true|yes|on = off; 0|false|no|off = force-on

# Or persist in the global config (machine-owner-owned)
rafter agent config set agent.hooks.enabled false
```

Granular: `RAFTER_DISABLE_SECRET_SCAN` / `agent.hooks.secretScan` (keep command
policy, drop secret scanning) and `RAFTER_DISABLE_COMMAND_POLICY` /
`agent.hooks.commandPolicy` (keep secret scanning, drop command prompts).

Check current state — including *which source* disabled it:

```bash
rafter agent status            # "Hooks: active" | "DISABLED (via …)" | "active (partial)"
rafter agent status --json     # .hook_control.{hook_enabled,…,source}
```

### Trust boundary — why `.rafter.yml` can't disable hooks

The off-switch is honored **only** from the env vars and the global
`~/.rafter/config.json` — never from project-local `.rafter.yml`. The resolver reads
`ConfigManager.load()` (global only), not `loadWithPolicy()`, and `hooks` is
deliberately absent from the policy schema. This closes a supply-chain footgun: if a
project file could disable the hook, cloning a hostile repo that ships
`hooks: { enabled: false }` would silently turn off the victim's secret scanning and
command interception. Disabling a security control is reserved to the machine owner.

---

## Turning hooks on/off entirely (install vs. runtime)

The off-switch above gates whether an *installed* hook acts. To install or remove the
hook itself:

| Action | Command |
|---|---|
| Install agent hook for a platform | `rafter agent init --with-claude-code` (or `enable claude-code.hooks`) |
| Remove agent hook for a platform | `rafter agent disable claude-code.hooks` (uninstalls from the platform's settings) |
| Install git pre-commit / pre-push hook | `rafter agent install-hook [--push] [--global]` |
| Remove global git hook | `git config --global --unset core.hooksPath` |
| Bypass a git hook once | `git commit --no-verify` (does **not** bypass the agent PreToolUse hook) |

`rafter agent list` shows per-component install state (`components` in the global
config), distinct from the runtime off-switch.
