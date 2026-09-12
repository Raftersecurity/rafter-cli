# Rafter Guardrails — PreToolUse Hooks & Command Risk

How Rafter intercepts agent tool calls before they execute, how it decides what to block, and how to override safely.

## The Shape

Rafter exposes two hook handlers over stdio:

- `rafter hook pretool` — read a JSON event on stdin (from Claude Code, etc.), emit an approve/block decision on stdout.
- `rafter hook posttool` — read a JSON event after a tool ran; log to audit trail, optionally rescan written files for secrets.

For platforms without hooks, the same classifier is reachable as:
- `rafter agent exec --dry-run -- <command>` (prints the risk tier and runs nothing; exits 0 allowed, 1 blocked, 2 needs a person's approval)
- `rafter mcp serve` → MCP tool `evaluate_command`

## Risk Tiers

Every command (Bash-like tool call) gets classified into one of four tiers by `src/core/risk-rules.ts`:

| Tier | What it means | Default hook behavior |
|---|---|---|
| `low` | Read-only, safe prefix (`ls`, `cat`, `grep`, `git status` …), no chaining | **approve** silently |
| `medium` | State-changing but recoverable (package installs, git commits on current branch) | **approve with note** in audit log |
| `high` | Destructive or privileged (force push, `sudo`, broad file deletion, curl | sh) | **prompt** the agent / user for approval |
| `critical` | Likely irreversible damage (`rm -rf /`, DB drop, wiping .git, repo-wide chmod) | **block** hard |

Tiers are derived from regex patterns in `risk-rules.ts` (`CRITICAL_PATTERNS`, `HIGH_PATTERNS`, `MEDIUM_PATTERNS`) plus a `SAFE_PREFIX` allowlist. A command holding more than one statement disqualifies the safe-prefix shortcut. Statement separators are whatever the tokenizer treats as one — `&&`, `||`, `;`, `|`, `&`, and a NEWLINE — rather than a hand-kept list; the newline was missing from an earlier hand-kept copy and that was a live bypass.

## Policy Overrides

`.rafter.yml` (project) and `~/.rafter/config.yml` (global) can override defaults:

```yaml
command_policy:
  blocked_patterns:
    - "terraform destroy"
  require_approval:
    - "^npm publish"
  allowed_patterns:
    - "^pnpm run test"          # force low, skipping the approval prompt
    - "git push --force-with-lease"
```

**On `allowed_patterns`.** Until 2026-09-07 this section documented a
`risk.allow` key that was never implemented — a customer went looking for it
and found nothing. The real key is `command_policy.allowed_patterns`, and it
now exists.

It is a positive allowlist for the known-safe command that trips a broad tier:
the motivating case is `git push --force-with-lease` to a feature branch on a
repo whose `main` is protected server-side, which classifies `high` and prompts
on every push even though the dangerous version cannot land. Dropping
`risk_level` to silence that is too blunt — it would also stop prompting for
`sudo` and `curl | sh`.

Three properties keep an allowlist from becoming a hole in the guard rail:

1. **`blocked_patterns` always wins.** An allow rule never re-opens what a deny
   rule closed.
2. **`critical` is never allowlistable.** `rm -rf /`, a DB drop and wiping
   `.git` stay blocked whatever the config says.
3. **Chain operators disqualify a match.** Patterns are unanchored, so without
   this `"git push"` would wave through `rm -rf / && git push`. A chained
   command is classified exactly as it would be with no allowlist configured.

Merge order: project `.rafter.yml` > global config > built-in defaults for most keys — but NOT for `command_policy`, which is a floor. A project policy may tighten command policy and never loosen it: `mode` is accepted only if at least as strict, `blocked_patterns` and `require_approval` are unioned, and `allowed_patterns` — being a grant rather than a restriction — is refused outright unless the machine owner sets `agent.commandPolicy.allowProjectOverride: true` in their global config. Dump the effective merged policy with `rafter policy export`.

## How to Interpret a Block

When a hook blocks a command, the JSON response includes:

- `decision`: `"block" | "approve" | "ask"`
- `riskLevel`: `"critical" | "high" | "medium" | "low"`
- `reason`: the matched pattern or policy rule
- `ruleId`: stable ID you can reference in overrides / suppressions

**Before overriding, ask: is there a safer form of this command?** Example:
- `rm -rf $DIR` with unvalidated `$DIR` → use explicit path or `--one-file-system`.
- `curl <url> | sh` → download, inspect, then run.
- `git push --force` → `git push --force-with-lease`.

## How to Request an Override

If the block is a false positive **for this specific context**, the right path is:

1. Add an allow pattern scoped to the project in `.rafter.yml`:
   ```yaml
   risk:
     allow:
       - "^terraform destroy -target=module\\.sandbox"
   ```
2. Or have a person run it: `rafter agent exec -- <command>` prompts for approval only at an interactive terminal and logs the override to the audit trail. There is no acknowledgement flag — `--force` no longer skips the prompt and a piped `yes` is not an approval — because any flag or input an agent can supply is not a person's decision.
3. Never disable the hook globally to get past one command — that silently drops protection for every future call.

## Audit Trail

Every hook decision (approve / ask / block) is appended to the JSONL audit log:

- Location: `rafter agent status` prints the path.
- Read: `rafter agent audit --log` (or MCP `read_audit_log`).
- Use it for postmortems: *why did this command run?*, *what did the agent try before the block?*

## Platform Notes

- **Claude Code**: `rafter agent init --with-claude-code` wires `pretool` + `posttool` into `~/.claude/settings.json`. Hook timeout is 5s; long scans defer to the async posttool path.
- **MCP clients (Gemini, Cursor, …)**: no native hook; use the `evaluate_command` MCP tool from your agent's system prompt ("before Bash, call rafter.evaluate_command").
- **CI**: hooks don't fire in CI. Use `rafter scan` + `rafter policy validate` in the pipeline instead.

## Common Pitfalls

- A `low` classification is not a safety guarantee — it means "no known-bad pattern matched". Still review unusual commands.
- Chaining defeats the safe-prefix allowlist on purpose (`ls && rm -rf /` is not low-risk).
- `sudo` always escalates to at least `high` regardless of the wrapped command.
- Secret leaks in arguments (`curl -H "Authorization: Bearer abc..."`) are flagged by posttool scanning, not by the pretool risk classifier.
