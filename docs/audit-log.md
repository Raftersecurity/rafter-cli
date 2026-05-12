# Audit Log

Every security-relevant event is logged to `~/.rafter/audit.jsonl` in JSON-lines format.
Each entry carries a `prevHash` forming a SHA-256 chain, plus the `cwd` and enclosing
`gitRepo` — so tampering, truncation, and out-of-context replays are all detectable.

## Commands

```sh
rafter agent audit                           # last 10 entries
rafter agent audit --last 20                 # last 20
rafter agent audit --event secret_detected   # filter by type
rafter agent audit --since 2026-02-01        # filter by date
rafter agent audit --verify                  # verify hash chain (exit 1 if tampered)
```

## Event types

| Event | Emitted when |
|-------|-------------|
| `command_intercepted` | A command is evaluated by the policy layer |
| `secret_detected` | A secret is found by the scanner |
| `content_sanitized` | Content is sanitized before output |
| `policy_override` | A policy default is overridden |

## Custom log path

Point the log at a repo-local path by setting `agent.audit.logPath` in `.rafter.yml`:

```yaml
audit:
  log_level: info
  log_path: .rafter/audit.jsonl   # relative to project root
  retention_days: 90
```

Retention pruning rewrites the log atomically and re-seals the chain. `audit --verify`
still passes after legitimate cleanup and fails on forgery.
