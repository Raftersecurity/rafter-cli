# Aider Setup

Aider has **no plugin/hook system** and **no native MCP support**. Its only
intercept-friendly persistent-context primitive is the `read:` flag in
`.aider.conf.yml`, which injects read-only files into every Aider session.

Rafter ships a `RAFTER.md` context file and adds it to that `read:` list.

> Earlier versions of `rafter agent init --with-aider` appended
> `mcp-server-command: rafter mcp serve` to `.aider.conf.yml`. Aider's
> documented config schema has no `mcp-server-command` key — Aider silently
> ignored it. That install was pruned in `rf-du2o`. Reinstalling on top of an
> old layout strips the legacy line.

## Prerequisites

- Rafter installed as either `@rafter-security/cli` or `rafter-cli`
- A project directory where `RAFTER.md` and `.aider.conf.yml` may be written
- Aider itself is optional during setup; install it before starting an Aider session

## Automatic setup

```sh
# At a project root (no Aider install required):
rafter agent init --local --with-aider

# At user scope (against ~/.aider.conf.yml):
rafter agent init --with-aider
```

This writes `RAFTER.md` at the workspace root and ensures `.aider.conf.yml`
contains:

```yaml
read:
  - RAFTER.md
```

Existing `read:` entries are preserved. The legacy `mcp-server-command:` line
(if present from older rafter installs) is stripped.

## What gets installed

| Path | Purpose |
|---|---|
| `<cwd>/RAFTER.md` | Rafter security context block (`<!-- rafter:start --> ... <!-- rafter:end -->`) |
| `<cwd>/.aider.conf.yml` | Adds `RAFTER.md` to the `read:` list (creates the list if absent) |

## Manual setup

1. Create `RAFTER.md` at the workspace root with rafter's security context.
2. Add to `.aider.conf.yml`:

   ```yaml
   read:
     - RAFTER.md
   ```

   Or, if you already have a `read:` list, append `- RAFTER.md` to it.

## Verify

```sh
rafter agent verify
```

Aider doesn't have persistent memory beyond `read:`. For richer reference
material per session, also run:

```sh
rafter brief commands    # quick command reference
```

## MCP tools reference

Aider does not expose native MCP support, so Rafter's MCP tools
(`scan_secrets`, `evaluate_command`, `read_audit_log`, and `get_config`)
are not available inside Aider. The installed `RAFTER.md` gives Aider the
security guidance it can consume; run the equivalent Rafter CLI commands in a
separate terminal when you need active scanning or policy checks.

## Troubleshooting

- **`RAFTER.md` is not loaded:** Run Aider from the directory containing
  `.aider.conf.yml`, and confirm its `read:` list contains `RAFTER.md`.
- **Existing read-only files disappeared:** Do not replace the `read:` block
  manually. Re-run `rafter agent init --local --with-aider`; the installer
  preserves existing entries.
- **A stale `mcp-server-command` line remains:** Re-run the automatic setup
  with the current Rafter release. It removes the obsolete, ignored key.
- **Rafter commands are not found:** Check that the npm or Python scripts
  directory is on `PATH`, then confirm with `rafter --version`.

## Uninstall

Remove `RAFTER.md` from the `read:` list in `.aider.conf.yml`. Then delete
`RAFTER.md` only if it contains no project-specific content outside the
`<!-- rafter:start -->` / `<!-- rafter:end -->` managed block. At user scope,
make the same change in `~/.aider.conf.yml`.
