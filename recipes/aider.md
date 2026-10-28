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

- Rafter installed as either `@rafter-security/cli` (Node.js 22+) or
  `rafter-cli` (Python 3.11+)
- A project directory where `RAFTER.md` and `.aider.conf.yml` may be written
- With `--local`, Aider need not be installed yet. At user scope,
  `~/.aider.conf.yml` must exist first. Install Aider before your first session.

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

Aider has no native MCP support, so Rafter's MCP server
(`rafter mcp serve`) isn't available inside Aider. `RAFTER.md` carries the
security guidance into each session; run the Rafter CLI (`rafter secrets`,
`rafter agent exec`, `rafter agent audit`) in a terminal for active checks.

## Troubleshooting

- **`RAFTER.md` is not loaded:** Run Aider from the directory containing
  `.aider.conf.yml`, and confirm its `read:` list contains `RAFTER.md`.
- **`RAFTER.md` dropped out of `read:`:** If you edit the `read:` block by hand,
  keep `RAFTER.md` in the list. Re-running
  `rafter agent init --local --with-aider` adds it back without touching your
  other entries.
- **A stale `mcp-server-command` line remains:** Re-run the automatic setup
  with the current Rafter release. It removes the obsolete, ignored key.
- **Rafter commands are not found:** Check that the npm or Python scripts
  directory is on `PATH`, then confirm with `rafter --version`.

## Uninstall

```sh
rafter agent disable aider.read
```

On 0.11.2 and later this removes Rafter's managed block and the `read:` entry
and keeps any project-specific content in `RAFTER.md`. To do it by hand,
remove `RAFTER.md` from the `read:` list in `.aider.conf.yml`. Then delete
`RAFTER.md` only if it contains no project-specific content outside the
`<!-- rafter:start -->` / `<!-- rafter:end -->` managed block. At user scope,
make the same change in `~/.aider.conf.yml` and `~/RAFTER.md`.
