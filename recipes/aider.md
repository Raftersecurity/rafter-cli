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
