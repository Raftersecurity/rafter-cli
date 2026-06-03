# Hermes Setup

Rafter's Hermes integration installs the Rafter MCP server into Hermes' user-scope config. v0 is MCP-only — `scan_secrets`, `evaluate_command`, `read_audit_log`, and `get_config` tools become available to Hermes once the config block is in place. Pre/post-tool hooks are deferred to a follow-on once Hermes' hook surface is documented; track this under bead `sable-gyw` follow-ons.

## Install the CLI first

```sh
npm install -g @rafter-security/cli   # Node
# or:
pip install rafter-cli                 # Python
```

> Using `npx`? The canonical form is `npx @rafter-security/cli` — the bare `npx rafter-cli` resolves to an **unrelated** package on npm.

## Automatic setup

```sh
rafter agent init --with-hermes
```

Auto-detects `~/.hermes`. The Rafter MCP server entry is merged into `~/.hermes/config.yaml` under `mcp_servers.rafter` — existing servers and other top-level YAML keys are preserved.

User scope only — Hermes itself reads `~/.hermes/config.yaml`, and `rafter agent init --local --with-hermes` is intentionally not supported in v0 (Hermes does not have an established project-local config story).

## Manual setup

Append the following to `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  rafter:
    command: rafter
    args:
      - mcp
      - serve
```

Restart Hermes so it picks up the new server. Verify:

```sh
rafter agent verify
```

## What you get

The Rafter MCP server exposes four tools to Hermes:

| Tool | Purpose |
|---|---|
| `scan_secrets` | Scan text or files for credentials before sending them across an agent boundary |
| `evaluate_command` | Classify a shell command's risk (`critical` / `high` / `medium` / `low`) before executing |
| `read_audit_log` | Inspect the JSON-lines audit log (`~/.rafter/audit.jsonl`) — every scan, every blocked command, with SHA-256 chain integrity |
| `get_config` | Read the active Rafter config (risk-level, custom patterns, audit settings) |

Plus two resources (`rafter://config`, `rafter://policy`) that surface the live config and `.rafter.yml` policy as MCP resources.

## Troubleshooting

**`agent init --with-hermes` says "Hermes requested but not detected."** Rafter looks for `~/.hermes/`. If Hermes is installed elsewhere, point it at the right home: `HOME=/custom/path rafter agent init --with-hermes`, or `rafter agent init --local --with-hermes` from inside a project that has its own `.hermes/` directory (project-local is treated as opt-in v0 — the config is written but Hermes itself may or may not consume it).

**`mcp_servers.rafter` already exists in my config.** The installer replaces the `rafter` entry idempotently — every other server and key in the file is preserved untouched. Run `rafter agent init --with-hermes` whenever you upgrade the CLI to refresh the entry.

**My YAML config got rewritten in a different style after `agent init`.** YAML round-trips through PyYAML (Python) / js-yaml (Node) lose comments and reorder keys. If you have a hand-curated config, prefer the manual setup above and pin the rafter block in place by hand.
