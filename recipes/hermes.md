# Hermes (Nous Research) Setup

Rafter integrates with [Hermes](https://hermes-agent.nousresearch.com/) through:

- An **MCP server** registered in `~/.hermes/config.yaml` (`scan_secrets`, `evaluate_command`, `read_audit_log`, `get_config`).
- **Skills** copied to `~/.hermes/skills/` (`rafter`, `rafter-secure-design`, `rafter-code-review`, `rafter-skill-review`).
- An **instruction block** appended to `~/.hermes/SOUL.md` so Hermes always loads the Rafter review gate.

Hermes does not expose tool-call lifecycle hooks, so there is no PreTool/PostTool wiring — risk is enforced via the instruction block and the MCP `evaluate_command` tool.

## Automatic setup

```sh
rafter agent init --with-hermes
```

This auto-detects `~/.hermes/` and installs all three components. Done.

## Manual setup

### 1. MCP server

Add to `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  rafter:
    command: rafter
    args:
      - mcp
      - serve
```

### 2. Skills

```sh
rafter agent enable hermes.skills
```

Copies the four canonical Rafter skills into `~/.hermes/skills/<name>/SKILL.md`.

### 3. Instruction block

```sh
rafter agent enable hermes.instructions
```

Injects a marker-delimited Rafter block into `~/.hermes/SOUL.md`. Existing personality content is preserved; `rafter agent disable hermes.instructions` strips just the block.

## Per-component control

```sh
rafter agent list --json | jq '.components[] | select(.platform == "hermes")'
rafter agent enable  hermes.mcp
rafter agent disable hermes.skills
```

## Verify

```sh
rafter agent verify
```

Restart Hermes to pick up the new MCP server and skills.
