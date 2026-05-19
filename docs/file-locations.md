# File Locations

[← Back to README](../README.md)

```
~/.rafter/
├── config.json        # Configuration
├── audit.jsonl        # Security event log (JSON lines)
├── bin/betterleaks    # Betterleaks binary
├── patterns/          # Custom patterns (reserved)
└── git-hooks/         # Global pre-commit hook (if --global)
```

With `rafter agent init --local`, configs are written under `./.rafter/` in the current working directory instead of `~/.rafter/`. Useful for ephemeral, containerized, or benchmark setups.

Project-level overrides live in `.rafter.yml` at the repo root (the CLI walks from cwd to git root looking for it). See [docs/local-toolkit.md](local-toolkit.md#policy-file-rafteryml) for the schema.

## See also

- [README](../README.md) — top-level overview
- [docs/local-toolkit.md](local-toolkit.md) — config and policy semantics
