# Rafter CLI — Copilot Instructions

Rafter is a security CLI for AI coding agents. It ships as two feature-identical implementations: Node.js (TypeScript) and Python.

## Project Rules

- **Every change must be made in both Node and Python.** A single-language PR is incomplete.
- **`shared-docs/CLI_SPEC.md` is the spec.** If CLI behavior changes, update the spec first.
- **Versions must match** between `node/package.json` and `python/pyproject.toml`.
- **This is a security tool.** Minimize dependencies. Never introduce `eval`, unsanitized template strings, or command injection vectors. Validate all external input at system boundaries.

## Directory Layout

- `node/src/commands/` — CLI commands (commander.js)
- `node/src/core/` — Command interceptor, audit logger, config manager
- `node/src/scanners/` — Gitleaks integration + regex-based secret scanner
- `node/src/adapters/` — Per-platform integration (8 platforms)
- `python/rafter_cli/` — Mirrors the Node structure with typer
- `shared-docs/CLI_SPEC.md` — Canonical output contracts and exit codes
- `recipes/` — Copy-paste setup guides per platform
- `vscode/` — VS Code extension

## Testing

- Node: Vitest (`cd node && pnpm test`)
- Python: pytest (`cd python && pytest`)
- Tests must pass in both before merging

## Key Patterns

- Commands export a `createXCommand()` factory (Node) or use `@app.command()` decorators (Python)
- Scanners use dual-engine: Gitleaks binary first, regex fallback
- Risk classification: critical > high > medium > low
- Audit log: JSONL format, append-only, documented schema in CLI_SPEC.md
- MCP server: 4 tools + 2 resources over stdio transport
