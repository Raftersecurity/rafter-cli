# Development

[← Back to README](../README.md)

This is a pnpm workspace. The Node CLI package lives in `node/`; the Python sibling in `python/`. Both implementations share the same CLI surface and JSON output contract (see [`shared-docs/CLI_SPEC.md`](../shared-docs/CLI_SPEC.md)) and versions are kept in lockstep (CI enforces via `validate-release.yml`).

## Node.js

```sh
pnpm install                # install all workspace deps (from repo root)
cd node && pnpm test        # run the Node test suite (Vitest)
cd node && pnpm run build   # TypeScript → dist/
node node/dist/index.js --help
```

`pnpm pack` produces the npm tarball; CI publishes via `.github/workflows/`.

## Python

```sh
cd python
poetry install
pytest
python -m build             # wheel + sdist
```

Python package details: see [`python/README.md`](../python/README.md).

## Adding a new agent platform

See [`docs/adding-a-platform.md`](adding-a-platform.md) for the contract every new platform integration must satisfy (Node + Python parity, recipe, verify check, probe).

## Documentation map

- **Full docs site**: [docs.rafter.so](https://docs.rafter.so)
- **Node CLI package**: [`node/README.md`](../node/README.md)
- **Python CLI package**: [`python/README.md`](../python/README.md)
- **CLI spec (canonical)**: [`shared-docs/CLI_SPEC.md`](../shared-docs/CLI_SPEC.md)

## Badges

Show that your project is protected by Rafter. Add one of these to your README:

[![Scanned by Rafter](https://img.shields.io/badge/scanned_by-Rafter-2ea44f)](https://github.com/Raftersecurity/rafter-cli) [![Rafter policy: enforced](https://img.shields.io/badge/rafter_policy-enforced-2ea44f)](https://github.com/Raftersecurity/rafter-cli)

```markdown
[![Scanned by Rafter](https://img.shields.io/badge/scanned_by-Rafter-2ea44f)](https://github.com/Raftersecurity/rafter-cli)
```

```markdown
[![Rafter policy: enforced](https://img.shields.io/badge/rafter_policy-enforced-2ea44f)](https://github.com/Raftersecurity/rafter-cli)
```

More badge variants (HTML, reStructuredText) available in [`badges/`](../badges/).

## See also

- [README](../README.md) — top-level overview
- [docs/adding-a-platform.md](adding-a-platform.md)
- [`shared-docs/CLI_SPEC.md`](../shared-docs/CLI_SPEC.md)
