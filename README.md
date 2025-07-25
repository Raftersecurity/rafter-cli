# Rafter CLI

Multi-language CLI for Rafter.

## Overview
This CLI allows you to trigger and retrieve security scans for your repositories via the Rafter public API. It is available for both Python (pip) and Node.js (npm, pnpm, yarn).

## Installation

### Python (pip)
```sh
pip install rafter-cli
```

### Node.js (npm, pnpm, yarn)
```sh
npm install -g @rafter/cli
# or
yarn global add @rafter/cli
# or
pnpm add -g @rafter/cli
```

## Quickstart
```sh
rafter run --repo myorg/myrepo --branch main
rafter get SCAN_ID --interactive
rafter usage
```

## Documentation
See `shared-docs/CLI_SPEC.md` for full CLI flag and command documentation. 