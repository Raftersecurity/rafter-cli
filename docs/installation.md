# Installation

[← Back to README](../README.md)

Both implementations have full feature parity. Pick whichever fits your stack.

## Node.js

```sh
npm install -g @rafter-security/cli
# or
pnpm add -g @rafter-security/cli
# or
yarn global add @rafter-security/cli

# One-off, no install
npx @rafter-security/cli --help
```

After install, the `rafter` binary is on your `PATH`. Verify with `rafter --version`.

## Python

```sh
pip install rafter-cli
```

Requires Python 3.10+. Full feature parity with Node.js including local security toolkit and MCP server.

## Verify

```sh
rafter --version
rafter agent verify    # report installed integrations and binaries
```

## See also

- [README](../README.md) — top-level overview
- [docs/development.md](development.md) — building from source
- [docs/supported-platforms.md](supported-platforms.md) — which agent IDEs Rafter integrates with
