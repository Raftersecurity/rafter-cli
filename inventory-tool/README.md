# trove

> **Status: scaffold (v0.0.0).** Runtime shell only. No scanners, no storage,
> no keystore reads. See spec for the v1 surface.

`trove` is the inventory tool from the Rafter 2.0 Secret Management project — a
read-only, annotate-only auditor for secrets that already live in plaintext on
your machine (`.env*` files, shell rc, agent configs, OS keystores, and source
code via betterleaks).

## What's landed so far

A single Go binary that:

- Binds an HTTP server to `127.0.0.1` on a random port
- Mints a per-session token, embeds it in the launcher URL
- Auto-opens the default browser to that URL
- Sets a strict, HttpOnly session cookie on first hit and strips the token
  from the URL so it doesn't linger in history
- Runs while the tab is open; exits on the close beacon or after the idle
  timeout with no heartbeat
- Serves a placeholder index page + `/api/status`

Plus the storage and fingerprint internals the rest of v1 builds on:

- `internal/storage`: typed schema for the `~/.config/trove/global.json`
  document, atomic `Save` (temp-file + fsync + rename, mode `0600`), `Load`
  with first-run-as-empty semantics, XDG-aware default path
- `internal/fingerprint`: `BLAKE3(key_name + 0x00 + value)` cross-source
  dedup ids and the rune-safe `value_preview` formatter

Scanners, the file watcher, the keystore reader, and the real UI land in
subsequent commits.

## Hard rules (carried in from the spec)

- **Zero mutations to `.env` files in any code path.** Ever. The audit surface
  is read + annotate only.
- Never bind to `0.0.0.0`. Never reuse a port. Never log the session token.
- Keystore-read code must NOT land before the `rafter-secure-design` walk
  (see bead **rc-4fc**).
- Source-code scan must NOT land before betterleaks lands in raftercli (bead
  **rc-ksy**).

## Build

```bash
make build       # host platform
make build-all   # darwin/linux × amd64/arm64
make run         # build + launch
```

## Layout

```
inventory-tool/
├── cmd/trove/         # entry point
└── internal/
    ├── server/        # localhost HTTP + token auth + lifecycle watchdog
    ├── browser/       # cross-platform default-browser opener
    ├── storage/       # global.json schema + atomic Load/Save
    └── fingerprint/   # BLAKE3 dedup ids and value previews
```

## Pointers

- Spec: `/home/rome/gt/obsidian/mayor/rig/Projects/Rafter 2.0/Secret Management/Inventory-Tool-Spec.md`
- Local context: `../RAFTER-2.0-CONTEXT.md`
- Parent research: orbit bead **or-hsz**, hooked bead **hq-echge**
