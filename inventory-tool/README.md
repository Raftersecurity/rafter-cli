# trove

> **Status: v0.1 — file/config/shellrc scanning + live UI shipped.** Storage,
> fingerprint dedup, drift watching, and a browser inventory built for
> non-technical people are all landed. Still gated: OS keystore reads
> (`rc-4fc`) and source-code scan via betterleaks (`rc-ksy`). See spec for the
> full v1 surface.

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
  with first-run-as-empty semantics, XDG-aware default path, plus
  `Upsert` / `MarkStale` / `MarkRotated` (fingerprint-based dedup, drift
  records value rotations to `value_history`, annotations survive drift)
- `internal/fingerprint`: `BLAKE3(key_name + 0x00 + value)` cross-source
  dedup ids and the rune-safe `value_preview` formatter
- `internal/scanners/file`, `internal/scanners/config`,
  `internal/scanners/shellrc`: read-only parsers for the v1 file
  surfaces — dotenv files, AWS shared credentials, npmrc auth tokens,
  docker config, gh hosts.yml, Claude settings, and shell rc files.
  Every scanner opens `O_RDONLY`, captures the file's mode in
  `FoundIn.Permissions`, and never writes/renames/deletes the source.
- `internal/scan`: filesystem walk that honours configured roots and
  excludes (with `**/X/`, `~/X/`, and basename rules), follows symlinks
  INTO scan roots only (never out), and detects ancestor cycles.
  Dispatches recognised paths to the matching scanner and folds
  observations into the global store via `Upsert`. Scans are
  zero-mutation by construction.
- `internal/wizard`: first-run prompt that seeds `ScanConfig.Roots`
  with `$HOME` (plus any detected `~/code`, `~/git`, … layouts) and
  pre-loads the spec's default exclude list.

A `--rescan` flag on `trove` triggers a non-interactive scan and
persists the updated store. The first-run wizard fires automatically
on launch when `ScanConfig.Roots` is empty.

- `internal/watch`: fsnotify-backed drift watcher. Registers
  directories under each scan root, debounces fs events into a single
  rescan trigger, and picks up new subdirectories as they appear.
  **It applies the same `ScanConfig.Excludes` the scanner uses** so it
  never opens a watch on `node_modules`/`.git`/caches/`~/Library`, and
  it **caps the number of watched directories** (`DefaultMaxWatchDirs`)
  and stops cleanly on `EMFILE`/`ENOSPC`. This is what keeps a default
  `$HOME` scope from exhausting file descriptors — on macOS fsnotify's
  kqueue backend opens one FD per watched directory, so an unbounded
  walk used to die with "too many open files" and take the scanner and
  UI down with it. When the cap or an OS limit is hit the watcher
  returns `ErrWatchLimit` (non-fatal): live coverage is partial and the
  periodic/launch rescans fill the rest. The trove store directory is
  excluded so the save-after-scan write doesn't loop the watcher.
  `cmd/trove` also raises `RLIMIT_NOFILE` soft→hard at startup for
  headroom, and runs one scan on launch so the UI shows the current
  inventory immediately instead of waiting for the first file change.
- `internal/eventbus`: in-process pub/sub broker for drift signals.
  Slow subscribers have events dropped rather than blocking the
  publisher, so a stalled browser tab can't stall the rescanner.
- `internal/rescan`: glues the above together — the watcher's
  debounced trigger fires a `scan.Run`, per-secret outcomes are
  published to the bus, and the doc is persisted before
  `scan_complete`.
- `/api/events`: server-sent-events stream over the trove HTTP
  surface. Clients connect with the existing session token, receive
  `scan_started`, `secret_created`, `secret_refreshed`,
  `secret_drifted`, and `scan_complete` frames as they happen.
- `internal/docstore`: a single-mutex wrapper around the on-disk
  `*storage.Global` that the rescanner and the HTTP handlers share.
  Every doc mutation (scanner upserts, annotations, mark-stale,
  mark-rotated) goes through the same lock, so a click in the UI
  during a rescan blocks briefly rather than racing the scanner.
- `internal/server/secrets.go`: `GET /api/secrets` returns the live
  inventory; `POST /api/secrets` adds a **user-curated (manual) entry**
  — a synthetic `manual:<rand>` id, no scanned value, an optional
  display-only path; `POST /api/secrets/{id}/reveal` reads the value from
  disk on demand (via `scan.ResolveValue`; manual + keystore + source-code
  sources return 422), `PUT /api/secrets/{id}/annotation` edits the user
  metadata (including project tags), and `POST /api/secrets/{id}/{stale,rotated}`
  expose the two action buttons from the spec.
- `internal/server/auth.go`: a `guard` middleware wraps token auth with
  the browser trust-boundary checks a localhost secrets viewer must not
  skip — a **Host allowlist** (rejects non-loopback Host headers, so DNS
  rebinding never reaches a handler) and an **Origin check** on every
  state-changing request (defends CSRF alongside the SameSite=Strict
  cookie). Same-origin in-page fetches pass; cross-site does not.
- `internal/server/static/`: the embedded inventory UI, branded
  **Rafter Secrets** (the user-facing name; the binary/module are still
  `trove` pending the repo move), written for people who have never
  opened a terminal. Dark Rafter aesthetic (matches the
  `docs/design-refs/` Vault Inspector). Every technical signal is
  translated at the edge: octal permissions become "readable by any app
  or AI agent on this computer" (the agent framing is deliberate — a
  plaintext secret is readable by every coding agent the user runs),
  `found_in.length > 1` becomes "stored in N places", `value_history`
  becomes "changed N times". Three views via a header toggle: **By
  secret** (default — one row per deduped credential), **By folder** (a
  path hierarchy that surfaces outliers and flags directories holding
  agent-readable secrets), and **By project** (grouped by the user's
  tags). Secrets are tracked at the credential level; projects are
  one-click chips on the detail panel. A "Worth a look" triage section
  floats exposed/duplicated secrets to the top; a stat row summarises the
  picture; the detail panel explains *what each finding means* and offers
  a copy-paste fix (never an auto-mutation). **"+ Add a secret"** opens a
  form (with a short "what's worth tracking" guide) that POSTs a manual
  entry. Click-to-reveal reads on demand (never persisted; manual entries
  have no value to reveal), debounced auto-save, live SSE updates when the
  drift watcher fires.

The keystore reader lands in subsequent commits.

## Hard rules (carried in from the spec)

- **Zero mutations to `.env` files in any code path.** Ever. The audit surface
  is read + annotate only.
- Never bind to `0.0.0.0`. Never reuse a port. Never log the session token.
- The served page carries a strict Content-Security-Policy
  (`default-src 'none'`, `connect-src 'self'`, no inline scripts). This is
  the "nothing leaves this computer" promise enforced below the JS layer:
  even an XSS could not exfiltrate a revealed secret to a remote host.
  The frontend renders all scanned data via `textContent`/escaped HTML and
  only allows `http(s)` annotation links — keep both invariants if you edit
  `internal/server/static/`.
- Keystore-read code must NOT land before the `rafter-secure-design` walk
  (see bead **rc-4fc**).
- Source-code scan must NOT land before betterleaks lands in raftercli (bead
  **rc-ksy**).

The zero-mutation rule has two enforcement layers — both must stay green:

- `scripts/no-write-syscalls.sh` is the **static** lint. It rejects banned
  write symbols (`os.WriteFile`, `os.Remove`, `os.Rename`, etc.) inside the
  read-only packages: `internal/scanners`, `internal/scan`, `internal/watch`,
  `internal/rescan`. `os.OpenFile` is allowed only when paired with
  `os.O_RDONLY` on the same line. Run from `inventory-tool/`:
  ```bash
  bash scripts/no-write-syscalls.sh
  ```
- `tests/invariant/` is the **runtime** safety net. It builds a synthetic
  fixture of `.env`, `.env.production`, `.npmrc`, `.zshrc`, and
  `.aws/credentials`, takes a SHA-256 manifest of the tree, drives the full
  HTTP API and the real fsnotify-backed rescan pipeline against it, and
  asserts the manifest is byte-identical afterwards (apart from any mutation
  the test itself performs). A second test attaches an independent fsnotify
  watcher to the fixture and asserts trove generates **zero** write events
  there. A third fuzzes random JSON bodies at every PATCH/POST endpoint and
  asserts the fixture is still untouched.
  ```bash
  go test ./tests/invariant/...
  ```

`.github-trove-lint.yml` is the staged GitHub Actions workflow that wires
both layers into CI; P7 promotes it to `.github/workflows/`.

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
    ├── server/        # localhost HTTP + token auth + lifecycle + SSE + inventory API + UI
    │   └── static/    # embedded HTML/JS for the inventory browser UI
    ├── browser/       # cross-platform default-browser opener
    ├── docstore/      # shared *storage.Global + lock + saver (rescan + server)
    ├── storage/       # global.json schema, atomic Load/Save, Upsert/dedup/drift
    ├── fingerprint/   # BLAKE3 dedup ids and value previews
    ├── scan/          # walk orchestrator + scanner dispatch + ResolveValue (reveal)
    ├── watch/         # fsnotify drift watcher + debounced rescan trigger
    ├── eventbus/      # in-process pub/sub for drift events
    ├── rescan/        # watch+scan+bus glue for live drift updates
    ├── wizard/        # first-run scope prompt
    └── scanners/      # per-source secret scanners (read-only)
        ├── file/      # .env, .env.*, .envrc parsers
        ├── config/    # ~/.aws/credentials, .npmrc, docker, gh, claude
        └── shellrc/   # .zshrc, .bashrc, .profile, .zshenv, .bash_profile
```

## Pointers

- Spec: `/home/rome/gt/obsidian/mayor/rig/Projects/Rafter 2.0/Secret Management/Inventory-Tool-Spec.md`
- Local context: `../RAFTER-2.0-CONTEXT.md`
- Parent research: orbit bead **or-hsz**, hooked bead **hq-echge**
