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

- `internal/watch`: fsnotify-backed drift watcher. Registers every
  directory under each scan root, debounces fs events into a single
  rescan trigger, and picks up new subdirectories as they appear.
  The trove store directory is excluded so the save-after-scan write
  doesn't loop the watcher.
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
  inventory; `POST /api/secrets/{id}/reveal` reads the value from
  disk on demand (via `scan.ResolveValue`), `PUT /api/secrets/{id}/annotation`
  edits the user metadata, and `POST /api/secrets/{id}/{stale,rotated}`
  expose the two action buttons from the spec. Keystore and source-code
  reveals return 422 (not yet supported).
- `internal/server/static/`: the embedded inventory UI. List grouped
  by source, side panel for annotation, click-to-reveal for plaintext
  sources, debounced auto-save on annotation edits, live SSE updates
  when the drift watcher fires. World-readable file groups expose a
  one-click "chmod 600" button that POSTs to the source-tightening
  endpoint and refreshes the inventory.
- `internal/server/sources.go`: `POST /api/sources/chmod600` is the
  only HTTP path that mutates a user file's mode. Body
  `{"path": "<source>"}`. The path must already be in the inventory
  (so the endpoint cannot be used as a generic chmod gadget) and the
  file must be regular. Tightens permissions to `0o600` and refreshes
  the in-doc `Permissions` for every secret at that path. The file's
  content is never read or rewritten, so the byte-identity guarantee
  in `tests/invariant/` continues to hold.

The keystore reader lands in subsequent commits.

## What v1 scans

- `.env`, `.envrc`, and per-environment files like `.env.local` and
  `.env.production` — every KEY=VALUE pair becomes a candidate Secret.
- `~/.aws/credentials`, `~/.npmrc`, `~/.docker/config.json`, `~/.config/gh/hosts.yml`,
  `~/.claude/settings.json`.
- Shell rc files: `.zshrc`, `.bashrc`, `.profile`, `.zshenv`, `.bash_profile`.

## What v1 does NOT scan

- **Documentation-template env files.** Files whose basename matches
  `.env.<...>.example`, `.sample`, `.template`, `.tmpl`, `.dist`, or `.dummy`
  (case-insensitive) are skipped by the file scanner — they hold placeholder
  values like `YOUR_API_KEY` by convention, and cataloging them as real
  secrets drowns the actual signal. `.env`, `.env.local`, `.env.production`,
  and `.envrc` are unaffected.
  Each `scan.Run` also reconciles previously-recorded FoundIn entries: if a
  past scan cataloged a `.env.example` (before this filter landed) or a path
  that now matches a `scan_config.excludes` rule, the FoundIn entry is
  pruned, and any Secret left without a single anchor on disk is removed.
- OS keystores (macOS Keychain, Linux Secret Service) — landing after
  `rafter-secure-design`.
- Source code — landing after `betterleaks` lands in raftercli.

## Hard rules (carried in from the spec)

- **Zero mutations to `.env` files in any code path.** Ever. The audit surface
  is read + annotate only.
- Never bind to `0.0.0.0`. Never reuse a port. Never log the session token.
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

### Performance under churn

Trove is expected to live alongside busy real-world `$HOME`s — log
rotators, build watchers, dev-server reloaders, dolt servers, polecat
worktrees. Two contracts hold even when the underlying filesystem is
firing thousands of inotify events per second:

- **HTTP read latency is bounded.** `GET /api/secrets`, `GET /api/status`,
  and the SSE stream all read from a snapshot pointer; no read path
  takes the docstore writer mutex. The performance test in
  `tests/perf/watcher_test.go` pins the budget at P95 < 200ms / P99 <
  500ms while the fixture fires 2,000 fs events/second under the scan
  root.
- **Watcher events are best-effort with a bounded queue, scans are
  rate-limited.** The watcher honours the same `scan_config.excludes`
  the walker uses (so excluded subtrees are never registered with
  inotify), and the rescanner caps wall-clock rescan rate at one full
  scan per second regardless of how many debounce windows close.
  Overflow events from the kernel queue are counted and surfaced via
  `GET /api/status` as `watch_events_dropped`, so a saturating consumer
  is visible to a curl probe without reading server logs.

## UI

The embedded inventory UI lives in `internal/server/static/` (one HTML file
+ one JS file, no build step, no CDN fonts). P14 corrected an earlier
brand miss and reshaped the page to put files first:

**Palette.** Rafter green `#2ea44f` (from `badges/README.md` —
"scanned by Rafter", "enforced", "clean") on a cool-dark base
(`--bg #0f1115`, `--bg-card #1a1f26`, `--fg #e8edf2`). Warn orange
`#d9822c` for permission warnings, danger red `#d6504d` for the
`.env`-in-git + real-secret combo. Mono font for keys, paths, octals,
and fingerprints; system sans elsewhere.

What you see on the page:

- **Header.** `trove` wordmark in mono (~22px) with `· by Rafter` in
  body text. A drift-watcher badge that turns Rafter green when SSE is
  connected ("Watching for changes"), warn-orange while connecting,
  muted-grey when closed. A `Re-scan` button and a `⚙` settings stub.
- **Risk dashboard.** Four tiles at the top, in this order:
  1. **files with secrets** — distinct files where trove found at least
     one secret. Tooltip lists the per-source-type breakdown.
  2. **files with loose perms** — files whose mode is more permissive
     than `0600` (`0644` / `0640` / `0666` / `0664`). Warn-coloured
     when `> 0`. Click the tile to filter the list to those files.
  3. **`.env` in git + secrets** — high-risk headline: `.env` files
     inside a git working tree that hold at least one secret.
     Danger-coloured when `> 0`. Tooltip: "These `.env` files live
     inside a git working tree — they can be accidentally committed.
     Add them to `.gitignore`."
  4. **secrets total** — distinct secrets after BLAKE3 dedup across
     all source files.
- **File-primary sections.** Three live, collapsible (`<details open>`):
  `Environment files (.env, .envrc)`, `Shell config`, `Config files`.
  Two greyed placeholders below: `OS keychain (coming soon)` and
  `Source code (coming soon, blocked on betterleaks)`.
- **File rows.** Path on the left (mono), `N secrets` count in the
  middle, chips on the right: mode-octal with the existing `?` tooltip,
  `in git` warn-chip if `InGitRepo`, `in history` danger-chip if
  `AppearsInGitHistory`. World-readable rows expose the
  one-click `Tighten to 0600` button (still wired to
  `POST /api/sources/chmod600`). A row's left border turns red on
  danger / amber on warn so you can scan severity without reading copy.
- **Expanded file rows.** Click a row to flip it open inline; the
  per-key UX (blurred preview → click reveal → click-to-copy → Notes
  / Mark stale / Mark rotated in the detail panel) is unchanged from
  P13. The older `Annotate` label was renamed to `Notes` everywhere
  user-visible; the wire endpoint `PUT /api/secrets/{id}/annotation`
  is unchanged.

The Playwright suite under `playwright/` doubles as the design
iteration harness — each test takes a screenshot of one state and
writes it to `docs/screenshots/NN-<step>.png`.

## Design log

See [docs/playwright.md](docs/playwright.md) for the palette, type
scale, spacing decisions, the screenshot index, and instructions for
running the iteration loop yourself.

Smoke tests in `internal/server/static_smoke_test.go` lock in the
structural markers (wordmark, aria-live drift ticker, `data-mode-octal`
hook, `data-clear-selection` hook, the four reveal-policy strings,
the four `data-tile` markers, the Rafter green / cool-dark palette)
so the page can't silently lose features OR regress on the brand.

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
