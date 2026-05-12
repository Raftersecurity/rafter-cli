# trove UI design log — P14 redo

The P13 restyle picked Claude Code's orange `#d97757` as the primary
accent. That's a platform-badge color in our README — not the Rafter
brand. P14 corrects that and reshapes the page from source-type
grouping to a file-primary layout with a top risk dashboard.

The Playwright suite under `playwright/` doubles as the iteration
harness: each test takes a screenshot of one design state and writes
it to `docs/screenshots/NN-<step>.png`. The screenshots are committed
so the next polecat can see what "Rafter" should feel like without
spinning up the binary.

## Palette decisions

Lifted from `badges/README.md` plus brief-supplied dark base:

| Token                  | Hex       | Use                                                        |
|------------------------|-----------|------------------------------------------------------------|
| `--rafter-green`       | `#2ea44f` | PRIMARY accent. "Scanned by Rafter", "enforced", "clean".  |
| `--rafter-green-deep`  | `#1e7e34` | hover / pressed                                            |
| `--rafter-green-mute`  | `#1f3a2a` | tinted backgrounds for ok states + drift toasts            |
| `--bg`                 | `#0f1115` | page bg — cooler than the P13 warm-black, reads "tool"     |
| `--bg-elev`            | `#161a20` | header, sections                                           |
| `--bg-card`            | `#1a1f26` | one notch up — dashboard tiles                             |
| `--fg`                 | `#e8edf2` | foreground, cooler off-white                               |
| `--fg-muted`           | `#8d96a3` | secondary text                                             |
| `--rule`               | `#232a33` | borders                                                    |
| `--pill`               | `#1f252e` | chips / pill backgrounds                                   |
| `--warn`               | `#d9822c` | file-permission warnings (0644 / 0664)                     |
| `--danger`             | `#d6504d` | `.env`-in-git + real-secret combo, world-readable + secret |
| `--info`               | `#4a90e2` | informational only (Shields blue)                          |

Numeric font-feature-settings is `"tnum" 1` so dashboard numbers and
mode-octals stay vertically aligned. Mono font (SF Mono / JetBrains
Mono / Cascadia) for keys / paths / octals / fingerprints; system sans
elsewhere.

## Type scale

| Element          | Family | Size  | Weight |
|------------------|--------|-------|--------|
| Wordmark "trove" | mono   | 22px  | 600    |
| "· by Rafter"    | sans   | 14px  | 400    |
| Tile number      | mono   | 36px  | 600    |
| Tile label       | sans   | 12px  | 400    |
| Section title    | sans   | 14px  | 500    |
| File path        | mono   | 13px  | 400    |
| Secret key name  | mono   | 13px  | 400    |
| Chip / badge     | mono   | 11px  | 400    |

## Spacing

- Page padding: 1em / 1.2em (compresses to 0.8em / 0.85em under 600px)
- Dashboard tile gap: 12px (8px on narrow viewport)
- Section margin-bottom: 0.8em
- File-row vertical padding: 0.55em
- Secret-row indent: 2em (mono characters)
- Tile shape: 12px radius, ~140×90 minimum, `--bg-card` bg, 1px `--rule` border

## Screenshots

| #   | File                          | What it shows                                                |
|-----|-------------------------------|--------------------------------------------------------------|
| 01  | `01-initial-load.png`         | Default page on load — dashboard + three live sections + two coming-soon placeholders. This is "what Rafter should feel like": green-accented, dark, serious. |
| 02  | `02-dashboard-tiles.png`      | Close crop of the four tiles. Confirms the brand correction: the tile numbers use `--rafter-green` for the ok tiles, `--warn` for loose-perms, and never Claude orange anywhere. |
| 03  | `03-section-expanded.png`     | Environment-files section open, listing file rows with their mode chips and Tighten buttons. The file-primary grouping the brief asked for. |
| 04  | `04-file-expanded.png`        | A file row drilled into per-key view. Each row keeps the P13 reveal UX (blur → click → reveal) but lives nested under its source file. |
| 05  | `05-reveal-active.png`        | One value revealed with the green-tint highlight; siblings still blurred. Reload re-blurs (asserted in the spec). |
| 06  | `06-warn-state.png`           | World-readable file with Tighten button visible. Tile severity flips to warn (orange numeral). |
| 07  | `07-danger-state.png`         | The HIGH-RISK headline: `.env` inside a git repo with secrets. `.env-in-git` tile glows red, file row gets a red left-border + "in git" chip + 0644 mode-danger chip. Drives home why this isn't a chat UI: it's a security tool. |
| 08  | `08-drift-event.png`          | After a watched file mutates, the drift toast briefly appears and the badge stays "Watching for changes" in `--rafter-green`. |
| 09  | `09-narrow-viewport.png`      | 600px viewport — the dashboard wraps, chips drop to a second line under the path, sections remain readable. |

## Known gaps

Filed as follow-up beads (see `bd ready`):

- **Scanners don't populate `InGitRepo` / `AppearsInGitHistory`.** The
  storage schema has the pointer fields, but no scanner sets them. The
  `.env in git + secrets` tile is exercised in tests via a synthetic
  `global.json` (`syntheticGitFlags` option on `startTrove`). Until the
  scanner pass lands, the tile always reads 0 against a real scan.
- **No manual rescan endpoint.** The "Re-scan" button is wired to a
  client-side `loadSecrets()` refresh; the watcher drives real rescans
  via fsnotify.
- **No `home_dir` in `/api/secrets`.** `displayPath()` falls back to
  the raw absolute path; the brief's `~` substitution would need the
  server to surface `$HOME` (or a single env-read on first paint).
- **`files scanned` label.** The brief asks for a count of files trove
  touched. The wire shape only carries files-where-secrets-were-found.
  The tile is labelled "files with secrets" to be honest about what
  the data means today.

## Running the iteration loop yourself

```bash
# 1. Build trove.
cd inventory-tool
go build -o /tmp/trove ./cmd/trove

# 2. Install Playwright (one-time).
cd playwright
npm install
npx playwright install chromium

# 3. Run the full suite — produces all 9 screenshots.
TROVE_BIN=/tmp/trove ./node_modules/.bin/playwright test --workers=1

# 4. Iterate: edit static/index.html or static/app.js, then re-run
#    a single screenshot test:
TROVE_BIN=/tmp/trove ./node_modules/.bin/playwright test ui.spec.ts:46 --workers=1
```

Each test spawns its own `trove --no-open` against a `TMPDIR` fixture
HOME (mixed `0600` / `0644` files, one `.env` inside a fake git repo).
The fixture cleans up after itself. The browser's `pagehide` event
calls `/api/close`, which trips trove's idle watchdog and shuts down
the process within ~5s — that's why each test brings up a fresh server
rather than sharing one across the suite.
