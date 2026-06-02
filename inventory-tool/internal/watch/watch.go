// Package watch is trove's filesystem drift watcher. It wraps fsnotify
// to follow the user's configured scan roots and folds the burst of
// events that a single edit produces into one debounced "rescan now"
// signal delivered to the caller.
//
// The watcher is intentionally coarse: it does NOT try to translate raw
// fs events into per-secret changes. The scan orchestrator already owns
// dedup and drift detection; the watcher's job is just to wake the
// orchestrator up when something on disk could plausibly have moved a
// secret. Anything finer would duplicate logic that already lives in
// internal/storage.Upsert.
package watch

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/scan"
	"github.com/fsnotify/fsnotify"
)

// DefaultDebounce is the window we wait after the last fs event before
// firing a rescan. Editors like vim and VSCode write a temp file and
// rename it on top of the target, which fires multiple events in close
// succession; the debounce collapses them into a single scan.
const DefaultDebounce = 500 * time.Millisecond

// DefaultMaxWatchDirs caps how many directories the watcher will ever
// register. The cap is a hard backstop against resource exhaustion: on
// macOS fsnotify's kqueue backend opens ONE file descriptor per watched
// directory, so an unbounded walk of $HOME blows past the default
// `ulimit -n` (256) and the whole process starts failing with "too many
// open files" — taking the scanner and HTTP server down with it. With
// the scan excludes applied (which prune node_modules/.git/.cache/…) a
// real home directory lands far below this; the cap only bites on
// pathological trees, where a partial watch + periodic rescan is a much
// better outcome than a dead UI.
const DefaultMaxWatchDirs = 4096

// ErrWatchLimit is returned (wrapped) when the watcher stops registering
// directories because it hit the dir cap or the OS refused a new watch
// with EMFILE/ENOSPC. It is non-fatal: the watcher keeps serving events
// for everything it did register, and the caller should fall back to
// periodic/manual rescans for the rest.
var ErrWatchLimit = errors.New("watch: directory watch limit reached; live updates cover a subset of the scan scope")

// Watcher subscribes to filesystem changes under a set of roots and
// invokes a callback when a debounce window passes after the last event.
//
// Watcher only watches directories — fsnotify on Linux requires every
// directory to be registered explicitly. New subdirectories created
// inside watched paths are picked up on the fly via Create events.
type Watcher struct {
	fsw      *fsnotify.Watcher
	roots    []string
	debounce time.Duration

	// added tracks every directory we currently have a watch on, so we
	// don't double-register and so Close can audit. Guarded by mu.
	mu       sync.Mutex
	added    map[string]struct{}
	excludes []string

	// excluder prunes the same directories the scanner skips
	// (node_modules, .git, ~/Library, …). Without it the watcher walks
	// vastly more of the tree than the scan ever reads. nil == no scan
	// excludes configured.
	excluder *scan.Excluder
	// maxDirs caps total registered directories; see DefaultMaxWatchDirs.
	maxDirs int
	// limited records that addTree stopped early (cap hit or the OS
	// refused a watch with EMFILE/ENOSPC). Read via Limited().
	limited bool
}

// Config bundles the watcher's construction-time options.
type Config struct {
	// Roots is the list of directories to watch recursively. Each is
	// canonicalised (Abs + EvalSymlinks) to match the paths the scan
	// orchestrator produces in events.
	Roots []string
	// Debounce is the post-event quiet window before onChange fires.
	// Zero or negative means DefaultDebounce.
	Debounce time.Duration
	// ExcludeDirs is a list of directory paths that must NOT be watched
	// even if they sit under a configured root. Used to suppress the
	// rescan→save→event→rescan loop the trove global-store directory
	// would otherwise produce when scanned-and-watched at $HOME.
	ExcludeDirs []string
	// Excludes is the user's spec-language exclude pattern set (the same
	// list the scanner uses: `**/node_modules/`, `~/Library/`, …). The
	// watcher prunes these so it doesn't register a watch on every
	// build-output and cache directory under the roots. Passing the
	// scan config's Excludes here is what keeps a $HOME-wide watch from
	// exhausting file descriptors.
	Excludes []string
	// MaxWatchDirs caps total registered directories. Zero or negative
	// means DefaultMaxWatchDirs.
	MaxWatchDirs int
}

// New constructs a Watcher and registers every directory at-or-below
// each root. A non-nil Watcher is always returned alongside any
// partial-setup error so the caller can still Close the underlying
// fsnotify watcher.
func New(roots []string, debounce time.Duration) (*Watcher, error) {
	return NewWithConfig(Config{Roots: roots, Debounce: debounce})
}

// NewWithConfig is the full-options form of New.
func NewWithConfig(cfg Config) (*Watcher, error) {
	debounce := cfg.Debounce
	if debounce <= 0 {
		debounce = DefaultDebounce
	}
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	maxDirs := cfg.MaxWatchDirs
	if maxDirs <= 0 {
		maxDirs = DefaultMaxWatchDirs
	}
	w := &Watcher{
		fsw:      fsw,
		debounce: debounce,
		added:    make(map[string]struct{}),
		excludes: canonDirs(cfg.ExcludeDirs),
		excluder: scan.NewExcluder(cfg.Excludes),
		maxDirs:  maxDirs,
	}
	w.roots = canonDirs(cfg.Roots)
	var firstErr error
	for _, root := range w.roots {
		if err := w.addTree(root); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if w.Limited() && firstErr == nil {
		firstErr = ErrWatchLimit
	}
	return w, firstErr
}

// Limited reports whether the watcher stopped registering directories
// before covering the whole scope (cap hit, or the OS refused a watch
// with EMFILE/ENOSPC). When true, callers should rely on periodic /
// manual rescans for full coverage.
func (w *Watcher) Limited() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.limited
}

// canonDirs runs Abs + EvalSymlinks on each entry, dropping any path
// that fails to resolve. EvalSymlinks failure on an exclude is silent
// because excludes are advisory; a missing dir simply has nothing to
// suppress.
func canonDirs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		abs, err := filepath.Abs(expandHome(p))
		if err != nil {
			continue
		}
		real, err := filepath.EvalSymlinks(abs)
		if err != nil {
			// Non-existent excludes are fine; non-existent roots are
			// dropped here too and the caller gets fewer Roots() back.
			continue
		}
		out = append(out, real)
	}
	return out
}

// Roots returns the canonical root list the watcher is registered against.
// Useful for tests and for logging at startup.
func (w *Watcher) Roots() []string {
	out := make([]string, len(w.roots))
	copy(out, w.roots)
	return out
}

// Run blocks until ctx is cancelled. While running, every fsnotify event
// resets a debounce timer; when the timer fires, onChange is invoked
// synchronously on Run's goroutine. onChange MUST NOT block — kick off
// the rescan asynchronously if it's slow.
//
// Errors from the underlying watcher are forwarded to onError if non-nil
// and otherwise dropped. fsnotify treats most errors as recoverable
// (e.g. a watched directory was deleted), so Run does not return on them.
func (w *Watcher) Run(ctx context.Context, onChange func(), onError func(error)) error {
	if onChange == nil {
		return errors.New("watch: onChange callback is required")
	}
	var (
		timer  *time.Timer
		timerC <-chan time.Time
	)
	resetTimer := func() {
		if timer != nil {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		timer = time.NewTimer(w.debounce)
		timerC = timer.C
	}
	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil
		case ev, ok := <-w.fsw.Events:
			if !ok {
				return nil
			}
			// New subdirectory inside a watched root — pick it up so
			// files created underneath it get reported too. We don't
			// stat for symlink-out-of-root here (the scan does the real
			// boundary check); a rescan will discard anything outside.
			if ev.Op&fsnotify.Create != 0 {
				if info, err := os.Lstat(ev.Name); err == nil && info.IsDir() {
					if w.insideAnyRoot(ev.Name) && !w.isExcluded(ev.Name) && !w.excluder.MatchDir(ev.Name) {
						_ = w.addTree(ev.Name)
					}
				}
			}
			// Drop events that originate inside an excluded directory.
			// fsnotify on Linux fires events on a watched parent for
			// changes to its immediate children, so a renamed temp file
			// in an excluded subtree can still surface as an event on
			// the watched root above it. Suppress those so the trove
			// store-save loop stays tame.
			if w.isExcluded(ev.Name) {
				continue
			}
			// Remove/Rename events on a watched directory cause fsnotify
			// to drop the watch automatically, but we still want to
			// trigger a rescan so the secret entries get marked stale.
			resetTimer()
		case err, ok := <-w.fsw.Errors:
			if !ok {
				return nil
			}
			if onError != nil {
				onError(err)
			}
		case <-timerC:
			timerC = nil
			onChange()
		}
	}
}

// Close releases the underlying fsnotify watcher. Run will return after
// Close drains the channels.
func (w *Watcher) Close() error {
	return w.fsw.Close()
}

// addTree walks root and registers a watch on every directory found.
// Symlinks are not followed: if the user wants them watched, they can
// add the resolved target as a separate root. Errors stating individual
// children are accumulated into the first non-nil error returned, but
// the walk continues so a single unreadable directory doesn't blind the
// whole watcher.
func (w *Watcher) addTree(root string) error {
	var firstErr error
	// errStop is a sentinel used to abort the WalkDir early once we've
	// hit the watch cap or the OS has run out of descriptors/inotify
	// watches. WalkDir treats any non-nil, non-SkipDir return as fatal
	// to the walk, which is exactly what we want — there's no point
	// statting the rest of $HOME once we can't register more watches.
	errStop := errors.New("watch: stop")
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		// Skip symlinked directories — fsnotify follows the link and we'd
		// double-watch the target. The scan orchestrator handles cross-
		// link traversal explicitly.
		if d.Type()&os.ModeSymlink != 0 {
			return filepath.SkipDir
		}
		// Prune the same directories the scanner skips (node_modules,
		// .git, ~/Library, caches, build output). This is the load-
		// bearing line: it keeps the watch count proportional to the
		// user's actual source tree instead of every cache on disk.
		if w.isExcluded(path) || w.excluder.MatchDir(path) {
			return filepath.SkipDir
		}
		w.mu.Lock()
		if len(w.added) >= w.maxDirs {
			w.limited = true
			w.mu.Unlock()
			return errStop
		}
		_, dup := w.added[path]
		if !dup {
			w.added[path] = struct{}{}
		}
		w.mu.Unlock()
		if dup {
			return nil
		}
		if err := w.fsw.Add(path); err != nil {
			// Out of file descriptors / inotify watches: stop here
			// rather than spin through the rest of the tree issuing
			// failing Adds (each of which can leak the partial state).
			// The watcher keeps serving everything registered so far.
			if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) || errors.Is(err, syscall.ENOSPC) {
				w.mu.Lock()
				delete(w.added, path) // the Add didn't take
				w.limited = true
				w.mu.Unlock()
				return errStop
			}
			if firstErr == nil {
				firstErr = err
			}
		}
		return nil
	})
	if errors.Is(walkErr, errStop) {
		walkErr = nil
	}
	if walkErr != nil && firstErr == nil {
		firstErr = walkErr
	}
	return firstErr
}

func (w *Watcher) insideAnyRoot(p string) bool {
	sep := string(filepath.Separator)
	for _, root := range w.roots {
		if p == root || hasPathPrefix(p, root+sep) {
			return true
		}
	}
	return false
}

// isExcluded reports whether p sits at or under any configured exclude
// directory. The check is a pure prefix test against pre-canonicalised
// paths, which is why excludes that don't yet exist on disk are
// dropped at construction time instead of carried as patterns.
func (w *Watcher) isExcluded(p string) bool {
	sep := string(filepath.Separator)
	for _, ex := range w.excludes {
		if p == ex || hasPathPrefix(p, ex+sep) {
			return true
		}
	}
	return false
}

func hasPathPrefix(p, prefix string) bool {
	if len(p) < len(prefix) {
		return false
	}
	return p[:len(prefix)] == prefix
}

// expandHome rewrites a leading "~" or "~/" to the user's home dir.
// Mirrors the helper in internal/scan so the two packages canonicalise
// roots the same way.
func expandHome(p string) string {
	if p == "~" || (len(p) >= 2 && p[:2] == "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return p
		}
		if p == "~" {
			return home
		}
		return filepath.Join(home, p[2:])
	}
	return p
}
