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
//
// Two things keep the watcher cheap on busy filesystems:
//
//   - Exclude-aware Add: directories that match the user's
//     scan_config.excludes patterns are NEVER registered with fsnotify.
//     A node_modules / .git / etc. exclude keeps the inotify watch list
//     small even when the configured root is broad like $HOME.
//
//   - Non-blocking onChange dispatch: the debounce timer fires onChange
//     in a fresh goroutine, so a slow consumer (the rescanner doing a
//     lock-free scan) doesn't stop us draining fsnotify's event queue.
//     If onChange runs slower than events arrive, the rescanner's own
//     rate-limit gate handles coalescing. The events themselves are
//     never queued by us — fsnotify owns its buffer.
package watch

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/excludes"
)

// DefaultDebounce is the window we wait after the last fs event before
// firing a rescan. Editors like vim and VSCode write a temp file and
// rename it on top of the target, which fires multiple events in close
// succession; the debounce collapses them into a single scan.
const DefaultDebounce = 500 * time.Millisecond

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
	mu              sync.Mutex
	added           map[string]struct{}
	excludeDirs     []string
	excludeMatchers []excludes.Matcher

	// eventsDropped counts fsnotify queue-overflow signals plus any
	// drops we apply ourselves. Exposed via EventsDropped so the
	// /api/status endpoint can surface saturation to a curl probe.
	eventsDropped atomic.Int64
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
	//
	// These are pre-canonicalised paths (no glob); a matching path or
	// any descendant is silently dropped on Add and on event delivery.
	ExcludeDirs []string
	// ExcludePatterns is the glob-style exclude language from
	// scan_config.excludes (e.g. `**/node_modules/`, `**/.git/`,
	// `~/Library/`). The watcher honours the same patterns the walker
	// does so a noisy excluded subtree never lands in the inotify
	// watch list.
	ExcludePatterns []string
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
	w := &Watcher{
		fsw:             fsw,
		debounce:        debounce,
		added:           make(map[string]struct{}),
		excludeDirs:     canonDirs(cfg.ExcludeDirs),
		excludeMatchers: excludes.Compile(cfg.ExcludePatterns),
	}
	w.roots = canonDirs(cfg.Roots)
	var firstErr error
	for _, root := range w.roots {
		if err := w.addTree(root); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return w, firstErr
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

// EventsDropped returns the running tally of fs events we couldn't
// service — currently an fsnotify queue-overflow report. Surfaced via
// /api/status so a saturating consumer is visible to curl without
// reading server logs.
func (w *Watcher) EventsDropped() int64 {
	return w.eventsDropped.Load()
}

// Run blocks until ctx is cancelled. While running, every fsnotify event
// resets a debounce timer; when the timer fires, onChange is invoked on
// a fresh goroutine so a slow scan can't stop the watcher from draining
// fsnotify's event queue. onChange may be called concurrently if a
// previous invocation hasn't returned; the rescanner gates duplicates
// itself.
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
					if w.insideAnyRoot(ev.Name) && !w.isExcluded(ev.Name) {
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
			// fsnotify reports kernel-side queue overflow as a string-
			// matched error; count those so /api/status can show the
			// drop tally. Other errors (deleted watched dir, etc.) are
			// non-fatal and just go to onError.
			if err != nil && strings.Contains(err.Error(), "queue overflow") {
				w.eventsDropped.Add(1)
			}
			if onError != nil {
				onError(err)
			}
		case <-timerC:
			timerC = nil
			// Dispatch onChange on a fresh goroutine so a slow scan
			// can't block the event drain. The rescanner is responsible
			// for in-flight coalescing + rate-limiting.
			go onChange()
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
		if w.isExcluded(path) {
			return filepath.SkipDir
		}
		w.mu.Lock()
		_, dup := w.added[path]
		if !dup {
			w.added[path] = struct{}{}
		}
		w.mu.Unlock()
		if dup {
			return nil
		}
		if err := w.fsw.Add(path); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
		return nil
	})
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
// directory, OR matches one of the configured exclude-patterns from
// scan_config.excludes. ExcludeDirs is a pure prefix test against
// pre-canonicalised paths; ExcludePatterns runs through the same
// glob-language matcher the walker uses, so the two stay in lockstep.
//
// We pass isDir=true to the matcher because the watcher only ever
// considers directories — a path-from-events doesn't have to be a
// directory, but we use isExcluded as a "should we register a watch
// here?" filter, which only fires for directories. Fall-through is the
// safe direction: a non-matching directory is watched (correct);
// a non-matching file is irrelevant to addTree.
func (w *Watcher) isExcluded(p string) bool {
	sep := string(filepath.Separator)
	for _, ex := range w.excludeDirs {
		if p == ex || hasPathPrefix(p, ex+sep) {
			return true
		}
	}
	if len(w.excludeMatchers) > 0 {
		// Try as a directory first — that's the watcher's normal use.
		// If a non-dir path happens through, fall back to file-mode so
		// `**/.DS_Store` style excludes also fire.
		if excludes.Match(p, true, w.excludeMatchers) || excludes.Match(p, false, w.excludeMatchers) {
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
