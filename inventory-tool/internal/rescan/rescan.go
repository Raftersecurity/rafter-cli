// Package rescan glues the fsnotify watcher, the scan orchestrator,
// the storage document, and the SSE event bus into a single long-lived
// background loop. It exists as a separate package so internal/watch
// stays focused on raw fs events and doesn't grow a transitive
// dependency on storage or scan.
//
// Concurrency model: scans run OUTSIDE the docstore writer lock. We
// snapshot the current doc, scan into a sandbox copy, then take the
// writer lock briefly to atomically publish the new secrets list with
// user annotations preserved. The doc is never write-locked for the
// duration of a filesystem walk; HTTP read paths therefore stay
// responsive even when a $HOME-sized scan takes seconds.
//
// Rescans are also rate-limited: the watcher's debounce can only
// trigger so many scans per second, so a sustained event firehose
// produces a bounded number of scans, not one per debounce-fire.
package rescan

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/docstore"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/eventbus"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/scan"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/watch"
)

// DefaultMaxRescanRate caps how often a watcher-driven rescan can fire.
// The watcher's debounce (~500ms) already collapses event bursts; this
// is the hard ceiling that survives sustained churn — at most one full
// scan per second, regardless of how many debounce windows close.
const DefaultMaxRescanRate = 1 * time.Second

// Config wires the rescanner. Store/Bus are required; Watcher is
// optional — passing nil means "construct one from the doc's
// ScanConfig.Roots".
type Config struct {
	Store   *docstore.Store
	Bus     *eventbus.Bus
	Watcher *watch.Watcher
	// MaxRescanRate is the minimum gap between watcher-driven rescans.
	// Zero or negative means DefaultMaxRescanRate. Direct callers of
	// Rescan() (the manual --rescan path, tests) bypass this gate.
	MaxRescanRate time.Duration
	// OnError is called for non-fatal scan or save errors. nil = drop.
	OnError func(error)
}

// Rescanner owns the watcher lifecycle. Concurrency safety with the
// HTTP handlers comes from the shared docstore.Store; Rescanner's own
// mutex only protects the rate-limit + pending-coalesce state.
type Rescanner struct {
	cfg Config

	// rateMu guards lastRescan + pending. They're touched from the
	// watcher goroutine (driveRescan) and the in-flight rescan goroutine
	// (when it kicks off a deferred follow-up).
	rateMu      sync.Mutex
	lastRescan  time.Time
	rescanning  bool
	pending     bool
}

// New validates cfg and returns a Rescanner. If cfg.Watcher is nil, a
// fresh watch.Watcher is created against the doc's ScanConfig.Roots.
// Any partial-setup error from the watcher is returned alongside a
// usable Rescanner so the caller can decide whether to abort or
// proceed.
func New(cfg Config) (*Rescanner, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("rescan: nil store")
	}
	if cfg.Bus == nil {
		return nil, fmt.Errorf("rescan: nil bus")
	}
	if cfg.MaxRescanRate <= 0 {
		cfg.MaxRescanRate = DefaultMaxRescanRate
	}
	var partial error
	if cfg.Watcher == nil {
		snap := cfg.Store.Snapshot()
		var roots []string
		if snap != nil {
			roots = append(roots, snap.ScanConfig.Roots...)
		}
		w, err := watch.New(roots, 0)
		if err != nil {
			partial = err
		}
		cfg.Watcher = w
	}
	return &Rescanner{cfg: cfg}, partial
}

// Run blocks until ctx is cancelled. Each fs-event burst within the
// watcher's debounce window collapses into one driveRescan call,
// which respects MaxRescanRate and coalesces overlapping requests.
func (r *Rescanner) Run(ctx context.Context) error {
	if r.cfg.Watcher == nil {
		return fmt.Errorf("rescan: nil watcher")
	}
	defer r.cfg.Watcher.Close()
	return r.cfg.Watcher.Run(ctx, func() {
		r.driveRescan(ctx)
	}, r.cfg.OnError)
}

// driveRescan applies the rate-limit + coalesce gate before invoking
// Rescan. Behaviour:
//
//   - If a rescan is currently in flight, mark a follow-up pending and
//     return. The in-flight rescan will trigger one more pass on
//     completion (subject to MaxRescanRate).
//   - If we're inside MaxRescanRate of the previous start, set pending
//     and return; the gating goroutine handles the deferred kick.
//   - Otherwise, claim the in-flight slot and run Rescan synchronously
//     on the watcher goroutine. After completion, drain pending and
//     schedule another driveRescan if needed.
//
// The watcher's onChange runs on the watcher's Run goroutine, so we
// MUST NOT block it for long. Rescan itself can take seconds; we
// therefore launch it in its own goroutine and let the watcher keep
// pumping events.
func (r *Rescanner) driveRescan(ctx context.Context) {
	r.rateMu.Lock()
	if r.rescanning {
		r.pending = true
		r.rateMu.Unlock()
		return
	}
	now := time.Now()
	wait := r.cfg.MaxRescanRate - now.Sub(r.lastRescan)
	if wait > 0 {
		// Too soon. Mark pending; the gating goroutine will fire once
		// the rate-limit window expires.
		if !r.pending {
			r.pending = true
			r.rateMu.Unlock()
			go r.waitAndKick(ctx, wait)
			return
		}
		r.rateMu.Unlock()
		return
	}
	r.rescanning = true
	r.lastRescan = now
	r.rateMu.Unlock()

	go func() {
		r.Rescan(ctx)
		r.rateMu.Lock()
		r.rescanning = false
		hadPending := r.pending
		r.pending = false
		r.rateMu.Unlock()
		if hadPending && ctx.Err() == nil {
			// Fire the follow-up pass on a fresh goroutine so this one
			// can return.
			go r.driveRescan(ctx)
		}
	}()
}

// waitAndKick sleeps until the rate-limit window opens, then re-enters
// driveRescan. ctx cancellation is honoured.
func (r *Rescanner) waitAndKick(ctx context.Context, wait time.Duration) {
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return
	case <-t.C:
		r.driveRescan(ctx)
	}
}

// Rescan re-runs the scan and publishes per-secret + summary events.
// Exposed (rather than only-private) so tests and the manual --rescan
// path can drive it deterministically. This entry point IGNORES
// MaxRescanRate — direct callers know what they're doing.
//
// The flow:
//
//  1. Snapshot the live doc and clone it into a sandbox.
//  2. Run scan.Run against the sandbox. The doc lock is NOT held.
//  3. Atomically publish the sandbox's Secrets back into the live
//     doc, preserving any Annotation edits the user made during the
//     scan window. The doc lock is held only for this brief swap.
func (r *Rescanner) Rescan(ctx context.Context) {
	r.cfg.Bus.Publish(eventbus.Event{Type: eventbus.EventScanStarted})

	// Step 1: snapshot + clone. Clone is needed because Upsert mutates
	// in place (drift detection looks at existing secrets).
	snap := r.cfg.Store.Snapshot()
	work := docstore.Clone(snap)
	if work == nil {
		work = storage.Empty()
	}

	// Step 2: scan into the sandbox, OUTSIDE the writer lock.
	res, err := scan.Run(ctx, work, work.ScanConfig)
	if err != nil {
		if r.cfg.OnError != nil {
			r.cfg.OnError(fmt.Errorf("rescan: scan: %w", err))
		}
		return
	}

	// Step 3: atomic-swap. The Update closure runs under the writer
	// mutex; it clones the latest live doc, copies the user-owned
	// Annotation fields onto our scanned secrets (so concurrent
	// annotate / mark-stale / mark-rotated edits made during the scan
	// window aren't lost), then replaces the secrets list.
	saveErr := r.cfg.Store.Update(func(live *storage.Global) bool {
		annoByID := make(map[string]storage.Annotation, len(live.Secrets))
		for i := range live.Secrets {
			annoByID[live.Secrets[i].ID] = live.Secrets[i].Annotation
		}
		live.Secrets = work.Secrets
		for i := range live.Secrets {
			if anno, ok := annoByID[live.Secrets[i].ID]; ok {
				live.Secrets[i].Annotation = anno
			}
		}
		return true
	})
	if saveErr != nil && r.cfg.OnError != nil {
		r.cfg.OnError(fmt.Errorf("rescan: save: %w", saveErr))
	}

	for _, c := range res.Changes {
		r.cfg.Bus.Publish(eventbus.Event{
			Type:     outcomeToEventType(c.Outcome),
			SecretID: c.SecretID,
			KeyName:  c.KeyName,
			Path:     c.Path,
		})
	}

	r.cfg.Bus.Publish(eventbus.Event{
		Type: eventbus.EventScanComplete,
		Stats: &eventbus.ScanStats{
			FilesScanned: res.FilesScanned,
			SecretsFound: res.SecretsFound,
			Errors:       len(res.Errors),
		},
	})
}

func outcomeToEventType(o storage.Outcome) string {
	switch o {
	case storage.OutcomeCreated:
		return eventbus.EventSecretCreated
	case storage.OutcomeDrifted:
		return eventbus.EventSecretDrifted
	default:
		return eventbus.EventSecretRefreshed
	}
}
