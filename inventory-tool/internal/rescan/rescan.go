// Package rescan glues the fsnotify watcher, the scan orchestrator,
// the storage document, and the SSE event bus into a single long-lived
// background loop. It exists as a separate package so internal/watch
// stays focused on raw fs events and doesn't grow a transitive
// dependency on storage or scan.
package rescan

import (
	"context"
	"fmt"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/docstore"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/eventbus"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/scan"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/watch"
)

// Config wires the rescanner. Store/Bus are required; Watcher is
// optional — passing nil means "construct one from the doc's
// ScanConfig.Roots".
type Config struct {
	Store   *docstore.Store
	Bus     *eventbus.Bus
	Watcher *watch.Watcher
	// OnError is called for non-fatal scan or save errors. nil = drop.
	OnError func(error)
}

// Rescanner owns the watcher lifecycle. Concurrency safety with the
// HTTP handlers comes from the shared docstore.Store; Rescanner
// itself adds no extra mutex.
type Rescanner struct {
	cfg Config
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
	var partial error
	if cfg.Watcher == nil {
		var roots []string
		cfg.Store.Read(func(g *storage.Global) {
			roots = append(roots, g.ScanConfig.Roots...)
		})
		w, err := watch.New(roots, 0)
		if err != nil {
			partial = err
		}
		cfg.Watcher = w
	}
	return &Rescanner{cfg: cfg}, partial
}

// Run blocks until ctx is cancelled. Each fs-event burst within the
// watcher's debounce window collapses into one Rescan() call.
func (r *Rescanner) Run(ctx context.Context) error {
	if r.cfg.Watcher == nil {
		return fmt.Errorf("rescan: nil watcher")
	}
	defer r.cfg.Watcher.Close()
	return r.cfg.Watcher.Run(ctx, func() {
		r.Rescan(ctx)
	}, r.cfg.OnError)
}

// Rescan re-runs the scan and publishes per-secret + summary events.
// Exposed (rather than only-private) so tests and the manual --rescan
// path can drive it deterministically.
func (r *Rescanner) Rescan(ctx context.Context) {
	r.cfg.Bus.Publish(eventbus.Event{Type: eventbus.EventScanStarted})

	var (
		runErr error
		// Capture changes + stats outside the lock so we can publish
		// events without holding it longer than necessary.
		changes []scan.Change
		stats   *eventbus.ScanStats
	)
	saveErr := r.cfg.Store.Update(func(g *storage.Global) bool {
		res, err := scan.Run(ctx, g, g.ScanConfig)
		if err != nil {
			runErr = err
			return false
		}
		changes = append(changes, res.Changes...)
		stats = &eventbus.ScanStats{
			FilesScanned: res.FilesScanned,
			SecretsFound: res.SecretsFound,
			Errors:       len(res.Errors),
		}
		return true
	})
	if runErr != nil {
		if r.cfg.OnError != nil {
			r.cfg.OnError(fmt.Errorf("rescan: scan: %w", runErr))
		}
		return
	}
	if saveErr != nil && r.cfg.OnError != nil {
		r.cfg.OnError(fmt.Errorf("rescan: save: %w", saveErr))
	}

	for _, c := range changes {
		r.cfg.Bus.Publish(eventbus.Event{
			Type:     outcomeToEventType(c.Outcome),
			SecretID: c.SecretID,
			KeyName:  c.KeyName,
			Path:     c.Path,
		})
	}

	r.cfg.Bus.Publish(eventbus.Event{
		Type:  eventbus.EventScanComplete,
		Stats: stats,
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
