// Package rescan glues the fsnotify watcher, the scan orchestrator,
// the storage document, and the SSE event bus into a single long-lived
// background loop. It exists as a separate package so internal/watch
// stays focused on raw fs events and doesn't grow a transitive
// dependency on storage or scan.
package rescan

import (
	"context"
	"fmt"
	"sync"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/eventbus"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/scan"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/watch"
)

// Saver persists the global doc. The whole point of the rescanner is
// to keep the on-disk store in sync with the live filesystem, so we
// require a saver rather than letting it default to a no-op.
type Saver func(*storage.Global) error

// Config wires the rescanner. Doc/Saver/Bus are required; Watcher is
// optional — passing nil means "construct one from doc.ScanConfig.Roots".
type Config struct {
	Doc     *storage.Global
	Saver   Saver
	Bus     *eventbus.Bus
	Watcher *watch.Watcher
	// OnError is called for non-fatal scan or save errors. nil = drop.
	OnError func(error)
}

// Rescanner owns the watcher lifecycle. It is safe to call Run exactly
// once; for re-arming after a config change, build a new Rescanner.
type Rescanner struct {
	cfg Config
	mu  sync.Mutex
}

// New validates cfg and returns a Rescanner. If cfg.Watcher is nil, a
// fresh watch.Watcher is created against doc.ScanConfig.Roots. Any
// partial-setup error from the watcher is returned alongside a usable
// Rescanner so the caller can decide whether to abort or proceed.
func New(cfg Config) (*Rescanner, error) {
	if cfg.Doc == nil {
		return nil, fmt.Errorf("rescan: nil doc")
	}
	if cfg.Saver == nil {
		return nil, fmt.Errorf("rescan: nil saver")
	}
	if cfg.Bus == nil {
		return nil, fmt.Errorf("rescan: nil bus")
	}
	var partial error
	if cfg.Watcher == nil {
		w, err := watch.New(cfg.Doc.ScanConfig.Roots, 0)
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
	r.mu.Lock()
	defer r.mu.Unlock()

	r.cfg.Bus.Publish(eventbus.Event{Type: eventbus.EventScanStarted})

	res, err := scan.Run(ctx, r.cfg.Doc, r.cfg.Doc.ScanConfig)
	if err != nil {
		if r.cfg.OnError != nil {
			r.cfg.OnError(fmt.Errorf("rescan: scan: %w", err))
		}
		return
	}

	for _, c := range res.Changes {
		r.cfg.Bus.Publish(eventbus.Event{
			Type:     outcomeToEventType(c.Outcome),
			SecretID: c.SecretID,
			KeyName:  c.KeyName,
			Path:     c.Path,
		})
	}

	if err := r.cfg.Saver(r.cfg.Doc); err != nil {
		if r.cfg.OnError != nil {
			r.cfg.OnError(fmt.Errorf("rescan: save: %w", err))
		}
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
