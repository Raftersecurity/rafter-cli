package rescan

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/docstore"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/eventbus"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
)

// drainEvents pulls events into a slice until the channel is empty for
// quietFor. Returns events received in order.
func drainEvents(t *testing.T, ch <-chan eventbus.Event, quietFor time.Duration) []eventbus.Event {
	t.Helper()
	var out []eventbus.Event
	timer := time.NewTimer(quietFor)
	defer timer.Stop()
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, ev)
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(quietFor)
		case <-timer.C:
			return out
		}
	}
}

func TestRescan_EmitsCreatedThenDriftEvents(t *testing.T) {
	root := t.TempDir()
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("API_KEY=first-value-1234567890\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	doc := storage.Empty()
	doc.ScanConfig.Roots = []string{root}

	bus := eventbus.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sub, _ := bus.Subscribe(ctx)

	var saved int
	var mu sync.Mutex
	saver := func(d *storage.Global) error {
		mu.Lock()
		defer mu.Unlock()
		saved++
		return nil
	}

	store := docstore.New(doc, saver)
	r, err := New(Config{Store: store, Bus: bus})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer r.cfg.Watcher.Close()

	// Initial scan: should see scan_started, secret_created, scan_complete.
	r.Rescan(ctx)
	events := drainEvents(t, sub, 100*time.Millisecond)
	got := typeSequence(events)
	want := []string{
		eventbus.EventScanStarted,
		eventbus.EventSecretCreated,
		eventbus.EventScanComplete,
	}
	if !equalSequence(got, want) {
		t.Fatalf("first rescan event types = %v, want %v", got, want)
	}

	// Mutate the file: drift.
	if err := os.WriteFile(envPath, []byte("API_KEY=second-value-9999999999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.Rescan(ctx)
	events = drainEvents(t, sub, 100*time.Millisecond)
	got = typeSequence(events)
	want = []string{
		eventbus.EventScanStarted,
		eventbus.EventSecretDrifted,
		eventbus.EventScanComplete,
	}
	if !equalSequence(got, want) {
		t.Fatalf("drift rescan event types = %v, want %v", got, want)
	}

	// Re-run with no change: refreshed.
	r.Rescan(ctx)
	events = drainEvents(t, sub, 100*time.Millisecond)
	got = typeSequence(events)
	want = []string{
		eventbus.EventScanStarted,
		eventbus.EventSecretRefreshed,
		eventbus.EventScanComplete,
	}
	if !equalSequence(got, want) {
		t.Fatalf("refresh rescan event types = %v, want %v", got, want)
	}

	mu.Lock()
	if saved != 3 {
		t.Errorf("saver called %d times, want 3", saved)
	}
	mu.Unlock()

	// scan_complete should carry stats.
	hasStats := false
	for _, e := range events {
		if e.Type == eventbus.EventScanComplete && e.Stats != nil && e.Stats.FilesScanned == 1 {
			hasStats = true
		}
	}
	if !hasStats {
		t.Errorf("scan_complete missing or wrong stats: %+v", events)
	}
}

func TestRescan_RequiresAllConfig(t *testing.T) {
	doc := storage.Empty()
	saver := func(*storage.Global) error { return nil }
	store := docstore.New(doc, saver)
	bus := eventbus.New()

	if _, err := New(Config{Bus: bus}); err == nil {
		t.Error("expected error for nil store")
	}
	if _, err := New(Config{Store: store}); err == nil {
		t.Error("expected error for nil bus")
	}
}

func typeSequence(evs []eventbus.Event) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.Type
	}
	return out
}

func equalSequence(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
