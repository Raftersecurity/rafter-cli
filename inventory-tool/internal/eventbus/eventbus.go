// Package eventbus is trove's in-process pub/sub for drift events.
// Producers (the watcher-driven rescanner) Publish; consumers (the SSE
// route handler) Subscribe and receive a stream over a buffered channel.
//
// The bus is intentionally minimal — no persistence, no replay. SSE
// clients that connect after a Publish miss the event; that's fine
// because the global store is the source of truth and the UI hydrates
// from it on connect.
package eventbus

import (
	"context"
	"sync"
	"time"
)

// Event types. The set is deliberately small and stable — both the SSE
// stream's "event:" field and the JSON envelope's "type" use these
// strings, and the browser code switches on them.
const (
	EventScanStarted  = "scan_started"
	EventScanComplete = "scan_complete"
	EventSecretCreated  = "secret_created"
	EventSecretRefreshed = "secret_refreshed"
	EventSecretDrifted  = "secret_drifted"
)

// Event is a single drift signal. Empty fields are omitted from the
// SSE payload so the wire shape stays small for the common cases.
type Event struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`

	// Optional payload fields. SecretID + KeyName are filled for
	// per-secret events; the scan_complete summary uses Stats.
	SecretID string `json:"secret_id,omitempty"`
	KeyName  string `json:"key_name,omitempty"`
	Path     string `json:"path,omitempty"`

	Stats *ScanStats `json:"stats,omitempty"`
}

// ScanStats is the summary attached to a scan_complete event. Mirrors
// scan.Result so the browser can show "scanned N files" without a
// separate fetch.
type ScanStats struct {
	FilesScanned int `json:"files_scanned"`
	SecretsFound int `json:"secrets_found"`
	Errors       int `json:"errors"`
}

// subscriberBufferSize bounds memory per subscriber. If a client falls
// this far behind, the bus drops events to that subscriber rather than
// blocking publishers — a slow browser tab cannot stall the rescanner.
const subscriberBufferSize = 64

// Bus is a fan-out broker. Zero-value is not usable — call New.
type Bus struct {
	mu   sync.Mutex
	subs map[*subscriber]struct{}
}

type subscriber struct {
	ch chan Event
	// dropped counts events lost because the channel was full at
	// publish time. Exposed via DroppedEvents for tests + diagnostics.
	dropped int
}

// New returns an empty bus.
func New() *Bus {
	return &Bus{subs: make(map[*subscriber]struct{})}
}

// Subscribe registers a new subscriber and returns a receive-only
// channel of events. The subscription is bound to ctx: when ctx is
// cancelled the subscriber is removed and the channel is closed. A
// SubscriberHandle is also returned for tests that need to inspect
// drop counts; production callers can ignore it.
func (b *Bus) Subscribe(ctx context.Context) (<-chan Event, *SubscriberHandle) {
	s := &subscriber{ch: make(chan Event, subscriberBufferSize)}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()

	go func() {
		<-ctx.Done()
		b.mu.Lock()
		if _, ok := b.subs[s]; ok {
			delete(b.subs, s)
			close(s.ch)
		}
		b.mu.Unlock()
	}()
	return s.ch, &SubscriberHandle{s: s}
}

// Publish delivers e to every current subscriber. Subscribers whose
// buffers are full have the event dropped (and their drop count
// incremented) — Publish never blocks.
func (b *Bus) Publish(e Event) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for s := range b.subs {
		select {
		case s.ch <- e:
		default:
			s.dropped++
		}
	}
}

// SubscriberCount reports how many active subscriptions the bus has.
// Useful for tests; not exposed on the wire.
func (b *Bus) SubscriberCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
}

// SubscriberHandle exposes per-subscription diagnostics.
type SubscriberHandle struct {
	s *subscriber
}

// DroppedEvents returns the number of events dropped for this
// subscriber because its channel was full at publish time.
func (h *SubscriberHandle) DroppedEvents() int {
	if h == nil || h.s == nil {
		return 0
	}
	return h.s.dropped
}
