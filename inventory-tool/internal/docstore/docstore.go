// Package docstore wraps the live storage.Global with the lock and
// saver that everything mutating it needs to share. The HTTP handlers
// (annotate, mark stale, mark rotated) and the rescan loop both
// mutate the same document; without a single shared lock a click in
// the UI during a rescan would race the scanner. docstore is the
// one place that lock lives.
//
// Reads are lock-free. The current doc is held in an atomic pointer
// that Update swaps under a writer mutex; Read and Snapshot just load
// the pointer. The doc behind that pointer is treated as immutable —
// callers receive a pointer they may serialise from but must not
// mutate, because the same pointer is shared across all concurrent
// readers and the next Update.
//
// Update serialises mutations: it clones the current doc, runs fn on
// the clone, persists via the saver if fn returns true, then atomically
// publishes the new doc. fn therefore mutates a private copy and never
// races a reader — the cost is a per-update deep clone, which is
// negligible compared to the JSON round-trip Save already does.
package docstore

import (
	"sync"
	"sync/atomic"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
)

// Saver persists the global doc to its backing store. Failure surfaces
// to the caller of Update.
type Saver func(*storage.Global) error

// Store is the writer-mutex + atomic-pointer wrapper around a
// storage.Global. The zero value is not usable; construct with New.
type Store struct {
	mu   sync.Mutex // serialises Update; readers do not take it
	doc  atomic.Pointer[storage.Global]
	save Saver
}

// New returns a Store wrapping doc with save as the persistence
// callback. Callers who already loaded a doc from disk hand it in;
// New does not call save.
func New(doc *storage.Global, save Saver) *Store {
	s := &Store{save: save}
	s.doc.Store(doc)
	return s
}

// Snapshot returns a pointer to the current immutable doc. Cost: one
// atomic load. Callers must not mutate the returned doc — pass it to
// JSON marshalling or copy fields out, but never assign into its
// slices or fields. The next Update will publish a different pointer;
// previously-handed-out pointers remain valid as long as the caller
// holds them.
func (s *Store) Snapshot() *storage.Global {
	return s.doc.Load()
}

// Read calls fn with the current doc. Non-blocking; fn sees an
// immutable snapshot. fn must not retain the pointer past return and
// must not mutate the doc.
func (s *Store) Read(fn func(*storage.Global)) {
	fn(s.doc.Load())
}

// Update serialises with other Updates via the writer mutex, clones
// the current doc, and calls fn on the clone. If fn returns true the
// saver is invoked with the mutated clone and any error is returned;
// on success the clone is atomically published as the new current doc.
// If fn returns false (no-op) nothing is saved or published and Update
// returns nil — useful when the requested mutation turned out to be a
// no-op (e.g. id not found, no actual change).
//
// fn receives a private clone; it may mutate slices and fields freely
// without affecting concurrent readers. fn must not retain the pointer
// past return.
func (s *Store) Update(fn func(*storage.Global) bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := Clone(s.doc.Load())
	if !fn(next) {
		return nil
	}
	if err := s.save(next); err != nil {
		return err
	}
	s.doc.Store(next)
	return nil
}
