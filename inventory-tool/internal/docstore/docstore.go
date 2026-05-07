// Package docstore wraps the live storage.Global with the lock and
// saver that everything mutating it needs to share. The HTTP handlers
// (annotate, mark stale, mark rotated) and the rescan loop both
// mutate the same document; without a single shared lock a click in
// the UI during a rescan would race the scanner. docstore is the
// one place that lock lives.
//
// Read holds the lock for the duration of fn and never persists.
// Update holds the lock, runs fn, and persists with the saver if fn
// returns true. The doc is not copied — fn receives a live pointer
// and must not retain it past the call.
package docstore

import (
	"sync"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
)

// Saver persists the global doc to its backing store. Failure surfaces
// to the caller of Update.
type Saver func(*storage.Global) error

// Store is the lock+saver wrapper around a single storage.Global.
//
// The zero value is not usable; construct with New.
type Store struct {
	mu   sync.Mutex
	doc  *storage.Global
	save Saver
}

// New returns a Store wrapping doc with save as the persistence
// callback. Callers who already loaded a doc from disk hand it in;
// New does not call save.
func New(doc *storage.Global, save Saver) *Store {
	return &Store{doc: doc, save: save}
}

// Read calls fn with the doc held under lock. fn must not retain the
// pointer past return.
func (s *Store) Read(fn func(*storage.Global)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s.doc)
}

// Update calls fn under lock. If fn returns true, the saver is
// invoked with the (mutated) doc and any error is returned. If fn
// returns false, no save is attempted and Update returns nil — useful
// when the requested mutation turned out to be a no-op (e.g. id not
// found, no actual change).
func (s *Store) Update(fn func(*storage.Global) bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !fn(s.doc) {
		return nil
	}
	return s.save(s.doc)
}
