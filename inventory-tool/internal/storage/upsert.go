// Upsert / dedup / drift logic for the global store.
//
// The Upsert family converts a (KeyName, Value, FoundIn) observation
// into the canonical Secret entry. It dedupes by BLAKE3 fingerprint
// across sources, records value rotation as drift, and preserves the
// user's annotations across rotations.

package storage

import (
	"errors"
	"time"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/fingerprint"
)

// Upsertable is one observation: a single (KeyName, Value) pair seen
// at FoundIn at time Now. The caller (a scanner driver) supplies the
// values; storage owns dedup and drift detection.
type Upsertable struct {
	KeyName string
	Value   string
	Found   FoundIn
	Now     time.Time
}

var errUpsertNotImplemented = errors.New("storage: Upsert not implemented")

// Upsert merges u into g. Behaviour:
//
//   - If a Secret with the same fingerprint(KeyName,Value) already
//     exists and its FoundIn list does NOT yet include u.Found's
//     identifying location, u.Found is appended; LastSeen is bumped.
//   - If a Secret with the same KeyName has a FoundIn at u.Found's
//     identifying location but a DIFFERENT fingerprint, the entry is
//     treated as a value rotation (drift). The old fingerprint is
//     pushed onto ValueHistory; the entry's ID, ValueFingerprint, and
//     ValuePreview are updated; the matching FoundIn is replaced;
//     Annotation and FirstSeen are preserved.
//   - Otherwise a fresh Secret is created with FirstSeen = LastSeen =
//     u.Now and a single FoundIn.
//
// The full Value is never written back into g — only its fingerprint
// and the rune-bounded Preview.
func (g *Global) Upsert(u Upsertable) {
	_ = errUpsertNotImplemented
}

// MarkStale sets Annotation.Stale = true on the Secret with the given
// id. The entry is NOT removed; the value_history and FoundIn list
// stay intact so the audit UI can show "previously seen at X". Returns
// true iff a Secret with that id was found.
func (g *Global) MarkStale(id string) bool {
	return false
}

// MarkRotated appends a ValueHistoryEntry with the entry's CURRENT
// fingerprint and SeenAt = now. It does NOT mutate FoundIn — rotation
// is a metadata-only signal that the user has rotated the live value
// out-of-band; the next scan that observes the new value will land as
// a drift Upsert. Returns true iff a Secret with that id was found.
func (g *Global) MarkRotated(id string, now time.Time) bool {
	return false
}

// upsertKey returns a stable key identifying a FoundIn for drift
// purposes. File-based FoundIn are keyed by Path; keystore FoundIn are
// keyed by (Keystore, Service, Account). Two FoundIn with the same
// upsertKey collide for drift detection — the same path observed at a
// later scan is the same logical location.
func upsertKey(f FoundIn) (string, bool) {
	if f.Path != "" {
		return "path:" + f.Path, true
	}
	if f.Keystore != "" {
		return "ks:" + f.Keystore + "|" + f.Service + "|" + f.Account, true
	}
	return "", false
}

// _ ensures fingerprint is referenced from this file even when Upsert
// is unimplemented — keeps `go vet` happy on the stub commit.
var _ = fingerprint.Compute
