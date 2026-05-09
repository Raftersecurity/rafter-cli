// Upsert / dedup / drift logic for the global store.
//
// The Upsert family converts a (KeyName, Value, FoundIn) observation
// into the canonical Secret entry. It dedupes by BLAKE3 fingerprint
// across sources, records value rotation as drift, and preserves the
// user's annotations across rotations.

package storage

import (
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

// Outcome is the kind of change Upsert applied to the global store.
// Used by the scan orchestrator to emit per-secret SSE events without
// rebuilding the diff itself.
type Outcome int

const (
	// OutcomeCreated: a brand-new Secret entry was appended.
	OutcomeCreated Outcome = iota
	// OutcomeRefreshed: an existing observation was re-confirmed at
	// the same path/keystore key with the same fingerprint, OR a known
	// fingerprint was newly observed at an additional location.
	OutcomeRefreshed
	// OutcomeDrifted: an existing path/keystore key now reports a
	// different fingerprint. The previous fingerprint was pushed onto
	// ValueHistory; the secret's ID is the new fingerprint.
	OutcomeDrifted
)

// Result is the per-Upsert summary returned to callers. Secret is a
// pointer into g.Secrets and is only valid until the next Upsert
// reslices the underlying array; copy fields out if you need to
// outlive the next call.
type UpsertResult struct {
	Outcome Outcome
	Secret  *Secret
}

// Upsert merges u into g. Behaviour:
//
//   - If a Secret with the same KeyName already has a FoundIn at u's
//     identifying location and a DIFFERENT fingerprint, the entry is
//     treated as a value rotation (drift). The old fingerprint is
//     pushed onto ValueHistory; ID, ValueFingerprint, and ValuePreview
//     are updated; the matching FoundIn is replaced with u.Found;
//     Annotation and FirstSeen are preserved.
//   - Otherwise, if a Secret with the same fingerprint(KeyName,Value)
//     already exists, u.Found is appended to its FoundIn list (or, if
//     that location is already present, the entry there is refreshed).
//     LastSeen is bumped.
//   - Otherwise a fresh Secret is created with FirstSeen = LastSeen =
//     u.Now and a single FoundIn.
//
// The full Value is never written back into g — only its fingerprint
// and the rune-bounded Preview.
//
// Returns an UpsertResult describing what changed. Existing call sites
// that ignore the return value continue to work unchanged.
func (g *Global) Upsert(u Upsertable) UpsertResult {
	newFP := fingerprint.Compute(u.KeyName, u.Value)
	uKey, uHasKey := upsertKey(u.Found)

	// Drift check: same KeyName + same identifying location + different fingerprint.
	// We have to scan because there's no secondary index on (key, path).
	if uHasKey {
		for i := range g.Secrets {
			s := &g.Secrets[i]
			if s.KeyName != u.KeyName {
				continue
			}
			for j := range s.FoundIn {
				k, ok := upsertKey(s.FoundIn[j])
				if !ok || k != uKey {
					continue
				}
				if s.ValueFingerprint == newFP {
					// Same path, same value: re-observation. Refresh
					// the FoundIn (line/permissions may change) and
					// bump LastSeen.
					s.FoundIn[j] = u.Found
					s.LastSeen = u.Now
					return UpsertResult{Outcome: OutcomeRefreshed, Secret: s}
				}
				// DRIFT.
				s.ValueHistory = append(s.ValueHistory, ValueHistoryEntry{
					Fingerprint: s.ValueFingerprint,
					SeenAt:      u.Now,
				})
				s.ID = newFP
				s.ValueFingerprint = newFP
				s.ValuePreview = fingerprint.Preview(u.Value)
				s.FoundIn[j] = u.Found
				s.LastSeen = u.Now
				return UpsertResult{Outcome: OutcomeDrifted, Secret: s}
			}
		}
	}

	// Dedup by fingerprint: same (key, value) seen elsewhere → add a
	// FoundIn rather than create a new entry.
	for i := range g.Secrets {
		s := &g.Secrets[i]
		if s.ValueFingerprint != newFP {
			continue
		}
		// If this exact location is already recorded, refresh it.
		if uHasKey {
			for j := range s.FoundIn {
				if k, ok := upsertKey(s.FoundIn[j]); ok && k == uKey {
					s.FoundIn[j] = u.Found
					s.LastSeen = u.Now
					return UpsertResult{Outcome: OutcomeRefreshed, Secret: s}
				}
			}
		}
		s.FoundIn = append(s.FoundIn, u.Found)
		s.LastSeen = u.Now
		return UpsertResult{Outcome: OutcomeRefreshed, Secret: s}
	}

	// New secret.
	g.Secrets = append(g.Secrets, Secret{
		ID:               newFP,
		KeyName:          u.KeyName,
		ValueFingerprint: newFP,
		ValuePreview:     fingerprint.Preview(u.Value),
		FoundIn:          []FoundIn{u.Found},
		Annotation:       Annotation{Tags: []string{}},
		FirstSeen:        u.Now,
		LastSeen:         u.Now,
		ValueHistory:     []ValueHistoryEntry{},
	})
	return UpsertResult{Outcome: OutcomeCreated, Secret: &g.Secrets[len(g.Secrets)-1]}
}

// MarkStale sets Annotation.Stale = true on the Secret with the given
// id. The entry is NOT removed; the value_history and FoundIn list
// stay intact so the audit UI can show "previously seen at X". Returns
// true iff a Secret with that id was found.
func (g *Global) MarkStale(id string) bool {
	for i := range g.Secrets {
		if g.Secrets[i].ID == id {
			g.Secrets[i].Annotation.Stale = true
			return true
		}
	}
	return false
}

// MarkRotated appends a ValueHistoryEntry with the entry's CURRENT
// fingerprint and SeenAt = now. It does NOT mutate FoundIn — rotation
// is a metadata-only signal that the user has rotated the live value
// out-of-band; the next scan that observes the new value will land as
// a drift Upsert. Returns true iff a Secret with that id was found.
func (g *Global) MarkRotated(id string, now time.Time) bool {
	for i := range g.Secrets {
		s := &g.Secrets[i]
		if s.ID != id {
			continue
		}
		s.ValueHistory = append(s.ValueHistory, ValueHistoryEntry{
			Fingerprint: s.ValueFingerprint,
			SeenAt:      now,
		})
		return true
	}
	return false
}

// PruneFoundInPaths removes any FoundIn entries whose Path appears in
// paths. A Secret whose FoundIn list becomes empty as a result is
// removed from g.Secrets entirely; it has no remaining anchor to a
// real source on disk and would otherwise persist as an orphan.
//
// Returns (foundInRemoved, secretsRemoved). Keystore-source FoundIn
// entries (Path == "") are never touched.
func (g *Global) PruneFoundInPaths(paths []string) (foundInRemoved, secretsRemoved int) {
	if len(paths) == 0 || len(g.Secrets) == 0 {
		return 0, 0
	}
	pathSet := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		pathSet[p] = struct{}{}
	}

	kept := make([]Secret, 0, len(g.Secrets))
	for i := range g.Secrets {
		s := g.Secrets[i]
		filtered := s.FoundIn[:0]
		for _, f := range s.FoundIn {
			if f.Path != "" {
				if _, hit := pathSet[f.Path]; hit {
					foundInRemoved++
					continue
				}
			}
			filtered = append(filtered, f)
		}
		s.FoundIn = filtered
		if len(s.FoundIn) == 0 {
			secretsRemoved++
			continue
		}
		kept = append(kept, s)
	}
	g.Secrets = kept
	return foundInRemoved, secretsRemoved
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
