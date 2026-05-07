// Package scanners defines the common shape returned by every per-source
// scanner (file, config, shellrc, keystore). A scanner reads a source and
// returns a slice of FoundSecret without ever mutating the source — the
// caller (storage.Upsert) is responsible for persistence and dedup.
package scanners

import "github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"

// FoundSecret is one (key, value) pair observed in a scanned source plus
// the FoundIn metadata describing where it was seen. Scanners emit these
// to a caller; they never persist directly.
//
// The full Value is carried here so the caller can compute the BLAKE3
// fingerprint and value preview. It must NEVER be written to disk by any
// scanner.
type FoundSecret struct {
	KeyName string
	Value   string
	Source  storage.FoundIn
}
