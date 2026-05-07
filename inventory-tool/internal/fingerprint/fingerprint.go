// Package fingerprint computes the BLAKE3-based identifiers and previews
// that the trove storage layer uses to dedup and display secrets without
// ever persisting the underlying values.
//
// Two scanned secrets are treated as the same entry iff they share the same
// (key_name, value) pair. The fingerprint is:
//
//	"blake3:" + hex( BLAKE3( key_name || 0x00 || value ) )
//
// The NUL separator prevents trivial cross-key collisions — without it,
// (key="A", value="BC") and (key="AB", value="C") would hash identically.
package fingerprint

import (
	"encoding/hex"

	"lukechampine.com/blake3"
)

// Prefix tags the hex digest so callers can distinguish hashing schemes if
// the algorithm ever changes. Persisted in the global JSON.
const Prefix = "blake3:"

// Compute returns the canonical fingerprint for (keyName, value).
//
// It is used both as the secret's stable id and as its value_fingerprint —
// the spec defines them as the same string. value_history entries reuse the
// same encoding for past values.
func Compute(keyName, value string) string {
	h := blake3.New(32, nil)
	_, _ = h.Write([]byte(keyName))
	_, _ = h.Write([]byte{0x00})
	_, _ = h.Write([]byte(value))
	return Prefix + hex.EncodeToString(h.Sum(nil))
}

// Preview returns the non-revealing display form of value: the first 8 runes
// plus "..." plus the last 4 runes. Computed on runes so multi-byte UTF-8
// values are never truncated mid-codepoint.
//
// If the value is short enough that the prefix and suffix would overlap (or
// the preview would expose the entire value), Preview returns "..." with no
// characters from the original. The persisted preview must never reveal the
// whole secret.
func Preview(value string) string {
	const prefixLen, suffixLen = 8, 4
	runes := []rune(value)
	if len(runes) <= prefixLen+suffixLen {
		return "..."
	}
	return string(runes[:prefixLen]) + "..." + string(runes[len(runes)-suffixLen:])
}
