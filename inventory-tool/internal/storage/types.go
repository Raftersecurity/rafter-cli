// Package storage defines the on-disk schema for trove's global JSON store
// and the Load/Save primitives that read and atomically write it.
//
// The persisted shape is the wire contract: kp v0.9 reads this file natively
// (no migrator), and the schema is committed-to v1 documentation in
// Inventory-Tool-Spec.md. Field renames or removals here are schema-breaking
// and require bumping Version.
package storage

import "time"

// Schema constants. SchemaCompat is the kp version that promises to read
// this file verbatim — bumping the kp consumer requires re-checking that
// promise.
const (
	SchemaVersion       = 1
	SchemaCompat        = "kp-v0.9"
	DefaultRevealPolicy = "session"
)

// Source-type tags for FoundIn.SourceType. Kept as exported constants so
// scanners produce consistent values that the kp reader can switch on.
const (
	SourceEnvFile    = "envfile"
	SourceKeystore   = "keystore"
	SourceShellRC    = "shell-rc"
	SourceSourceCode = "source-code"
)

// Reveal-policy tags for Global.RevealPolicy. Spec § Reveal & auth UX names
// the four modes; only "session" is the v1 default.
const (
	RevealStrict   = "strict"
	RevealSession  = "session"
	RevealLoose    = "loose"
	RevealParanoid = "paranoid"
)

// Global is the entire on-disk document. One per host, at DefaultPath.
type Global struct {
	Version      int        `json:"version"`
	SchemaCompat string     `json:"schema_compat"`
	ScanConfig   ScanConfig `json:"scan_config"`
	Telemetry    Telemetry  `json:"telemetry"`
	RevealPolicy string     `json:"reveal_policy"`
	Secrets      []Secret   `json:"secrets"`
}

// ScanConfig holds the user's configured filesystem scan scope. Roots and
// Excludes are always serialised as arrays (never null) so the kp reader
// doesn't have to handle the absent-vs-empty case.
type ScanConfig struct {
	Roots    []string `json:"roots"`
	Excludes []string `json:"excludes"`
}

type Telemetry struct {
	Enabled bool `json:"enabled"`
}

// Secret is one logical credential, deduped across all sources where it was
// found. ID and ValueFingerprint are both fingerprint.Compute(KeyName, value)
// — the spec defines them as the same string. The full value is never stored
// here; ValuePreview is the only on-disk hint.
type Secret struct {
	ID               string              `json:"id"`
	KeyName          string              `json:"key_name"`
	ValueFingerprint string              `json:"value_fingerprint"`
	ValuePreview     string              `json:"value_preview"`
	FoundIn          []FoundIn           `json:"found_in"`
	Annotation       Annotation          `json:"annotation"`
	FirstSeen        time.Time           `json:"first_seen"`
	LastSeen         time.Time           `json:"last_seen"`
	ValueHistory     []ValueHistoryEntry `json:"value_history"`
}

// FoundIn records one location where a Secret was observed. The shape is
// flat with omitempty fields rather than per-source variants because the kp
// v0.9 reader expects a single object schema; SourceType is the discriminator.
type FoundIn struct {
	SourceType string `json:"source_type"`

	// File-based fields (envfile, shell-rc, source-code).
	// Pointer bools so non-file sources can omit them entirely instead of
	// emitting misleading false values.
	Path                string `json:"path,omitempty"`
	Line                int    `json:"line,omitempty"`
	Permissions         string `json:"permissions,omitempty"`
	InGitRepo           *bool  `json:"in_git_repo,omitempty"`
	InGitignore         *bool  `json:"in_gitignore,omitempty"`
	AppearsInGitHistory *bool  `json:"appears_in_git_history,omitempty"`

	// Keystore-source fields.
	Keystore string `json:"keystore,omitempty"`
	Service  string `json:"service,omitempty"`
	Account  string `json:"account,omitempty"`
}

// Annotation is the user-edited metadata that survives value rotation. Tags
// is always serialised as an array (never null) for kp-reader simplicity.
type Annotation struct {
	SourceURL string   `json:"source_url"`
	Owner     string   `json:"owner"`
	Notes     string   `json:"notes"`
	RotateURL string   `json:"rotate_url"`
	Tags      []string `json:"tags"`
	Stale     bool     `json:"stale"`
}

// ValueHistoryEntry records that a secret with this fingerprint was observed
// at SeenAt. The full value is not stored — only the fingerprint, so the UI
// can display "rotated N times in the last 90 days" without ever persisting
// past values.
type ValueHistoryEntry struct {
	Fingerprint string    `json:"fingerprint"`
	SeenAt      time.Time `json:"seen_at"`
}

// Empty returns a fresh Global pinned to the current schema version, with
// non-nil empty slices so JSON output never produces nulls.
func Empty() *Global {
	return &Global{
		Version:      SchemaVersion,
		SchemaCompat: SchemaCompat,
		ScanConfig:   ScanConfig{Roots: []string{}, Excludes: []string{}},
		Telemetry:    Telemetry{Enabled: false},
		RevealPolicy: DefaultRevealPolicy,
		Secrets:      []Secret{},
	}
}
