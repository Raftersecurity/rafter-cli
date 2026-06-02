package scan

import (
	"errors"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
)

// ErrUnsupportedSource is returned by ResolveValue when the FoundIn
// describes a source that has no implemented file-read path: keystore
// entries (need OS auth), source-code entries (need betterleaks), or
// any future source whose path is empty.
var ErrUnsupportedSource = errors.New("scan: source not supported for reveal")

// ErrSecretNotFound is returned when the scanner re-ran cleanly but
// the requested (KeyName, Line) pair is no longer present at the
// path. This is the drift-not-yet-rescanned case: the file changed
// after the last rescan, the UI is showing stale state, and the live
// reveal can't find the value to return.
var ErrSecretNotFound = errors.New("scan: secret not found at source")

// ResolveValue re-reads the file at found.Path with the matching
// scanner and returns the raw value of the entry whose KeyName equals
// keyName. If found.Line > 0 it must also match — this disambiguates
// duplicate keys (e.g. an env file with two FOO= lines) so a reveal
// always returns the value the UI was pointed at.
//
// ResolveValue never writes to disk and never returns the value
// preview — it returns the actual on-disk value, which the server
// streams back to the (already-authenticated) client.
//
// For sources that don't have a Path (keystore) or whose scanner
// isn't recognised, ResolveValue returns ErrUnsupportedSource. For a
// path that the scanner re-reads cleanly but where no matching entry
// exists, it returns ErrSecretNotFound.
func ResolveValue(found storage.FoundIn, keyName string) (string, error) {
	// Manual entries are user-typed metadata, not a scanned value —
	// never open the path the user wrote, just refuse the reveal.
	if found.SourceType == storage.SourceManual {
		return "", ErrUnsupportedSource
	}
	if found.Path == "" {
		return "", ErrUnsupportedSource
	}
	fn, ok := scannerFor(found.Path)
	if !ok {
		return "", ErrUnsupportedSource
	}
	secrets, err := fn(found.Path)
	if err != nil {
		return "", err
	}
	for _, s := range secrets {
		if s.KeyName != keyName {
			continue
		}
		// When the FoundIn carries a Line (env files, shell rc, npmrc),
		// require it to match so duplicate keys don't collide. Other
		// scanners (AWS credentials, docker, gh, claude) leave Line=0;
		// those KeyNames are already namespaced (e.g. "default.aws_access_key_id")
		// and don't repeat within a file, so KeyName-only match is safe.
		if found.Line != 0 && s.Source.Line != 0 && s.Source.Line != found.Line {
			continue
		}
		return s.Value, nil
	}
	return "", ErrSecretNotFound
}
