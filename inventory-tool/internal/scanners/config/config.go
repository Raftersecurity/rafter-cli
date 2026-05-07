// Package config implements scanners for structured credential-bearing
// config files: AWS shared credentials, npmrc, docker config, gh hosts,
// and Claude Code settings.
//
// All readers open files O_RDONLY. Source files are never mutated,
// renamed, or deleted by anything in this package. Scanners only
// recognise structured fields (INI sections, JSON keys, YAML keys);
// no regex "smell" detection.
package config

import (
	"errors"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/scanners"
)

var errNotImplemented = errors.New("config: scanner not implemented")

// ScanAWSCredentials parses the AWS shared-credentials INI at path
// (typically ~/.aws/credentials). Each [profile] section emits up to
// three secrets — aws_access_key_id, aws_secret_access_key, and (if
// present) aws_session_token. KeyName is namespaced as
// "<profile>.<field>" so multiple profiles dedupe independently.
//
// On a missing path: ([], nil). Other read or parse errors surface.
func ScanAWSCredentials(path string) ([]scanners.FoundSecret, error) {
	return nil, errNotImplemented
}

// ScanNpmrc parses an npmrc file (typically ~/.npmrc) and emits one
// FoundSecret per `_authToken=` line, keyed by the registry segment so
// multiple registries dedupe independently.
//
// On a missing path: ([], nil).
func ScanNpmrc(path string) ([]scanners.FoundSecret, error) {
	return nil, errNotImplemented
}

// ScanDockerConfig parses a Docker config.json (typically
// ~/.docker/config.json). For each `auths.<registry>` entry it emits
// the base64 `auth` blob and the `identitytoken` if present, keyed as
// "<registry>.auth" / "<registry>.identitytoken".
//
// On a missing path: ([], nil).
func ScanDockerConfig(path string) ([]scanners.FoundSecret, error) {
	return nil, errNotImplemented
}

// ScanGhHosts parses gh's hosts.yml (typically ~/.config/gh/hosts.yml)
// and emits one FoundSecret per oauth_token field, keyed as
// "<host>.oauth_token". Refresh tokens, if present, emit similarly.
//
// On a missing path: ([], nil).
func ScanGhHosts(path string) ([]scanners.FoundSecret, error) {
	return nil, errNotImplemented
}

// ScanClaudeSettings parses Claude Code's settings.json (typically
// ~/.claude/settings.json). It emits FoundSecret for any string-valued
// field whose key name matches a common credential-bearing pattern
// (apiKeyHelper, *token*, *apiKey*, *secret*, *password*, *auth*).
//
// On a missing path: ([], nil).
func ScanClaudeSettings(path string) ([]scanners.FoundSecret, error) {
	return nil, errNotImplemented
}
