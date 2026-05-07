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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v3"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/scanners"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
)

// readSourceFile is the shared "open + stat + slurp" used by every
// scanner in this package. Returns (nil, nil) on missing path so
// callers can probe optional config files without per-scanner
// errors.Is checks.
func readSourceFile(path string) (body []byte, perms string, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, "", fmt.Errorf("stat %s: %w", path, err)
	}
	body, err = io.ReadAll(f)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", path, err)
	}
	return body, fmt.Sprintf("%04o", st.Mode().Perm()), nil
}

// awsCredFields are the credential-bearing keys we recognise inside an
// AWS [profile] section. Other keys (region, output) are ignored.
var awsCredFields = []string{
	"aws_access_key_id",
	"aws_secret_access_key",
	"aws_session_token",
}

// ScanAWSCredentials parses the AWS shared-credentials INI at path.
// Each [profile] section emits up to three secrets — aws_access_key_id,
// aws_secret_access_key, and (if present) aws_session_token. KeyName
// is namespaced as "<profile>.<field>" so multiple profiles dedupe
// independently.
func ScanAWSCredentials(path string) ([]scanners.FoundSecret, error) {
	body, perms, err := readSourceFile(path)
	if err != nil || body == nil {
		return nil, err
	}
	cfg, err := ini.LoadSources(ini.LoadOptions{IgnoreInlineComment: false}, body)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	var out []scanners.FoundSecret
	for _, sec := range cfg.Sections() {
		name := sec.Name()
		if name == ini.DefaultSection {
			// AWS files conventionally start with `[default]` — but
			// go-ini also creates an implicit DEFAULT section that's
			// usually empty. Skip when no keys.
			if len(sec.Keys()) == 0 {
				continue
			}
			name = "DEFAULT"
		}
		// "[profile work]" is normalised to "work". Plain "[default]"
		// stays "default".
		profile := strings.TrimSpace(strings.TrimPrefix(name, "profile "))
		for _, field := range awsCredFields {
			if !sec.HasKey(field) {
				continue
			}
			val := sec.Key(field).String()
			if val == "" {
				continue
			}
			out = append(out, scanners.FoundSecret{
				KeyName: profile + "." + field,
				Value:   val,
				Source: storage.FoundIn{
					SourceType:  storage.SourceEnvFile,
					Path:        path,
					Permissions: perms,
				},
			})
		}
	}
	return out, nil
}

// ScanNpmrc parses an npmrc file (typically ~/.npmrc) and emits one
// FoundSecret per `<registry>:_authToken=...` line. We use a hand
// parser rather than a full INI loader because npmrc keys frequently
// contain `:` and `/` characters that go-ini treats specially.
func ScanNpmrc(path string) ([]scanners.FoundSecret, error) {
	body, perms, err := readSourceFile(path)
	if err != nil || body == nil {
		return nil, err
	}

	var out []scanners.FoundSecret
	for i, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		eq := strings.IndexByte(trimmed, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:eq])
		val := strings.TrimSpace(trimmed[eq+1:])
		if !isCredentialBearingNpmrcKey(key) || val == "" {
			continue
		}
		out = append(out, scanners.FoundSecret{
			KeyName: key,
			Value:   val,
			Source: storage.FoundIn{
				SourceType:  storage.SourceEnvFile,
				Path:        path,
				Line:        i + 1,
				Permissions: perms,
			},
		})
	}
	return out, nil
}

// isCredentialBearingNpmrcKey returns true for npmrc keys we treat as
// secrets. The audit set covers the documented credential keys
// (_authToken, _auth, _password) — both registry-scoped
// (`//registry/...`) and global. Public, non-credential settings
// (email, registry, prefix, always-auth) are excluded.
func isCredentialBearingNpmrcKey(key string) bool {
	low := strings.ToLower(key)
	if low == "always-auth" {
		return false
	}
	return strings.Contains(low, "_authtoken") ||
		strings.Contains(low, ":_auth") ||
		strings.Contains(low, "_password")
}

// dockerConfig models the subset of ~/.docker/config.json we read.
// Other top-level fields (credsStore, credHelpers, currentContext)
// are intentionally ignored — they're pointers to credentials, not
// credentials themselves.
type dockerConfig struct {
	Auths map[string]dockerAuth `json:"auths"`
}
type dockerAuth struct {
	Auth          string `json:"auth"`
	IdentityToken string `json:"identitytoken"`
}

// ScanDockerConfig parses a Docker config.json. For each
// auths.<registry> entry it emits the base64 `auth` blob and the
// `identitytoken` if present.
func ScanDockerConfig(path string) ([]scanners.FoundSecret, error) {
	body, perms, err := readSourceFile(path)
	if err != nil || body == nil {
		return nil, err
	}
	var d dockerConfig
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	var out []scanners.FoundSecret
	for registry, a := range d.Auths {
		if a.Auth != "" {
			out = append(out, scanners.FoundSecret{
				KeyName: registry + ".auth",
				Value:   a.Auth,
				Source: storage.FoundIn{
					SourceType:  storage.SourceEnvFile,
					Path:        path,
					Permissions: perms,
				},
			})
		}
		if a.IdentityToken != "" {
			out = append(out, scanners.FoundSecret{
				KeyName: registry + ".identitytoken",
				Value:   a.IdentityToken,
				Source: storage.FoundIn{
					SourceType:  storage.SourceEnvFile,
					Path:        path,
					Permissions: perms,
				},
			})
		}
	}
	return out, nil
}

// ghHostsTokenFields lists the fields in gh hosts.yml we treat as
// credentials. `user` and `git_protocol` are metadata and are ignored.
var ghHostsTokenFields = []string{
	"oauth_token",
	"oauth_refresh_token",
}

// ScanGhHosts parses gh's hosts.yml.
func ScanGhHosts(path string) ([]scanners.FoundSecret, error) {
	body, perms, err := readSourceFile(path)
	if err != nil || body == nil {
		return nil, err
	}
	// Top-level shape is map[host]map[field]value; we use a generic
	// decode rather than a typed struct because gh occasionally adds
	// fields we don't want to model.
	root := map[string]map[string]string{}
	if err := yaml.Unmarshal(body, &root); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	var out []scanners.FoundSecret
	for host, fields := range root {
		for _, f := range ghHostsTokenFields {
			val, ok := fields[f]
			if !ok || val == "" {
				continue
			}
			out = append(out, scanners.FoundSecret{
				KeyName: host + "." + f,
				Value:   val,
				Source: storage.FoundIn{
					SourceType:  storage.SourceEnvFile,
					Path:        path,
					Permissions: perms,
				},
			})
		}
	}
	return out, nil
}

// ScanClaudeSettings walks ~/.claude/settings.json (or any equivalent
// JSON document) and emits a FoundSecret for each string-valued field
// whose key name matches a credential-bearing pattern. The walk is
// recursive so nested env blocks are covered.
func ScanClaudeSettings(path string) ([]scanners.FoundSecret, error) {
	body, perms, err := readSourceFile(path)
	if err != nil || body == nil {
		return nil, err
	}
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	src := storage.FoundIn{
		SourceType:  storage.SourceEnvFile,
		Path:        path,
		Permissions: perms,
	}
	var out []scanners.FoundSecret
	walkClaude(&out, "", root, src)
	return out, nil
}

func walkClaude(out *[]scanners.FoundSecret, prefix string, v any, src storage.FoundIn) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			path := k
			if prefix != "" {
				path = prefix + "." + k
			}
			if s, ok := child.(string); ok {
				if isCredentialKey(k) && s != "" {
					*out = append(*out, scanners.FoundSecret{
						KeyName: path,
						Value:   s,
						Source:  src,
					})
				}
				continue
			}
			walkClaude(out, path, child, src)
		}
	case []any:
		// We don't index into arrays — credentials at array positions
		// would have no stable key name to dedup on across scans.
	}
}

// isCredentialKey returns true if the JSON field name is plausibly
// credential-bearing. We match common substrings rather than a strict
// allow-list because Claude settings + plugin schemas evolve.
func isCredentialKey(k string) bool {
	low := strings.ToLower(k)
	for _, needle := range []string{
		"apikey", "api_key",
		"token",
		"secret",
		"password",
		"credential",
		"oauth",
	} {
		if strings.Contains(low, needle) {
			return true
		}
	}
	// Special-case helper hooks that resolve to a credential at runtime.
	if low == "apikeyhelper" {
		return true
	}
	return false
}
