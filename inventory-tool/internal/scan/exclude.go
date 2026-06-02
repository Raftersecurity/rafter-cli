package scan

import (
	"os"
	"path/filepath"
	"strings"
)

// excludeMatcher is one compiled exclude rule. The spec's exclude
// language is small but heterogeneous (`~/Library/`, `**/node_modules/`,
// `**/.DS_Store`); rather than compile a single regex we classify each
// pattern into one of three shapes — anchored absolute prefix,
// "anywhere" basename match, or simple basename — and let the matcher
// dispatch on the cheapest test.
type excludeMatcher struct {
	raw      string
	abs      string // anchored absolute path prefix (~/X/ or /X/)
	base     string // basename pattern (filepath.Match semantics)
	isDir    bool   // pattern ended with `/` — only matches directories
	starStar bool   // pattern began with `**/` — match base anywhere in tree
}

// compileExcludes parses each user-supplied pattern into an
// excludeMatcher. Empty / blank patterns are dropped silently because
// the wizard and config UIs both routinely produce them when a user
// clears a row.
func compileExcludes(patterns []string) []excludeMatcher {
	out := make([]excludeMatcher, 0, len(patterns))
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		em := excludeMatcher{raw: p}
		if strings.HasSuffix(p, "/") {
			em.isDir = true
			p = strings.TrimSuffix(p, "/")
		}
		switch {
		case strings.HasPrefix(p, "**/"):
			em.starStar = true
			em.base = strings.TrimPrefix(p, "**/")
		case strings.HasPrefix(p, "~/"):
			if home, err := os.UserHomeDir(); err == nil {
				em.abs = filepath.Join(home, strings.TrimPrefix(p, "~/"))
			} else {
				em.base = p
			}
		case strings.HasPrefix(p, "/"):
			em.abs = p
		default:
			em.base = p
		}
		out = append(out, em)
	}
	return out
}

// Excluder is the exported, reusable form of a compiled exclude set so
// other packages (notably internal/watch) can prune the same
// directories the scanner skips — without re-implementing the spec's
// `**/X/` / `~/X/` / basename pattern language. Zero value is unusable;
// build one with NewExcluder.
type Excluder struct {
	matchers []excludeMatcher
}

// NewExcluder compiles the spec exclude patterns into a reusable
// matcher. Returns nil for an empty pattern set so callers can cheaply
// skip the check with a nil guard.
func NewExcluder(patterns []string) *Excluder {
	if len(patterns) == 0 {
		return nil
	}
	return &Excluder{matchers: compileExcludes(patterns)}
}

// MatchDir reports whether a directory path is excluded. It evaluates
// every rule as if the path is a directory, which is exactly what a
// directory watcher needs.
func (e *Excluder) MatchDir(path string) bool {
	if e == nil {
		return false
	}
	return matchExcluded(path, true, e.matchers)
}

// matchExcluded reports whether path is matched by any compiled rule.
// dir-only rules (`**/node_modules/`) only fire on directories;
// file-only rules (`**/.DS_Store`) only on files. Absolute-anchored
// rules match the path itself or any descendant.
func matchExcluded(path string, isDir bool, excludes []excludeMatcher) bool {
	if len(excludes) == 0 {
		return false
	}
	base := filepath.Base(path)
	sep := string(filepath.Separator)
	for _, em := range excludes {
		if em.isDir && !isDir {
			continue
		}
		if em.abs != "" {
			if path == em.abs || strings.HasPrefix(path, em.abs+sep) {
				return true
			}
			continue
		}
		if em.base == "" {
			continue
		}
		if matched, _ := filepath.Match(em.base, base); matched {
			return true
		}
	}
	return false
}

// expandHome replaces a leading `~` or `~/` with the user's home dir.
// Used at root-canonicalisation time so the user can write `~/code` in
// their config.
func expandHome(p string) string {
	if p == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
		return p
	}
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~/"))
		}
	}
	return p
}
