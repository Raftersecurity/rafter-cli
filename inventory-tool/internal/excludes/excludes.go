// Package excludes implements trove's user-configured exclude-pattern
// language. The orchestrator uses it to skip directories during the
// walk; the watcher uses the same matcher to skip registering inotify
// watches under excluded subtrees, so a noisy node_modules / .git / etc.
// can't drown the event channel.
//
// The pattern language is intentionally small but covers the cases
// users actually write into trove's config: an absolute or `~`-prefixed
// path, a `**/`-prefixed basename ("anywhere in tree"), or a bare
// basename. A trailing `/` restricts the rule to directories.
//
// Examples:
//
//	~/Library/                  → absolute, dir-only
//	**/node_modules/            → "anywhere", dir-only
//	**/.DS_Store                → "anywhere", file-or-dir
//	.git                        → bare basename
package excludes

import (
	"os"
	"path/filepath"
	"strings"
)

// Matcher is one compiled exclude rule. The zero value matches nothing.
type Matcher struct {
	raw      string
	abs      string // anchored absolute path prefix (~/X/ or /X/)
	base     string // basename pattern (filepath.Match semantics)
	isDir    bool   // pattern ended with `/` — only matches directories
	starStar bool   // pattern began with `**/` — match base anywhere in tree
}

// Compile parses each user-supplied pattern into a Matcher. Empty /
// blank patterns are dropped silently because the wizard and config
// UIs both routinely produce them when a user clears a row.
func Compile(patterns []string) []Matcher {
	out := make([]Matcher, 0, len(patterns))
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		em := Matcher{raw: p}
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

// Match reports whether path is matched by any compiled rule.
// dir-only rules (`**/node_modules/`) only fire on directories;
// file-only rules (`**/.DS_Store`) only on files. Absolute-anchored
// rules match the path itself or any descendant.
func Match(path string, isDir bool, ms []Matcher) bool {
	if len(ms) == 0 {
		return false
	}
	base := filepath.Base(path)
	sep := string(filepath.Separator)
	for _, em := range ms {
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

// MatchDir is a convenience for "this is a directory, do any rules
// fire?" The watcher uses it to decide whether to descend into a
// subtree before adding inotify watches under it.
func MatchDir(path string, ms []Matcher) bool {
	return Match(path, true, ms)
}
