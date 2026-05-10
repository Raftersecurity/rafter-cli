package scan

import (
	"os"
	"path/filepath"
	"strings"
)

// expandHome replaces a leading `~` or `~/` with the user's home dir.
// Used at root-canonicalisation time so the user can write `~/code` in
// their config. The exclude-pattern matcher itself lives in
// internal/excludes; both the walker and the watcher import it from
// there so the two see the exact same set of effective excludes.
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
