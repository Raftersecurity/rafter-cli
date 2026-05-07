// Package shellrc implements the scanner for shell rc files —
// .zshrc, .bashrc, .profile, .zshenv, .bash_profile.
//
// It only emits FoundSecrets for `export KEY=VALUE` lines (commented
// exports skipped, quotes stripped). Aliases, functions, and shell
// logic are ignored. Source files are opened O_RDONLY only.
package shellrc

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/scanners"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
)

const maxLineLen = 256 * 1024

// ScanRC parses a shell rc file at path and emits one FoundSecret per
// uncommented `export KEY=VALUE` line.
//
// We deliberately do NOT execute or expand the shell — single quotes
// stay literal, double quotes have outer markers stripped but no $VAR
// expansion. The audit surface should reflect what's on disk, not what
// a live shell would resolve.
//
// On a missing path: ([], nil).
func ScanRC(path string) ([]scanners.FoundSecret, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	perms := fmt.Sprintf("%04o", st.Mode().Perm())

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), maxLineLen)

	var out []scanners.FoundSecret
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		key, val, ok := parseExport(line)
		if !ok {
			continue
		}
		out = append(out, scanners.FoundSecret{
			KeyName: key,
			Value:   val,
			Source: storage.FoundIn{
				SourceType:  storage.SourceShellRC,
				Path:        path,
				Line:        lineNo,
				Permissions: perms,
			},
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return out, nil
}

func parseExport(line string) (key, value string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	if !strings.HasPrefix(trimmed, "export ") && !strings.HasPrefix(trimmed, "export\t") {
		return "", "", false
	}
	rest := strings.TrimSpace(trimmed[len("export"):])

	eq := strings.IndexByte(rest, '=')
	if eq <= 0 {
		return "", "", false
	}
	key = rest[:eq]
	if !isValidKey(key) {
		return "", "", false
	}
	rawVal := rest[eq+1:]
	value = stripQuotes(rawVal)
	return key, value, true
}

func stripQuotes(s string) string {
	if len(s) == 0 {
		return ""
	}
	switch s[0] {
	case '"':
		if i := strings.IndexByte(s[1:], '"'); i >= 0 {
			return s[1 : 1+i]
		}
		return s[1:]
	case '\'':
		if i := strings.IndexByte(s[1:], '\''); i >= 0 {
			return s[1 : 1+i]
		}
		return s[1:]
	}
	return strings.TrimRight(s, " \t")
}

func isValidKey(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		switch {
		case r == '_':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}
