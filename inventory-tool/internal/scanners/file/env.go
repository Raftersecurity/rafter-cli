// Package file implements scanners for plaintext credential files —
// .env, .env.*, .envrc and similar dotfiles that follow the common
// KEY=VALUE shell-export convention.
//
// All readers open files O_RDONLY only. Source files are never mutated,
// renamed, or deleted by anything in this package.
package file

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

// maxLineLen caps the byte length of a single env-file line. .env values
// are typically short tokens; anything past 256 KiB is more likely a
// binary or corrupted file than a real secret.
const maxLineLen = 256 * 1024

// ScanEnvFile parses path as a dotenv-style file and returns one
// FoundSecret per non-comment, non-blank KEY=VALUE line.
//
// On a non-existent path ScanEnvFile returns ([], nil). Other read
// errors surface unchanged. The file is opened O_RDONLY and never
// modified.
func ScanEnvFile(path string) ([]scanners.FoundSecret, error) {
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
		key, val, ok := parseEnvLine(line)
		if !ok {
			continue
		}
		out = append(out, scanners.FoundSecret{
			KeyName: key,
			Value:   val,
			Source: storage.FoundIn{
				SourceType:  storage.SourceEnvFile,
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

// parseEnvLine extracts (key, value) from a single dotenv line. Returns
// ok=false for blanks, comments, malformed lines, or anything that
// isn't a KEY=VALUE pair. Quotes are stripped from the value; an
// unquoted ` #` strips the trailing inline comment.
func parseEnvLine(line string) (key, value string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	// Optional `export ` prefix is shell convention; strip it before
	// hunting for the `=`.
	if strings.HasPrefix(trimmed, "export ") || strings.HasPrefix(trimmed, "export\t") {
		trimmed = strings.TrimSpace(trimmed[len("export"):])
	}

	eq := strings.IndexByte(trimmed, '=')
	if eq <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(trimmed[:eq])
	if !isValidKey(key) {
		return "", "", false
	}
	rawVal := trimmed[eq+1:]

	// Strip leading whitespace before the value but preserve everything
	// inside quotes verbatim. Trailing whitespace on unquoted values is
	// stripped (shell strips it on assignment).
	rawVal = strings.TrimLeft(rawVal, " \t")
	value = stripQuotesOrComment(rawVal)
	return key, value, true
}

// stripQuotesOrComment handles the three value shapes:
//
//   - "double-quoted"  → return contents verbatim
//   - 'single-quoted'  → return contents verbatim, no expansion
//   - bare value       → trim trailing whitespace, then strip ` #` inline
//     comment
//
// If a value opens with a quote but never closes (malformed), the raw
// remainder is returned so the auditor still sees something rather than
// silently dropping the line.
func stripQuotesOrComment(s string) string {
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
	// Unquoted: an inline ` #` comment ends the value. We require a
	// space before the `#` to avoid eating values like
	// `password=p#ss` (legal in shell because there's no space).
	if i := strings.Index(s, " #"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimRight(s, " \t")
}

// isValidKey returns true if k is a plausible env-var name. We accept
// the conservative POSIX rule: starts with letter or underscore, then
// letters / digits / underscores. This rejects junk like `KEY VALUE`
// (where the user forgot the `=`) and shell function declarations.
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
