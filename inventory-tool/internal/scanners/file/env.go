// Package file implements scanners for plaintext credential files —
// .env, .env.*, .envrc and similar dotfiles that follow the common
// KEY=VALUE shell-export convention.
//
// All readers open files O_RDONLY only. Source files are never mutated,
// renamed, or deleted by anything in this package.
package file

import "github.com/Raftersecurity/rafter-cli/inventory-tool/internal/scanners"

// ScanEnvFile parses path as a dotenv-style file and returns one
// FoundSecret per non-comment, non-blank KEY=VALUE line.
//
// Format support:
//   - KEY=value
//   - KEY="value"  (double-quoted; outer quotes stripped, contents verbatim)
//   - KEY='value'  (single-quoted; outer quotes stripped, no var expansion)
//   - export KEY=value  (export prefix stripped)
//   - # KEY=value  (skipped)
//   - blank lines (skipped)
//
// Inline comments (text after an unquoted ` #`) are stripped from the
// value. Quoted values keep `#` verbatim.
//
// On a non-existent path ScanEnvFile returns ([], nil) — first-run callers
// can probe paths without error handling. Other read errors are surfaced.
func ScanEnvFile(path string) ([]scanners.FoundSecret, error) {
	return nil, errNotImplemented
}
