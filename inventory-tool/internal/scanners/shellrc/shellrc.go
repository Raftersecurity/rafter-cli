// Package shellrc implements the scanner for shell rc files —
// .zshrc, .bashrc, .profile, .zshenv, .bash_profile.
//
// It only emits FoundSecrets for `export KEY=VALUE` lines (commented
// exports skipped, quotes stripped). Aliases, functions, and shell
// logic are ignored. Source files are opened O_RDONLY only.
package shellrc

import (
	"errors"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/scanners"
)

var errNotImplemented = errors.New("shellrc: scanner not implemented")

// ScanRC parses a shell rc file at path and emits one FoundSecret per
// uncommented `export KEY=VALUE` line. Quoted values have outer quotes
// stripped (single quotes — verbatim, no expansion; double quotes —
// verbatim, no expansion either, since we never run a shell).
//
// On a missing path: ([], nil).
func ScanRC(path string) ([]scanners.FoundSecret, error) {
	return nil, errNotImplemented
}
