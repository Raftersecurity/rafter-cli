package scan

import (
	"path/filepath"
	"strings"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/scanners"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/scanners/config"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/scanners/file"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/scanners/shellrc"
)

// scannerFn is the common shape for the per-source scanners in
// internal/scanners/*. The orchestrator only needs the path → []FoundSecret
// mapping; per-scanner setup happens inside each scanner.
type scannerFn func(string) ([]scanners.FoundSecret, error)

// scannerFor maps a discovered file path to the scanner that should
// read it, or returns ok=false when the path is uninteresting. We
// dispatch on (basename, parent-basename) rather than full-path
// patterns because the spec lists every credential file by its
// well-known name; a project-local `.env` and a `~/.npmrc` are the
// same logical source regardless of where they live in the tree.
func scannerFor(path string) (scannerFn, bool) {
	base := filepath.Base(path)
	parent := filepath.Base(filepath.Dir(path))

	// Shell rc files — only the documented set; we don't try to guess
	// at exotic shells like fish or nushell.
	switch base {
	case ".zshrc", ".bashrc", ".profile", ".zshenv", ".bash_profile":
		return shellrc.ScanRC, true
	}

	// Dotenv family. Match `.env`, `.envrc`, and any `.env.*` variant
	// (`.env.local`, `.env.production`, etc.) so per-environment files
	// land in the same scanner.
	if base == ".env" || base == ".envrc" || strings.HasPrefix(base, ".env.") {
		return file.ScanEnvFile, true
	}

	// Structured config files. Each requires the parent directory to
	// match because a stray `config.json` somewhere in a repo is not a
	// docker config and parsing it as one would produce noise.
	switch base {
	case ".npmrc":
		return config.ScanNpmrc, true
	case "credentials":
		if parent == ".aws" {
			return config.ScanAWSCredentials, true
		}
	case "config.json":
		if parent == ".docker" {
			return config.ScanDockerConfig, true
		}
	case "hosts.yml":
		if parent == "gh" {
			return config.ScanGhHosts, true
		}
	case "settings.json":
		if parent == ".claude" {
			return config.ScanClaudeSettings, true
		}
	}
	return nil, false
}
