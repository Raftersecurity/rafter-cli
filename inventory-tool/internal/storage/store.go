package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	appDir   = "trove"
	fileName = "global.json"

	// 0600: owner read/write only. The file holds key names, value
	// fingerprints, previews, and source paths — sensitive enough that
	// world-readable is wrong even though the underlying secrets aren't
	// stored.
	fileMode fs.FileMode = 0o600

	// 0700: same reasoning for the parent directory.
	dirMode fs.FileMode = 0o700
)

// DefaultPath returns the canonical location of the global store.
//
// It honours $XDG_CONFIG_HOME if set, falling back to ~/.config/trove/global.json
// otherwise. The returned path is not guaranteed to exist; first-run callers
// should pass it to Load (which treats not-exist as empty) and then Save.
func DefaultPath() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, appDir, fileName), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", appDir, fileName), nil
}

// Load reads the global store at path.
//
// If path does not exist, Load returns Empty() and a nil error — first-run
// is a normal condition, not a failure. Any other read or parse error is
// returned unchanged so the caller can surface it.
func Load(path string) (*Global, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Empty(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	g := &Global{}
	if err := json.Unmarshal(b, g); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return g, nil
}

// Save atomically writes g to path with mode 0600, creating the parent
// directory at 0700 if needed.
//
// Atomicity: contents are written to a sibling temp file in the same
// directory (so rename is a same-filesystem operation), fsynced to disk,
// then renamed over path. A crash mid-write leaves the previous file
// intact, never a half-written one.
//
// JSON is indented with two spaces and terminated with a newline so the
// file is hand-editable and diff-friendly.
func Save(path string, g *Global) error {
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return fmt.Errorf("ensure config dir: %w", err)
	}

	body, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal global: %w", err)
	}
	body = append(body, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(fileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmpPath, path, err)
	}
	committed = true
	return nil
}
