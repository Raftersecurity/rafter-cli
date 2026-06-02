package scan

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
)

func TestResolveValue_EnvFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("FOO=alpha\nBAR=beta\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveValue(storage.FoundIn{
		SourceType: storage.SourceEnvFile,
		Path:       envPath,
		Line:       2,
	}, "BAR")
	if err != nil {
		t.Fatalf("ResolveValue: %v", err)
	}
	if got != "beta" {
		t.Errorf("got %q, want beta", got)
	}
}

// Two FOO= lines in one file: the FoundIn's Line disambiguates.
func TestResolveValue_DuplicateKeyDisambiguatedByLine(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("FOO=first\nFOO=second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveValue(storage.FoundIn{
		SourceType: storage.SourceEnvFile,
		Path:       envPath,
		Line:       2,
	}, "FOO")
	if err != nil {
		t.Fatalf("ResolveValue: %v", err)
	}
	if got != "second" {
		t.Errorf("got %q, want second", got)
	}
}

func TestResolveValue_KeystoreUnsupported(t *testing.T) {
	_, err := ResolveValue(storage.FoundIn{
		SourceType: storage.SourceKeystore,
		Keystore:   "macos-keychain",
		Service:    "anthropic",
		Account:    "rome",
	}, "anthropic")
	if !errors.Is(err, ErrUnsupportedSource) {
		t.Errorf("err = %v, want ErrUnsupportedSource", err)
	}
}

func TestResolveValue_UnknownSourcePath(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "not-a-recognised-file.txt")
	if err := os.WriteFile(junk, []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ResolveValue(storage.FoundIn{
		SourceType: storage.SourceEnvFile,
		Path:       junk,
	}, "FOO")
	if !errors.Is(err, ErrUnsupportedSource) {
		t.Errorf("err = %v, want ErrUnsupportedSource", err)
	}
}

func TestResolveValue_KeyMissing(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("OTHER=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ResolveValue(storage.FoundIn{
		SourceType: storage.SourceEnvFile,
		Path:       envPath,
		Line:       1,
	}, "FOO")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("err = %v, want ErrSecretNotFound", err)
	}
}

func TestResolveValue_RefusesManualSource(t *testing.T) {
	// A manual entry carries a path the user typed; reveal must never
	// open it — it returns ErrUnsupportedSource regardless of the path.
	_, err := ResolveValue(storage.FoundIn{SourceType: storage.SourceManual, Path: "/etc/passwd"}, "anything")
	if err != ErrUnsupportedSource {
		t.Fatalf("manual source reveal err = %v, want ErrUnsupportedSource", err)
	}
}
