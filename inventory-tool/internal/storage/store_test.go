package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/fingerprint"
)

func TestEmpty_SchemaPins(t *testing.T) {
	g := Empty()
	if g.Version != 1 {
		t.Errorf("Version = %d, want 1", g.Version)
	}
	if g.SchemaCompat != "kp-v0.9" {
		t.Errorf("SchemaCompat = %q, want kp-v0.9", g.SchemaCompat)
	}
	if g.RevealPolicy != "session" {
		t.Errorf("RevealPolicy = %q, want session", g.RevealPolicy)
	}
	if g.Secrets == nil || g.ScanConfig.Roots == nil || g.ScanConfig.Excludes == nil {
		t.Error("Empty() must initialise slices to non-nil so JSON output has [] not null")
	}
}

func TestEmpty_NoNullsInJSON(t *testing.T) {
	// kp v0.9's reader treats "null" and missing-field differently from "[]".
	// The empty document must never produce nulls for the array fields.
	b, err := json.Marshal(Empty())
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"secrets":null`, `"roots":null`, `"excludes":null`} {
		if strings.Contains(string(b), field) {
			t.Errorf("Empty() emitted %s; want []", field)
		}
	}
}

func TestLoad_MissingFileReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.json")

	g, err := Load(path)
	if err != nil {
		t.Fatalf("Load on missing file: %v (want nil — first-run is non-error)", err)
	}
	if g.Version != 1 || g.SchemaCompat != "kp-v0.9" {
		t.Errorf("missing-file Load did not return Empty(): %+v", g)
	}
}

func TestLoad_MalformedFileErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load must surface JSON parse errors")
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "global.json")

	in := Empty()
	in.ScanConfig.Roots = []string{"/Users/rome"}
	in.ScanConfig.Excludes = []string{"~/Library/", "**/node_modules/"}
	in.Telemetry.Enabled = true
	in.RevealPolicy = "strict"

	now := time.Date(2026, 5, 1, 8, 14, 0, 0, time.UTC)
	tru := true
	in.Secrets = append(in.Secrets, Secret{
		ID:               fingerprint.Compute("ANTHROPIC_API_KEY", "sk-ant-abc123zRfx"),
		KeyName:          "ANTHROPIC_API_KEY",
		ValueFingerprint: fingerprint.Compute("ANTHROPIC_API_KEY", "sk-ant-abc123zRfx"),
		ValuePreview:     fingerprint.Preview("sk-ant-abc123zRfx"),
		FoundIn: []FoundIn{
			{
				SourceType:          SourceEnvFile,
				Path:                "/Users/rome/code/naledi/.env",
				Line:                3,
				Permissions:         "0644",
				InGitRepo:           &tru,
				AppearsInGitHistory: &tru,
			},
			{
				SourceType: SourceKeystore,
				Keystore:   "macos-keychain",
				Service:    "anthropic-cli",
				Account:    "rome",
			},
		},
		Annotation: Annotation{
			SourceURL: "https://console.anthropic.com/settings/keys",
			Owner:     "@rome",
			Notes:     "Personal account.",
			Tags:      []string{"personal", "anthropic"},
		},
		FirstSeen:    now,
		LastSeen:     now.Add(4 * 24 * time.Hour),
		ValueHistory: []ValueHistoryEntry{{Fingerprint: "blake3:9f00", SeenAt: now}},
	})

	if err := Save(path, in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Round-trip via JSON for a structural compare; pointer-bool fields
	// don't compare cleanly with reflect.DeepEqual across goroutines but
	// JSON canonicalisation is what we actually care about persisting.
	wantJSON, _ := json.Marshal(in)
	gotJSON, _ := json.Marshal(out)
	if string(wantJSON) != string(gotJSON) {
		t.Errorf("round-trip mismatch:\nwant: %s\n got: %s", wantJSON, gotJSON)
	}
}

func TestSave_AtomicWriteLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "global.json")

	for i := 0; i < 3; i++ {
		if err := Save(path, Empty()); err != nil {
			t.Fatalf("Save iter %d: %v", i, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temp file %q left behind after successful Save", e.Name())
		}
	}
}

func TestSave_FileMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes don't apply on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "global.json")
	if err := Save(path, Empty()); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	const want = os.FileMode(0o600)
	if got := st.Mode().Perm(); got != want {
		t.Errorf("file mode = %#o, want %#o", got, want)
	}
}

func TestSave_DirMode0700(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes don't apply on Windows")
	}
	root := t.TempDir()
	// Save into a nested path that doesn't exist yet so MkdirAll has to
	// create it with our chosen mode.
	path := filepath.Join(root, "nested", "trove", "global.json")
	if err := Save(path, Empty()); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	const want = os.FileMode(0o700)
	if got := st.Mode().Perm(); got != want {
		t.Errorf("dir mode = %#o, want %#o", got, want)
	}
}

func TestSave_OverwritesAtomically(t *testing.T) {
	// Two distinct documents: the second Save must completely replace
	// the first, with no merged or appended state.
	dir := t.TempDir()
	path := filepath.Join(dir, "global.json")

	first := Empty()
	first.RevealPolicy = "loose"
	if err := Save(path, first); err != nil {
		t.Fatal(err)
	}

	second := Empty()
	second.RevealPolicy = "paranoid"
	if err := Save(path, second); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.RevealPolicy != "paranoid" {
		t.Errorf("RevealPolicy after overwrite = %q, want paranoid", got.RevealPolicy)
	}
}

func TestSave_TerminatingNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "global.json")
	if err := Save(path, Empty()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		t.Error("output must end with a newline (POSIX text-file convention; diff-friendly)")
	}
}

func TestDefaultPath_HonoursXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/custom/xdg")
	got, err := DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join("/custom/xdg", "trove", "global.json")
	if got != want {
		t.Errorf("DefaultPath = %q, want %q", got, want)
	}
}

func TestDefaultPath_FallsBackToHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir available")
	}
	got, err := DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".config", "trove", "global.json")
	if got != want {
		t.Errorf("DefaultPath = %q, want %q", got, want)
	}
}
