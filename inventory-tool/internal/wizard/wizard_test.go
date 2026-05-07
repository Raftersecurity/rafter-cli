package wizard

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
)

// withFakeHome replaces $HOME (and clears XDG_CONFIG_HOME) with a temp
// directory for the duration of one test. The wizard probes $HOME to
// detect default roots and common layouts; without this isolation the
// tests would observe whatever the developer's real home looks like.
func withFakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	return home
}

func TestWizard_DefaultRootIsHome(t *testing.T) {
	home := withFakeHome(t)
	doc := storage.Empty()

	// Empty input → wizard accepts all defaults (no extra prompts).
	in := strings.NewReader("\n\n\n\n\n\n")
	var out bytes.Buffer
	if err := FirstRun(in, &out, doc); err != nil {
		t.Fatalf("FirstRun: %v", err)
	}
	if len(doc.ScanConfig.Roots) == 0 {
		t.Fatal("ScanConfig.Roots not populated")
	}
	foundHome := false
	for _, r := range doc.ScanConfig.Roots {
		if r == home {
			foundHome = true
		}
	}
	if !foundHome {
		t.Errorf("expected $HOME (%s) in roots, got %v", home, doc.ScanConfig.Roots)
	}
}

func TestWizard_DetectsCommonLayouts(t *testing.T) {
	home := withFakeHome(t)
	if err := os.MkdirAll(filepath.Join(home, "code"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "git"), 0o755); err != nil {
		t.Fatal(err)
	}

	doc := storage.Empty()
	in := strings.NewReader("\n\n\n\n\n\n")
	var out bytes.Buffer
	if err := FirstRun(in, &out, doc); err != nil {
		t.Fatalf("FirstRun: %v", err)
	}

	// The wizard's prose must mention the detected dirs to the user
	// (so they know what's going to be scanned). Output is for humans;
	// we just check the names appear.
	o := out.String()
	if !strings.Contains(o, "code") {
		t.Errorf("wizard should surface detected ~/code layout; output:\n%s", o)
	}
	if !strings.Contains(o, "git") {
		t.Errorf("wizard should surface detected ~/git layout; output:\n%s", o)
	}
}

func TestWizard_ApplyExcludes(t *testing.T) {
	withFakeHome(t)
	doc := storage.Empty()
	in := strings.NewReader("\n\n\n\n\n\n")
	var out bytes.Buffer
	if err := FirstRun(in, &out, doc); err != nil {
		t.Fatalf("FirstRun: %v", err)
	}

	// Spec excludes that MUST be pre-loaded (Inventory-Tool-Spec.md
	// "Default search roots & excludes"). Not exhaustive — these are
	// the load-bearing performance/safety ones.
	required := []string{
		"**/node_modules/",
		"**/.git/",
		"**/vendor/",
		"**/__pycache__/",
		"**/.cache/",
		"**/.DS_Store",
	}
	have := map[string]bool{}
	for _, e := range doc.ScanConfig.Excludes {
		have[e] = true
	}
	for _, want := range required {
		if !have[want] {
			t.Errorf("missing required exclude %q; got %v", want, doc.ScanConfig.Excludes)
		}
	}
}

func TestWizard_PersistsToScanConfig(t *testing.T) {
	withFakeHome(t)
	doc := storage.Empty()
	if len(doc.ScanConfig.Roots) != 0 || len(doc.ScanConfig.Excludes) != 0 {
		t.Fatal("Empty() ScanConfig should be empty")
	}
	in := strings.NewReader("\n\n\n\n\n\n")
	var out bytes.Buffer
	if err := FirstRun(in, &out, doc); err != nil {
		t.Fatalf("FirstRun: %v", err)
	}
	if len(doc.ScanConfig.Roots) == 0 {
		t.Errorf("FirstRun must populate doc.ScanConfig.Roots")
	}
	if len(doc.ScanConfig.Excludes) == 0 {
		t.Errorf("FirstRun must populate doc.ScanConfig.Excludes")
	}
	// Re-running with already-populated config must be a no-op
	// (FirstRun only fires on first run; idempotency is the contract).
	doc.ScanConfig.Roots = []string{"/explicit"}
	doc.ScanConfig.Excludes = []string{"keepme"}
	in2 := strings.NewReader("\n\n\n\n\n\n")
	var out2 bytes.Buffer
	if err := FirstRun(in2, &out2, doc); err != nil {
		t.Fatalf("FirstRun second call: %v", err)
	}
	if len(doc.ScanConfig.Roots) != 1 || doc.ScanConfig.Roots[0] != "/explicit" {
		t.Errorf("second FirstRun must not overwrite existing Roots; got %v", doc.ScanConfig.Roots)
	}
	if len(doc.ScanConfig.Excludes) != 1 || doc.ScanConfig.Excludes[0] != "keepme" {
		t.Errorf("second FirstRun must not overwrite existing Excludes; got %v", doc.ScanConfig.Excludes)
	}
}
