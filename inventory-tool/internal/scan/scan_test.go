package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
)

// snapshotTree returns a deterministic sha256 manifest of every regular
// file under root: lines of "<rel>\t<sha256>" sorted by rel. Used to
// prove a scan made zero mutations to the source tree.
func snapshotTree(t *testing.T, root string) string {
	t.Helper()
	var lines []string
	if err := filepath.Walk(root, func(p string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		lines = append(lines, rel+"\t"+hex.EncodeToString(sum[:]))
		return nil
	}); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func runScan(t *testing.T, doc *storage.Global, roots []string, excludes []string) *Result {
	t.Helper()
	r, err := Run(context.Background(), doc, storage.ScanConfig{Roots: roots, Excludes: excludes})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return r
}

// hasSecretWithKeyAtPath returns true if doc has a Secret with key_name
// that includes a FoundIn at path. KeyName matching is exact.
func hasSecretWithKeyAtPath(doc *storage.Global, key, path string) bool {
	for _, s := range doc.Secrets {
		if s.KeyName != key {
			continue
		}
		for _, f := range s.FoundIn {
			if f.Path == path {
				return true
			}
		}
	}
	return false
}

func TestWalk_HonorsRoots(t *testing.T) {
	tmp := t.TempDir()
	inside := filepath.Join(tmp, "inside")
	outside := filepath.Join(tmp, "outside")
	writeFile(t, filepath.Join(inside, ".env"), "INSIDE_KEY=in_value\n")
	writeFile(t, filepath.Join(outside, ".env"), "OUTSIDE_KEY=out_value\n")

	doc := storage.Empty()
	runScan(t, doc, []string{inside}, nil)

	if !hasSecretWithKeyAtPath(doc, "INSIDE_KEY", filepath.Join(inside, ".env")) {
		t.Errorf("expected INSIDE_KEY found at %s", filepath.Join(inside, ".env"))
	}
	for _, s := range doc.Secrets {
		if s.KeyName == "OUTSIDE_KEY" {
			t.Errorf("walk leaked outside configured root: found %q", s.KeyName)
		}
	}
}

func TestWalk_HonorsExcludes(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "src", ".env"), "SRC_KEY=v\n")
	writeFile(t, filepath.Join(tmp, "node_modules", "pkg", ".env"), "NM_KEY=v\n")
	writeFile(t, filepath.Join(tmp, "deep", "node_modules", ".env"), "DEEP_NM_KEY=v\n")

	doc := storage.Empty()
	runScan(t, doc, []string{tmp}, []string{"**/node_modules/"})

	if !hasSecretWithKeyAtPath(doc, "SRC_KEY", filepath.Join(tmp, "src", ".env")) {
		t.Errorf("expected SRC_KEY scanned (not under excludes)")
	}
	for _, s := range doc.Secrets {
		if s.KeyName == "NM_KEY" || s.KeyName == "DEEP_NM_KEY" {
			t.Errorf("excluded path leaked: %q", s.KeyName)
		}
	}
}

func TestWalk_SymlinkBoundary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks unreliable on Windows")
	}
	tmp := t.TempDir()
	root := filepath.Join(tmp, "root")
	external := filepath.Join(tmp, "external")
	writeFile(t, filepath.Join(root, "real", ".env"), "INNER_KEY=v\n")
	writeFile(t, filepath.Join(external, "secret", ".env"), "EXTERNAL_KEY=v\n")

	// Symlink WITHIN root → other dir within root: should be followed.
	innerLink := filepath.Join(root, "innerlink")
	if err := os.Symlink(filepath.Join(root, "real"), innerLink); err != nil {
		t.Fatalf("symlink innerlink: %v", err)
	}
	// Symlink WITHIN root → dir OUTSIDE root: must NOT be followed.
	outerLink := filepath.Join(root, "outerlink")
	if err := os.Symlink(external, outerLink); err != nil {
		t.Fatalf("symlink outerlink: %v", err)
	}

	doc := storage.Empty()
	runScan(t, doc, []string{root}, nil)

	if !hasSecretWithKeyAtPath(doc, "INNER_KEY", filepath.Join(root, "real", ".env")) {
		t.Errorf("symlinks within root should be followed: missing INNER_KEY")
	}
	for _, s := range doc.Secrets {
		if s.KeyName == "EXTERNAL_KEY" {
			t.Errorf("symlink leaving root must NOT be followed; found %q", s.KeyName)
		}
	}
}

func TestWalk_SkipsCycles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks unreliable on Windows")
	}
	tmp := t.TempDir()
	root := filepath.Join(tmp, "root")
	if err := os.MkdirAll(filepath.Join(root, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "a", ".env"), "ONLY_KEY=v\n")
	// a/loop -> root/a (cycle through ancestor)
	if err := os.Symlink(filepath.Join(root, "a"), filepath.Join(root, "a", "loop")); err != nil {
		t.Fatalf("cycle symlink: %v", err)
	}

	doc := storage.Empty()
	done := make(chan *Result, 1)
	go func() {
		r, _ := Run(context.Background(), doc, storage.ScanConfig{Roots: []string{root}})
		done <- r
	}()

	select {
	case <-done:
		// good — finished without infinite loop
	case <-time.After(5 * time.Second):
		t.Fatal("scan did not terminate; cycle detection broken")
	}
}

func TestScan_CallsCorrectScannerForType(t *testing.T) {
	tmp := t.TempDir()

	// .env → file scanner
	writeFile(t, filepath.Join(tmp, "proj", ".env"), "ENV_KEY=ev\n")
	// .npmrc → config scanner (ScanNpmrc emits keys verbatim, e.g. "//registry.npmjs.org/:_authToken")
	writeFile(t, filepath.Join(tmp, ".npmrc"),
		"//registry.npmjs.org/:_authToken=npm_token_value\n")

	doc := storage.Empty()
	runScan(t, doc, []string{tmp}, nil)

	if !hasSecretWithKeyAtPath(doc, "ENV_KEY", filepath.Join(tmp, "proj", ".env")) {
		t.Errorf(".env should be routed to file scanner")
	}
	if !hasSecretWithKeyAtPath(doc, "//registry.npmjs.org/:_authToken", filepath.Join(tmp, ".npmrc")) {
		t.Errorf(".npmrc should be routed to config scanner")
	}
}

func TestScan_DedupsAcrossSources(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "a", ".env"), "SHARED=samevalue\n")
	writeFile(t, filepath.Join(tmp, "b", ".env"), "SHARED=samevalue\n")

	doc := storage.Empty()
	runScan(t, doc, []string{tmp}, nil)

	var sharedEntries []storage.Secret
	for _, s := range doc.Secrets {
		if s.KeyName == "SHARED" {
			sharedEntries = append(sharedEntries, s)
		}
	}
	if len(sharedEntries) != 1 {
		t.Fatalf("dedup failed: got %d entries for SHARED, want 1", len(sharedEntries))
	}
	if len(sharedEntries[0].FoundIn) != 2 {
		t.Errorf("FoundIn count = %d, want 2 (one per source)", len(sharedEntries[0].FoundIn))
	}
}

func TestScan_NeverWritesAnyFile(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, ".env"), "K=v\n")
	writeFile(t, filepath.Join(tmp, "sub", ".env.local"), "K2=v2\n")
	writeFile(t, filepath.Join(tmp, ".npmrc"), "//x/:_authToken=zzz\n")
	writeFile(t, filepath.Join(tmp, "innocent.txt"), "not a secret\n")

	before := snapshotTree(t, tmp)

	doc := storage.Empty()
	runScan(t, doc, []string{tmp}, nil)

	after := snapshotTree(t, tmp)
	if before != after {
		t.Errorf("scan mutated source tree.\nBEFORE:\n%s\nAFTER:\n%s", before, after)
	}
}

func TestScan_PruneFoundInForFilteredPaths(t *testing.T) {
	// rf-sq72: pre-populate the store with a Secret that has FoundIn at both
	// a real .env and a .env.example. After scan, only the real .env FoundIn
	// survives — the template-env entry is reconciled away.
	tmp := t.TempDir()
	realEnv := filepath.Join(tmp, ".env")
	example := filepath.Join(tmp, ".env.example")
	writeFile(t, realEnv, "API_KEY=real-secret-value\n")
	writeFile(t, example, "API_KEY=YOUR_API_KEY_HERE\n")

	doc := storage.Empty()
	now := time.Now().UTC()
	// Stage S so it has both FoundIn entries upfront. The fingerprint is
	// computed against the real value so the rescan refreshes the .env entry
	// rather than creating a new secret.
	doc.Upsert(storage.Upsertable{
		KeyName: "API_KEY",
		Value:   "real-secret-value",
		Found: storage.FoundIn{
			SourceType: storage.SourceEnvFile,
			Path:       realEnv,
			Line:       1,
		},
		Now: now,
	})
	doc.Upsert(storage.Upsertable{
		KeyName: "API_KEY",
		Value:   "real-secret-value",
		Found: storage.FoundIn{
			SourceType: storage.SourceEnvFile,
			Path:       example,
			Line:       1,
		},
		Now: now,
	})
	if len(doc.Secrets) != 1 || len(doc.Secrets[0].FoundIn) != 2 {
		t.Fatalf("setup: want 1 secret with 2 FoundIn, got %+v", doc.Secrets)
	}

	r := runScan(t, doc, []string{tmp}, nil)

	if len(doc.Secrets) != 1 {
		t.Fatalf("after scan: len(Secrets) = %d, want 1", len(doc.Secrets))
	}
	s := doc.Secrets[0]
	if len(s.FoundIn) != 1 {
		t.Fatalf("FoundIn = %+v, want only the real .env entry", s.FoundIn)
	}
	if s.FoundIn[0].Path != realEnv {
		t.Errorf("FoundIn[0].Path = %q, want %q", s.FoundIn[0].Path, realEnv)
	}
	if r.FoundInPruned != 1 {
		t.Errorf("Result.FoundInPruned = %d, want 1", r.FoundInPruned)
	}
	if r.SecretsRemoved != 0 {
		t.Errorf("Result.SecretsRemoved = %d, want 0 (real .env still there)", r.SecretsRemoved)
	}
}

func TestScan_RemoveSecretIfAllFoundInFiltered(t *testing.T) {
	// rf-sq72: if a Secret's only FoundIn was a template env file, the
	// reconciliation pass removes the FoundIn AND the now-orphan Secret.
	tmp := t.TempDir()
	example := filepath.Join(tmp, ".env.example")
	writeFile(t, example, "API_KEY=YOUR_API_KEY_HERE\n")

	doc := storage.Empty()
	doc.Upsert(storage.Upsertable{
		KeyName: "API_KEY",
		Value:   "stale-recorded-value",
		Found: storage.FoundIn{
			SourceType: storage.SourceEnvFile,
			Path:       example,
			Line:       1,
		},
		Now: time.Now().UTC(),
	})
	if len(doc.Secrets) != 1 {
		t.Fatalf("setup: len(Secrets) = %d, want 1", len(doc.Secrets))
	}

	r := runScan(t, doc, []string{tmp}, nil)

	if len(doc.Secrets) != 0 {
		t.Errorf("after scan: len(Secrets) = %d, want 0 (orphan secret removed)", len(doc.Secrets))
	}
	if r.SecretsRemoved != 1 {
		t.Errorf("Result.SecretsRemoved = %d, want 1", r.SecretsRemoved)
	}
	if r.FoundInPruned != 1 {
		t.Errorf("Result.FoundInPruned = %d, want 1", r.FoundInPruned)
	}
}

func TestScan_FirstSeenLastSeenCorrect(t *testing.T) {
	tmp := t.TempDir()
	envPath := filepath.Join(tmp, ".env")
	writeFile(t, envPath, "AGED=v\n")

	doc := storage.Empty()
	r1 := runScan(t, doc, []string{tmp}, nil)
	if r1.SecretsFound == 0 {
		t.Fatal("first scan found nothing")
	}
	if len(doc.Secrets) != 1 {
		t.Fatalf("want 1 secret, got %d", len(doc.Secrets))
	}
	first := doc.Secrets[0].FirstSeen
	lastA := doc.Secrets[0].LastSeen
	if first.IsZero() {
		t.Errorf("FirstSeen unset after first scan")
	}
	if !lastA.Equal(first) {
		t.Errorf("first scan: LastSeen %v != FirstSeen %v", lastA, first)
	}

	// Second scan: FirstSeen must be unchanged, LastSeen >= first.
	time.Sleep(2 * time.Millisecond)
	runScan(t, doc, []string{tmp}, nil)
	if !doc.Secrets[0].FirstSeen.Equal(first) {
		t.Errorf("FirstSeen changed on rescan: %v -> %v", first, doc.Secrets[0].FirstSeen)
	}
	if doc.Secrets[0].LastSeen.Before(lastA) {
		t.Errorf("LastSeen regressed: %v -> %v", lastA, doc.Secrets[0].LastSeen)
	}
}
