package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/fingerprint"
)

func at(year int, month time.Month, day int) time.Time {
	return time.Date(year, month, day, 12, 0, 0, 0, time.UTC)
}

func mkFound(path string, line int) FoundIn {
	return FoundIn{
		SourceType:  SourceEnvFile,
		Path:        path,
		Line:        line,
		Permissions: "0644",
	}
}

func TestUpsert_NewSecret(t *testing.T) {
	g := Empty()
	now := at(2026, 5, 1)
	g.Upsert(Upsertable{
		KeyName: "FOO",
		Value:   "bar-secret-value",
		Found:   mkFound("/p/.env", 2),
		Now:     now,
	})

	if len(g.Secrets) != 1 {
		t.Fatalf("len(Secrets) = %d, want 1", len(g.Secrets))
	}
	s := g.Secrets[0]
	if s.KeyName != "FOO" {
		t.Errorf("KeyName = %q, want FOO", s.KeyName)
	}
	wantFP := fingerprint.Compute("FOO", "bar-secret-value")
	if s.ID != wantFP {
		t.Errorf("ID = %q, want %q", s.ID, wantFP)
	}
	if s.ValueFingerprint != wantFP {
		t.Errorf("ValueFingerprint = %q, want %q", s.ValueFingerprint, wantFP)
	}
	if s.ValuePreview == "" {
		t.Error("ValuePreview must be non-empty")
	}
	if !s.FirstSeen.Equal(now) {
		t.Errorf("FirstSeen = %v, want %v", s.FirstSeen, now)
	}
	if !s.LastSeen.Equal(now) {
		t.Errorf("LastSeen = %v, want %v", s.LastSeen, now)
	}
	if len(s.FoundIn) != 1 || s.FoundIn[0].Path != "/p/.env" {
		t.Errorf("FoundIn = %+v, want single /p/.env", s.FoundIn)
	}
}

func TestUpsert_DedupSameSecretMultipleSources(t *testing.T) {
	g := Empty()
	g.Upsert(Upsertable{KeyName: "K", Value: "v", Found: mkFound("/a/.env", 1), Now: at(2026, 5, 1)})
	g.Upsert(Upsertable{KeyName: "K", Value: "v", Found: mkFound("/b/.env", 7), Now: at(2026, 5, 2)})

	if len(g.Secrets) != 1 {
		t.Fatalf("len(Secrets) = %d, want 1 (dedup)", len(g.Secrets))
	}
	s := g.Secrets[0]
	if len(s.FoundIn) != 2 {
		t.Errorf("len(FoundIn) = %d, want 2", len(s.FoundIn))
	}
	if s.ID != fingerprint.Compute("K", "v") {
		t.Errorf("ID changed across dedup: %q", s.ID)
	}
}

func TestUpsert_DistinctValuesKept(t *testing.T) {
	g := Empty()
	g.Upsert(Upsertable{KeyName: "K", Value: "v1", Found: mkFound("/a/.env", 1), Now: at(2026, 5, 1)})
	g.Upsert(Upsertable{KeyName: "K", Value: "v2", Found: mkFound("/b/.env", 1), Now: at(2026, 5, 1)})

	if len(g.Secrets) != 2 {
		t.Fatalf("len(Secrets) = %d, want 2", len(g.Secrets))
	}
	if g.Secrets[0].ID == g.Secrets[1].ID {
		t.Errorf("two distinct values shared an id: %q", g.Secrets[0].ID)
	}
}

func TestUpsert_DriftAppendsValueHistory(t *testing.T) {
	g := Empty()
	g.Upsert(Upsertable{KeyName: "K", Value: "v_old", Found: mkFound("/a/.env", 1), Now: at(2026, 5, 1)})
	oldFP := fingerprint.Compute("K", "v_old")

	g.Upsert(Upsertable{KeyName: "K", Value: "v_new_rotated", Found: mkFound("/a/.env", 1), Now: at(2026, 5, 5)})

	if len(g.Secrets) != 1 {
		t.Fatalf("len(Secrets) = %d, want 1 (drift, not new)", len(g.Secrets))
	}
	s := g.Secrets[0]
	if s.ValueFingerprint != fingerprint.Compute("K", "v_new_rotated") {
		t.Errorf("ValueFingerprint not updated to new value: %q", s.ValueFingerprint)
	}
	if s.ValuePreview != fingerprint.Preview("v_new_rotated") {
		t.Errorf("ValuePreview not updated: %q", s.ValuePreview)
	}
	foundOld := false
	for _, h := range s.ValueHistory {
		if h.Fingerprint == oldFP {
			foundOld = true
		}
	}
	if !foundOld {
		t.Errorf("old fingerprint not in ValueHistory: %+v", s.ValueHistory)
	}
}

func TestUpsert_AnnotationPersistsAcrossDrift(t *testing.T) {
	g := Empty()
	g.Upsert(Upsertable{KeyName: "K", Value: "v_old", Found: mkFound("/a/.env", 1), Now: at(2026, 5, 1)})
	g.Secrets[0].Annotation = Annotation{
		Notes: "personal token",
		Tags:  []string{"personal"},
		Owner: "@rome",
	}
	g.Upsert(Upsertable{KeyName: "K", Value: "v_new", Found: mkFound("/a/.env", 1), Now: at(2026, 5, 5)})

	if g.Secrets[0].Annotation.Notes != "personal token" {
		t.Errorf("Notes lost across drift: %+v", g.Secrets[0].Annotation)
	}
	if g.Secrets[0].Annotation.Owner != "@rome" {
		t.Errorf("Owner lost: %q", g.Secrets[0].Annotation.Owner)
	}
}

func TestUpsert_FirstSeenLastSeen(t *testing.T) {
	g := Empty()
	first := at(2026, 5, 1)
	later := at(2026, 5, 7)

	g.Upsert(Upsertable{KeyName: "K", Value: "v", Found: mkFound("/a/.env", 1), Now: first})
	g.Upsert(Upsertable{KeyName: "K", Value: "v", Found: mkFound("/a/.env", 1), Now: later})

	s := g.Secrets[0]
	if !s.FirstSeen.Equal(first) {
		t.Errorf("FirstSeen = %v, want %v (preserved)", s.FirstSeen, first)
	}
	if !s.LastSeen.Equal(later) {
		t.Errorf("LastSeen = %v, want %v (updated)", s.LastSeen, later)
	}
}

func TestUpsert_NoFullValueLeak(t *testing.T) {
	g := Empty()
	const secret = "sk-ant-VERY-DISTINCTIVE-FULL-VALUE-DO-NOT-LEAK"
	g.Upsert(Upsertable{KeyName: "ANTHROPIC_API_KEY", Value: secret, Found: mkFound("/p/.env", 1), Now: at(2026, 5, 1)})

	dir := t.TempDir()
	path := filepath.Join(dir, "global.json")
	if err := Save(path, g); err != nil {
		t.Fatal(err)
	}
	body := readFile(t, path)
	if bytes.Contains(body, []byte(secret)) {
		t.Errorf("full secret value leaked into persisted store:\n%s", body)
	}
	// Sanity: preview should appear (it's the only value-derived hint)
	if !strings.Contains(string(body), "...") {
		t.Errorf("expected truncated preview in persisted body")
	}
}

func TestMarkStale(t *testing.T) {
	g := Empty()
	g.Upsert(Upsertable{KeyName: "K", Value: "v", Found: mkFound("/a/.env", 1), Now: at(2026, 5, 1)})
	id := g.Secrets[0].ID

	if !g.MarkStale(id) {
		t.Fatal("MarkStale returned false for existing id")
	}
	if !g.Secrets[0].Annotation.Stale {
		t.Error("Stale not set")
	}
	if len(g.Secrets) != 1 {
		t.Errorf("MarkStale removed entry; len = %d", len(g.Secrets))
	}
	// Persistence round-trip preserves the flag.
	dir := t.TempDir()
	path := filepath.Join(dir, "global.json")
	if err := Save(path, g); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Secrets[0].Annotation.Stale {
		t.Error("Stale flag lost across Save/Load")
	}

	if g.MarkStale("blake3:does-not-exist") {
		t.Error("MarkStale returned true for unknown id")
	}
}

func TestMarkRotated(t *testing.T) {
	g := Empty()
	g.Upsert(Upsertable{KeyName: "K", Value: "v", Found: mkFound("/a/.env", 1), Now: at(2026, 5, 1)})
	id := g.Secrets[0].ID
	beforeFP := g.Secrets[0].ValueFingerprint
	beforeFound := append([]FoundIn(nil), g.Secrets[0].FoundIn...)

	rotateAt := at(2026, 5, 9)
	if !g.MarkRotated(id, rotateAt) {
		t.Fatal("MarkRotated returned false for existing id")
	}

	s := g.Secrets[0]
	gotEntry := false
	for _, h := range s.ValueHistory {
		if h.Fingerprint == beforeFP && h.SeenAt.Equal(rotateAt) {
			gotEntry = true
		}
	}
	if !gotEntry {
		t.Errorf("rotation event not recorded in ValueHistory: %+v", s.ValueHistory)
	}
	if len(s.FoundIn) != len(beforeFound) || s.FoundIn[0].Path != beforeFound[0].Path {
		t.Errorf("MarkRotated mutated FoundIn: %+v", s.FoundIn)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAddManual(t *testing.T) {
	g := Empty()
	now := time.Now().UTC()
	s := g.AddManual("manual:abc", "MY_KEY", "~/secrets/x", Annotation{Tags: []string{"proj"}}, now)
	if s == nil {
		t.Fatal("AddManual returned nil for a fresh id")
	}
	if s.ValueFingerprint != "" || s.ValuePreview != "" {
		t.Errorf("manual entry should have no scanned value, got fp=%q preview=%q", s.ValueFingerprint, s.ValuePreview)
	}
	if len(s.FoundIn) != 1 || s.FoundIn[0].SourceType != SourceManual || s.FoundIn[0].Path != "~/secrets/x" {
		t.Errorf("manual FoundIn wrong: %+v", s.FoundIn)
	}
	if len(g.Secrets) != 1 {
		t.Fatalf("want 1 secret, got %d", len(g.Secrets))
	}
	// duplicate id refused
	if dup := g.AddManual("manual:abc", "OTHER", "", Annotation{}, now); dup != nil {
		t.Error("AddManual should refuse a duplicate id")
	}
	// no-path entry has empty FoundIn
	s2 := g.AddManual("manual:def", "NOPATH", "", Annotation{}, now)
	if s2 == nil || len(s2.FoundIn) != 0 {
		t.Errorf("no-path manual entry should have empty FoundIn, got %+v", s2)
	}
}
