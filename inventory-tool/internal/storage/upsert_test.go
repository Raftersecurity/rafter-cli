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

func TestPruneFoundInPaths(t *testing.T) {
	g := Empty()
	now := at(2026, 5, 1)

	// S1: lives at both /a/.env and /a/.env.example.
	g.Upsert(Upsertable{KeyName: "K", Value: "v", Found: mkFound("/a/.env", 1), Now: now})
	g.Upsert(Upsertable{KeyName: "K", Value: "v", Found: mkFound("/a/.env.example", 1), Now: now})
	// S2: lives ONLY at /b/.env.example — pruning that path must remove S2.
	g.Upsert(Upsertable{KeyName: "ONLY_TEMPLATE", Value: "v", Found: mkFound("/b/.env.example", 1), Now: now})
	// S3: untouched control — never appears in the prune list.
	g.Upsert(Upsertable{KeyName: "KEEPME", Value: "v", Found: mkFound("/c/.env", 1), Now: now})

	if len(g.Secrets) != 3 {
		t.Fatalf("setup: len(Secrets) = %d, want 3", len(g.Secrets))
	}

	foundInRemoved, secretsRemoved := g.PruneFoundInPaths([]string{
		"/a/.env.example",
		"/b/.env.example",
	})
	if foundInRemoved != 2 {
		t.Errorf("foundInRemoved = %d, want 2", foundInRemoved)
	}
	if secretsRemoved != 1 {
		t.Errorf("secretsRemoved = %d, want 1 (only S2 had no other locations)", secretsRemoved)
	}
	if len(g.Secrets) != 2 {
		t.Fatalf("len(Secrets) = %d, want 2", len(g.Secrets))
	}

	// S1 keeps its real /a/.env entry; the .example FoundIn is gone.
	var s1 *Secret
	for i := range g.Secrets {
		if g.Secrets[i].KeyName == "K" {
			s1 = &g.Secrets[i]
		}
	}
	if s1 == nil {
		t.Fatal("S1 (KeyName=K) was removed; expected it to keep /a/.env")
	}
	if len(s1.FoundIn) != 1 || s1.FoundIn[0].Path != "/a/.env" {
		t.Errorf("S1.FoundIn = %+v, want single /a/.env", s1.FoundIn)
	}

	// S3 untouched.
	var s3 *Secret
	for i := range g.Secrets {
		if g.Secrets[i].KeyName == "KEEPME" {
			s3 = &g.Secrets[i]
		}
	}
	if s3 == nil {
		t.Fatal("S3 (KeyName=KEEPME) missing — prune touched a path it shouldn't have")
	}
	if len(s3.FoundIn) != 1 || s3.FoundIn[0].Path != "/c/.env" {
		t.Errorf("S3.FoundIn = %+v, want single /c/.env", s3.FoundIn)
	}
}

func TestPruneFoundInPaths_Empty(t *testing.T) {
	g := Empty()
	g.Upsert(Upsertable{KeyName: "K", Value: "v", Found: mkFound("/a/.env", 1), Now: at(2026, 5, 1)})

	foundInRemoved, secretsRemoved := g.PruneFoundInPaths(nil)
	if foundInRemoved != 0 || secretsRemoved != 0 {
		t.Errorf("empty paths: removed=(%d,%d), want (0,0)", foundInRemoved, secretsRemoved)
	}
	if len(g.Secrets) != 1 {
		t.Errorf("empty paths must not touch Secrets; len = %d", len(g.Secrets))
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
