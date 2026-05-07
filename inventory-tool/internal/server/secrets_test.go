package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/docstore"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
)

// newTestServerWithStore returns a server wired against an in-memory
// docstore plus the HTTP test fixture for talking to it. The saver
// captures the doc to a tempfile so the persistence path is exercised
// end-to-end (mark stale / annotate go through Save).
func newTestServerWithStore(t *testing.T) (*Server, *httptest.Server, *docstore.Store, string) {
	t.Helper()
	dir := t.TempDir()
	storePath := filepath.Join(dir, "global.json")
	doc := storage.Empty()
	store := docstore.New(doc, func(g *storage.Global) error {
		return storage.Save(storePath, g)
	})
	s, err := New(Config{IdleTimeout: time.Hour, Store: store})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = s.listener.Close()
	mux := http.NewServeMux()
	s.routes(mux)
	ts := httptest.NewServer(s.requireToken(mux))
	t.Cleanup(ts.Close)
	return s, ts, store, storePath
}

// authedReq builds a request authenticated by header so each test
// doesn't reimplement the cookie dance.
func authedReq(t *testing.T, method, url, token string, body []byte) *http.Request {
	t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(headerName, token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func doJSON(t *testing.T, req *http.Request, want int) []byte {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("%s %s: got %d (%s), want %d", req.Method, req.URL.Path, resp.StatusCode, body, want)
	}
	return body
}

// seedSecrets injects a Secret with a known id and an env-file source
// pointing at a real on-disk dotenv so reveal can read the value back.
func seedEnvSecret(t *testing.T, store *docstore.Store, dir string) (id, envPath string) {
	t.Helper()
	envPath = filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("API_KEY=super-secret-1234567890\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store.Update(func(g *storage.Global) bool {
		g.Secrets = append(g.Secrets, storage.Secret{
			ID:               "blake3:test-id",
			KeyName:          "API_KEY",
			ValueFingerprint: "blake3:test-id",
			ValuePreview:     "super...7890",
			FoundIn: []storage.FoundIn{{
				SourceType:  storage.SourceEnvFile,
				Path:        envPath,
				Line:        1,
				Permissions: "0600",
			}},
			Annotation:   storage.Annotation{Tags: []string{}},
			ValueHistory: []storage.ValueHistoryEntry{},
		})
		return true
	})
	return "blake3:test-id", envPath
}

func TestSecretsList_ReturnsSecrets(t *testing.T) {
	s, ts, store, _ := newTestServerWithStore(t)
	dir := t.TempDir()
	seedEnvSecret(t, store, dir)

	body := doJSON(t, authedReq(t, "GET", ts.URL+"/api/secrets", s.token, nil), 200)
	var resp struct {
		Secrets      []storage.Secret `json:"secrets"`
		RevealPolicy string           `json:"reveal_policy"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v: %s", err, body)
	}
	if len(resp.Secrets) != 1 {
		t.Fatalf("got %d secrets, want 1", len(resp.Secrets))
	}
	if resp.Secrets[0].KeyName != "API_KEY" {
		t.Errorf("KeyName = %q, want API_KEY", resp.Secrets[0].KeyName)
	}
	if resp.RevealPolicy != storage.DefaultRevealPolicy {
		t.Errorf("RevealPolicy = %q, want %q", resp.RevealPolicy, storage.DefaultRevealPolicy)
	}
}

func TestSecretsList_NoStoreReturns503(t *testing.T) {
	s, err := New(Config{IdleTimeout: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.listener.Close()
	mux := http.NewServeMux()
	s.routes(mux)
	ts := httptest.NewServer(s.requireToken(mux))
	defer ts.Close()

	resp, err := http.DefaultClient.Do(authedReq(t, "GET", ts.URL+"/api/secrets", s.token, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", resp.StatusCode)
	}
}

func TestSecretReveal_ReturnsLiveValue(t *testing.T) {
	s, ts, store, _ := newTestServerWithStore(t)
	dir := t.TempDir()
	id, _ := seedEnvSecret(t, store, dir)

	body := doJSON(t, authedReq(t, "POST", ts.URL+"/api/secrets/"+id+"/reveal", s.token, []byte(`{}`)), 200)
	var resp struct {
		Value      string `json:"value"`
		SourceType string `json:"source_type"`
		Path       string `json:"path"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v: %s", err, body)
	}
	if resp.Value != "super-secret-1234567890" {
		t.Errorf("Value = %q, want super-secret-1234567890", resp.Value)
	}
	if resp.SourceType != storage.SourceEnvFile {
		t.Errorf("SourceType = %q, want %q", resp.SourceType, storage.SourceEnvFile)
	}
}

func TestSecretReveal_UnknownIdReturns404(t *testing.T) {
	s, ts, _, _ := newTestServerWithStore(t)
	resp, err := http.DefaultClient.Do(
		authedReq(t, "POST", ts.URL+"/api/secrets/blake3:nope/reveal", s.token, []byte(`{}`)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got %d, want 404", resp.StatusCode)
	}
}

func TestSecretReveal_KeystoreReturns422(t *testing.T) {
	s, ts, store, _ := newTestServerWithStore(t)
	store.Update(func(g *storage.Global) bool {
		g.Secrets = append(g.Secrets, storage.Secret{
			ID:      "blake3:keystore-only",
			KeyName: "anthropic-cli",
			FoundIn: []storage.FoundIn{{
				SourceType: storage.SourceKeystore,
				Keystore:   "macos-keychain",
				Service:    "anthropic-cli",
				Account:    "rome",
			}},
			Annotation: storage.Annotation{Tags: []string{}},
		})
		return true
	})

	resp, err := http.DefaultClient.Do(
		authedReq(t, "POST", ts.URL+"/api/secrets/blake3:keystore-only/reveal", s.token, []byte(`{}`)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("got %d, want 422", resp.StatusCode)
	}
}

func TestSecretReveal_ValueGoneReturns410(t *testing.T) {
	s, ts, store, _ := newTestServerWithStore(t)
	dir := t.TempDir()
	id, envPath := seedEnvSecret(t, store, dir)

	// Mutate the file: API_KEY removed entirely. Reveal should now 410.
	if err := os.WriteFile(envPath, []byte("OTHER_KEY=irrelevant\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(
		authedReq(t, "POST", ts.URL+"/api/secrets/"+id+"/reveal", s.token, []byte(`{}`)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("got %d, want 410", resp.StatusCode)
	}
}

func TestSecretAnnotate_PersistsAndPersists(t *testing.T) {
	s, ts, store, storePath := newTestServerWithStore(t)
	dir := t.TempDir()
	id, _ := seedEnvSecret(t, store, dir)

	patch := []byte(`{
        "source_url": "https://console.example.com",
        "owner": "@rome",
        "notes": "personal account",
        "rotate_url": "https://console.example.com/rotate",
        "tags": ["personal", "anthropic"]
    }`)
	doJSON(t, authedReq(t, "PUT", ts.URL+"/api/secrets/"+id+"/annotation", s.token, patch), 204)

	// In-memory check.
	var got storage.Annotation
	store.Read(func(g *storage.Global) {
		got = g.Secrets[0].Annotation
	})
	if got.Owner != "@rome" || got.Notes != "personal account" {
		t.Errorf("annotation not stored: %+v", got)
	}
	if len(got.Tags) != 2 || got.Tags[0] != "personal" {
		t.Errorf("tags wrong: %+v", got.Tags)
	}

	// On-disk check: PUT should have triggered Save.
	body, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("read storePath: %v", err)
	}
	if !strings.Contains(string(body), "@rome") {
		t.Errorf("annotation not persisted to disk: %s", body)
	}
}

func TestSecretAnnotate_UnknownIdReturns404(t *testing.T) {
	s, ts, _, _ := newTestServerWithStore(t)
	resp, err := http.DefaultClient.Do(
		authedReq(t, "PUT", ts.URL+"/api/secrets/blake3:nope/annotation", s.token, []byte(`{"owner":"x"}`)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got %d, want 404", resp.StatusCode)
	}
}

func TestSecretAnnotate_PreservesStaleFlag(t *testing.T) {
	s, ts, store, _ := newTestServerWithStore(t)
	dir := t.TempDir()
	id, _ := seedEnvSecret(t, store, dir)
	store.Update(func(g *storage.Global) bool {
		g.Secrets[0].Annotation.Stale = true
		return true
	})
	doJSON(t, authedReq(t, "PUT", ts.URL+"/api/secrets/"+id+"/annotation", s.token, []byte(`{"owner":"new"}`)), 204)
	var stale bool
	store.Read(func(g *storage.Global) { stale = g.Secrets[0].Annotation.Stale })
	if !stale {
		t.Errorf("annotation PUT cleared the stale flag — should be sticky")
	}
}

func TestSecretMarkStale_FlipsFlag(t *testing.T) {
	s, ts, store, _ := newTestServerWithStore(t)
	dir := t.TempDir()
	id, _ := seedEnvSecret(t, store, dir)
	doJSON(t, authedReq(t, "POST", ts.URL+"/api/secrets/"+id+"/stale", s.token, nil), 204)
	var stale bool
	store.Read(func(g *storage.Global) { stale = g.Secrets[0].Annotation.Stale })
	if !stale {
		t.Errorf("Stale not set after POST /stale")
	}
}

func TestSecretMarkRotated_AppendsHistory(t *testing.T) {
	s, ts, store, _ := newTestServerWithStore(t)
	dir := t.TempDir()
	id, _ := seedEnvSecret(t, store, dir)
	doJSON(t, authedReq(t, "POST", ts.URL+"/api/secrets/"+id+"/rotated", s.token, nil), 204)
	var n int
	store.Read(func(g *storage.Global) { n = len(g.Secrets[0].ValueHistory) })
	if n != 1 {
		t.Errorf("ValueHistory has %d entries, want 1", n)
	}
}

func TestSecretEndpoints_UnknownIdsConsistent404(t *testing.T) {
	s, ts, _, _ := newTestServerWithStore(t)
	cases := []struct {
		method, path string
		body         []byte
	}{
		{"POST", "/api/secrets/blake3:nope/stale", nil},
		{"POST", "/api/secrets/blake3:nope/rotated", nil},
	}
	for _, c := range cases {
		resp, err := http.DefaultClient.Do(authedReq(t, c.method, ts.URL+c.path, s.token, c.body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s: got %d, want 404", c.method, c.path, resp.StatusCode)
		}
	}
}

func TestStaticAssets_AppJSReachable(t *testing.T) {
	s, ts, _, _ := newTestServerWithStore(t)
	resp, err := http.DefaultClient.Do(authedReq(t, "GET", ts.URL+"/static/app.js", s.token, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("/api/secrets")) {
		t.Errorf("app.js does not reference /api/secrets — bundling broken: first 200 bytes %q", body[:min(200, len(body))])
	}
}

func TestIndexHTML_LoadsAtRoot(t *testing.T) {
	s, ts, _, _ := newTestServerWithStore(t)
	resp, err := http.DefaultClient.Do(authedReq(t, "GET", ts.URL+"/", s.token, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type = %q, want text/html…", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("/static/app.js")) {
		t.Errorf("index.html does not reference app.js")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
