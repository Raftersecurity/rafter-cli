package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/docstore"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
)

// seedEnvSecretAtMode writes a fixture .env with the requested mode
// and registers it in the store. Mirrors seedEnvSecret but lets the
// caller pick the starting permission so chmod-600 tests can exercise
// both the world-readable and already-tightened paths.
func seedEnvSecretAtMode(t *testing.T, store *docstore.Store, dir string, mode os.FileMode) (id, envPath string) {
	t.Helper()
	envPath = filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("API_KEY=super-secret-1234567890\n"), mode); err != nil {
		t.Fatal(err)
	}
	// os.WriteFile honours umask, so explicitly chmod to the requested
	// mode. Without this, a strict umask would silently downshift 0644
	// to 0600 and the "world readable" tests become tautologies.
	if err := os.Chmod(envPath, mode); err != nil {
		t.Fatal(err)
	}
	perms := "0600"
	if mode != 0o600 {
		perms = "0644"
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
				Permissions: perms,
			}},
			Annotation:   storage.Annotation{Tags: []string{}},
			ValueHistory: []storage.ValueHistoryEntry{},
		})
		return true
	})
	return "blake3:test-id", envPath
}

func TestSourceChmod600_TightensFileAndDoc(t *testing.T) {
	s, ts, store, storePath := newTestServerWithStore(t)
	dir := t.TempDir()
	_, envPath := seedEnvSecretAtMode(t, store, dir, 0o644)

	body := []byte(`{"path":"` + envPath + `"}`)
	respBody := doJSON(t, authedReq(t, "POST", ts.URL+"/api/sources/chmod600", s.token, body), 200)

	var resp struct {
		Path        string `json:"path"`
		Permissions string `json:"permissions"`
		NoOp        bool   `json:"no_op"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		t.Fatalf("unmarshal: %v: %s", err, respBody)
	}
	if resp.Permissions != "0600" {
		t.Errorf("Permissions = %q, want 0600", resp.Permissions)
	}
	if resp.NoOp {
		t.Errorf("NoOp = true on 0644→0600 transition; should be false")
	}

	// On-disk mode is now 0600.
	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("file mode = %#o, want 0o600", got)
	}

	// In-memory doc reflects the tightening.
	var docPerms string
	store.Read(func(g *storage.Global) {
		docPerms = g.Secrets[0].FoundIn[0].Permissions
	})
	if docPerms != "0600" {
		t.Errorf("docstore Permissions = %q, want 0600", docPerms)
	}

	// Persisted: the saved global.json carries the new perms.
	saved, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saved), `"permissions": "0600"`) {
		t.Errorf("persisted doc missing 0600 permissions: %s", saved)
	}
}

func TestSourceChmod600_AlreadyTightenedIsNoOp(t *testing.T) {
	s, ts, store, _ := newTestServerWithStore(t)
	dir := t.TempDir()
	_, envPath := seedEnvSecretAtMode(t, store, dir, 0o600)

	body := []byte(`{"path":"` + envPath + `"}`)
	respBody := doJSON(t, authedReq(t, "POST", ts.URL+"/api/sources/chmod600", s.token, body), 200)

	var resp struct {
		Permissions string `json:"permissions"`
		NoOp        bool   `json:"no_op"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		t.Fatalf("unmarshal: %v: %s", err, respBody)
	}
	if !resp.NoOp {
		t.Errorf("NoOp = false; should report no-op when file is already 0600")
	}
	if resp.Permissions != "0600" {
		t.Errorf("Permissions = %q, want 0600", resp.Permissions)
	}
}

func TestSourceChmod600_UnknownPathReturns404(t *testing.T) {
	s, ts, _, _ := newTestServerWithStore(t)
	body := []byte(`{"path":"/etc/passwd"}`)
	resp, err := http.DefaultClient.Do(authedReq(t, "POST", ts.URL+"/api/sources/chmod600", s.token, body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got %d, want 404", resp.StatusCode)
	}
}

func TestSourceChmod600_MissingPathReturns400(t *testing.T) {
	s, ts, _, _ := newTestServerWithStore(t)
	resp, err := http.DefaultClient.Do(authedReq(t, "POST", ts.URL+"/api/sources/chmod600", s.token, []byte(`{}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", resp.StatusCode)
	}
}

func TestSourceChmod600_FileGoneReturns404(t *testing.T) {
	s, ts, store, _ := newTestServerWithStore(t)
	dir := t.TempDir()
	_, envPath := seedEnvSecretAtMode(t, store, dir, 0o644)
	if err := os.Remove(envPath); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"path":"` + envPath + `"}`)
	resp, err := http.DefaultClient.Do(authedReq(t, "POST", ts.URL+"/api/sources/chmod600", s.token, body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got %d, want 404", resp.StatusCode)
	}
}

func TestSourceChmod600_NoStoreReturns503(t *testing.T) {
	s, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.listener.Close()
	mux := http.NewServeMux()
	s.routes(mux)

	req := authedReq(t, "POST", "http://example.test/api/sources/chmod600", s.token, []byte(`{"path":"/x"}`))
	rr := httpRecord{}
	mux.ServeHTTP(&rr, req)
	if rr.code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", rr.code)
	}
}

// httpRecord is a minimal http.ResponseWriter for the no-store path
// (we want to skip the requireToken middleware so the 503 surfaces
// before auth checks; the same pattern that secrets_test.go uses for
// 503 cases relies on the public test server, but the chmod handler
// reads the body unconditionally so we can shortcut here).
type httpRecord struct {
	code    int
	headers http.Header
	body    []byte
}

func (r *httpRecord) Header() http.Header {
	if r.headers == nil {
		r.headers = http.Header{}
	}
	return r.headers
}
func (r *httpRecord) Write(b []byte) (int, error) { r.body = append(r.body, b...); return len(b), nil }
func (r *httpRecord) WriteHeader(code int)        { r.code = code }
