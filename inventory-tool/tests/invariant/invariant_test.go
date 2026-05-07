// Package invariant is the cross-package safety net that proves trove's
// hard rule: zero mutations to user secret files in any code path.
//
// These tests construct a synthetic fixture filesystem of representative
// secret-bearing files (.env, .npmrc, .zshrc, ~/.aws/credentials), drive
// the full trove HTTP API and the real fsnotify-backed rescan pipeline
// against it, and assert that the fixture is byte-identical afterwards
// (apart from any mutation the test itself performs).
//
// They intentionally live OUTSIDE the per-package unit tests: every
// individual scanner already has unit tests that confirm "this scanner
// reads O_RDONLY"; this package confirms the SAME guarantee at the
// process level — even if a future scanner forgets to be careful, the
// invariant test catches it before it lands.
package invariant_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	mathrand "math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/docstore"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/eventbus"
	rescanpkg "github.com/Raftersecurity/rafter-cli/inventory-tool/internal/rescan"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/server"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/watch"
)

// fixtureFiles is the canonical set of secret-bearing files trove must
// never mutate. The set covers each scanner family at least once: env
// (file/), npmrc + aws credentials (config/), shellrc (shellrc/). A
// nested project directory exercises walking past the root.
func fixtureFiles() map[string]string {
	return map[string]string{
		".env":              "API_KEY=super-secret-1234567890\nDB_PASS=hunter2-must-stay\n",
		".env.production":   "STRIPE_KEY=sk_live_abcdef1234567890\n",
		"project/.env":      "PROJECT_TOKEN=tok_proj_qwertyuiop1234\n",
		"project/.npmrc":    "//registry.npmjs.org/:_authToken=npm_super_secret_token_123\n",
		".zshrc":            "export GITHUB_TOKEN=ghp_supersecrettoken1234567890\n",
		".aws/credentials":  "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
		"project/README.md": "# project\nNothing to see here.\n",
		"project/notes.txt": "free-form notes that should never be touched\n",
	}
}

// writeFixture lays out the files at base. Parent directories are
// created at 0o700 to match how the user's $HOME tree typically looks;
// individual files use 0o600 because a real .env file is owner-only.
func writeFixture(t *testing.T, base string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		full := filepath.Join(base, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", full, err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
}

// manifest is path → sha256(contents). Walking the tree once and hashing
// every regular file is cheap for a fixture of this size and is the
// most evidence-rich form of "did anything change" we have.
type manifest map[string]string

func manifestOf(t *testing.T, root string) manifest {
	t.Helper()
	out := manifest{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("read %s: %w", p, err)
		}
		sum := sha256.Sum256(b)
		out[p] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatalf("manifest walk %s: %v", root, err)
	}
	return out
}

// diff returns paths whose hash changed (added, removed, modified).
func (m manifest) diff(other manifest) []string {
	var changed []string
	for p, h := range m {
		oh, ok := other[p]
		if !ok {
			changed = append(changed, "removed:"+p)
			continue
		}
		if oh != h {
			changed = append(changed, "modified:"+p)
		}
	}
	for p := range other {
		if _, ok := m[p]; !ok {
			changed = append(changed, "added:"+p)
		}
	}
	return changed
}

// trove bundles the live server + rescanner + plumbing the tests drive.
// Everything the test needs to talk to the running process (URL, token,
// rescan trigger, store path) is exposed here so individual tests stay
// short.
type trove struct {
	t        *testing.T
	baseURL  string
	token    string
	storeDir string
	store    *docstore.Store
	rescan   *rescanpkg.Rescanner
	bus      *eventbus.Bus
	srv      *server.Server
	cancel   context.CancelFunc
	wg       *sync.WaitGroup
}

// startTrove spins up a real trove server (real listener, real watcher,
// real rescanner) pointed at fixtureRoot. The store directory is held
// completely separate from the fixture so we can prove "trove only
// writes inside its config dir" by checking for any write touching the
// fixture tree.
func startTrove(t *testing.T, fixtureRoot string) *trove {
	t.Helper()

	storeDir := t.TempDir()
	storePath := filepath.Join(storeDir, "trove", "global.json")

	doc := storage.Empty()
	doc.ScanConfig.Roots = []string{fixtureRoot}

	// Persist the initial doc so the saver path is exercised on every
	// later mutation rather than only on first save.
	if err := storage.Save(storePath, doc); err != nil {
		t.Fatalf("initial save: %v", err)
	}

	store := docstore.New(doc, func(g *storage.Global) error {
		return storage.Save(storePath, g)
	})

	bus := eventbus.New()

	srv, err := server.New(server.Config{
		IdleTimeout: time.Hour,
		Bus:         bus,
		Store:       store,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	// Real fsnotify watcher with a short debounce so the SSE-drift
	// portion of the test doesn't take half a second per mutation.
	wch, err := watch.NewWithConfig(watch.Config{
		Roots:       []string{fixtureRoot},
		Debounce:    50 * time.Millisecond,
		ExcludeDirs: []string{storeDir},
	})
	if err != nil {
		t.Fatalf("watch.NewWithConfig: %v", err)
	}

	rs, err := rescanpkg.New(rescanpkg.Config{
		Store:   store,
		Bus:     bus,
		Watcher: wch,
		OnError: func(e error) { t.Logf("rescan: %v", e) },
	})
	if err != nil {
		t.Fatalf("rescan.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := rs.Run(ctx); err != nil {
			t.Logf("rescanner exited: %v", err)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := srv.Run(ctx); err != nil {
			t.Logf("server exited: %v", err)
		}
	}()

	parsed, err := url.Parse(srv.URL())
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	tok := parsed.Query().Get("token")
	base := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)

	tr := &trove{
		t:        t,
		baseURL:  base,
		token:    tok,
		storeDir: storeDir,
		store:    store,
		rescan:   rs,
		bus:      bus,
		srv:      srv,
		cancel:   cancel,
		wg:       wg,
	}

	// Wait for the server goroutine to start serving. The listener is
	// already bound by New(), but Serve may not have looped yet — poll
	// /api/status until it answers (or fail loudly).
	tr.waitReady(t)

	t.Cleanup(func() {
		shCtx, shCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shCancel()
		_ = srv.Shutdown(shCtx)
		cancel()
		wg.Wait()
	})
	return tr
}

func (tr *trove) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		req, err := http.NewRequest("GET", tr.baseURL+"/api/status", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Trove-Token", tr.token)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never became ready: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// do makes an authenticated request and returns (status, body). Any
// transport error fails the test — body parsing is the caller's job.
func (tr *trove) do(method, path string, body []byte) (int, []byte) {
	tr.t.Helper()
	var r io.Reader
	if body != nil {
		r = strings.NewReader(string(body))
	}
	req, err := http.NewRequest(method, tr.baseURL+path, r)
	if err != nil {
		tr.t.Fatal(err)
	}
	req.Header.Set("X-Trove-Token", tr.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		tr.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// listSecrets returns every secret currently in the store as the API
// reports them. Used to discover IDs after a scan.
func (tr *trove) listSecrets() []storage.Secret {
	tr.t.Helper()
	status, body := tr.do("GET", "/api/secrets", nil)
	if status != 200 {
		tr.t.Fatalf("GET /api/secrets: %d (%s)", status, body)
	}
	var resp struct {
		Secrets []storage.Secret `json:"secrets"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		tr.t.Fatalf("decode secrets: %v: %s", err, body)
	}
	return resp.Secrets
}

// driveFullAPI exercises every documented mutation surface against
// every secret currently in the store. Each call is a separate request
// so a single bad handler can't taint subsequent ones.
func (tr *trove) driveFullAPI() {
	tr.t.Helper()
	secrets := tr.listSecrets()
	if len(secrets) == 0 {
		tr.t.Fatalf("no secrets to drive against — scan never populated the store")
	}
	for _, s := range secrets {
		// Reveal at the default index plus an explicit index 0.
		tr.do("POST", "/api/secrets/"+s.ID+"/reveal", []byte(`{}`))
		tr.do("POST", "/api/secrets/"+s.ID+"/reveal", []byte(`{"source_index":0}`))
		// Annotate with realistic metadata.
		patch := []byte(`{"source_url":"https://example.test","owner":"@invariant","notes":"trove never wrote me","rotate_url":"https://example.test/rotate","tags":["invariant","test"]}`)
		tr.do("PUT", "/api/secrets/"+s.ID+"/annotation", patch)
		// Stale + rotated round-trip.
		tr.do("POST", "/api/secrets/"+s.ID+"/stale", nil)
		tr.do("POST", "/api/secrets/"+s.ID+"/rotated", nil)
	}
	// And the read paths once more to make sure handlers don't write
	// on the way out the door.
	tr.do("GET", "/api/secrets", nil)
	tr.do("GET", "/api/status", nil)
}

func TestInvariant_ServerNeverMutatesFixtureFS(t *testing.T) {
	fixture := t.TempDir()
	writeFixture(t, fixture, fixtureFiles())

	before := manifestOf(t, fixture)

	tr := startTrove(t, fixture)

	// Initial scan populates the store. The rescanner publishes events
	// only when triggered by the watcher OR by an explicit call — so we
	// kick it once up front.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tr.rescan.Rescan(ctx)

	// Drive every documented mutation surface twice — once before any
	// fs mutation, once after — so a handler that silently writes on
	// "second click" would still be caught.
	tr.driveFullAPI()
	tr.rescan.Rescan(ctx)
	tr.driveFullAPI()

	// SSE drift exercise: the test (not trove) mutates one .env, then
	// triggers a rescan. The rescanner should refresh its store entry
	// and publish events; it must not write anywhere under fixture/.
	target := filepath.Join(fixture, ".env")
	if err := os.WriteFile(target, []byte("API_KEY=rotated-9876543210-from-test\n"), 0o600); err != nil {
		t.Fatalf("test mutation: %v", err)
	}
	// Wait a beat for fsnotify to deliver, plus the watcher's debounce
	// (50ms in tests) — then explicitly Rescan to make the assertion
	// independent of fsnotify timing flakiness in CI.
	time.Sleep(150 * time.Millisecond)
	tr.rescan.Rescan(ctx)
	tr.driveFullAPI()

	after := manifestOf(t, fixture)

	// Every fixture path other than the explicitly-mutated .env must
	// be byte-identical. The mutated path must be different — if it
	// matches, the test didn't actually modify the file and the whole
	// invariant assertion is a tautology.
	for path, beforeHash := range before {
		afterHash, ok := after[path]
		if !ok {
			t.Errorf("trove deleted fixture file: %s", path)
			continue
		}
		if path == target {
			if beforeHash == afterHash {
				t.Errorf("test never actually mutated %s — invariant assertion would be vacuous", path)
			}
			continue
		}
		if beforeHash != afterHash {
			t.Errorf("trove mutated fixture file %s\n  before=%s\n  after =%s", path, beforeHash, afterHash)
		}
	}
	for path := range after {
		if _, ok := before[path]; !ok {
			t.Errorf("trove created file under fixture root: %s", path)
		}
	}
}

func TestInvariant_ConfigDirIsTheOnlyWriter(t *testing.T) {
	fixture := t.TempDir()
	writeFixture(t, fixture, fixtureFiles())

	// Spin up a *separate* fsnotify watcher whose only job is to record
	// every write/create/remove/rename/chmod event under fixture/. If
	// trove writes anywhere in the tree, the recorder sees it.
	rec, err := newWriteRecorder(fixture)
	if err != nil {
		t.Fatalf("recorder: %v", err)
	}
	defer rec.close()

	tr := startTrove(t, fixture)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tr.rescan.Rescan(ctx)
	tr.driveFullAPI()
	tr.rescan.Rescan(ctx)
	tr.driveFullAPI()

	// Settle: give fsnotify a moment to drain any in-flight events.
	time.Sleep(100 * time.Millisecond)

	if events := rec.snapshot(); len(events) > 0 {
		t.Fatalf("trove generated %d write event(s) under fixture root (expected 0):\n  %s",
			len(events), strings.Join(events, "\n  "))
	}

	// Sanity: the config dir SHOULD have been written. If not, we're
	// not actually exercising the save path and the negative check
	// above is meaningless.
	storeFile := filepath.Join(tr.storeDir, "trove", "global.json")
	info, err := os.Stat(storeFile)
	if err != nil {
		t.Fatalf("expected trove to have written %s: %v", storeFile, err)
	}
	if info.Size() == 0 {
		t.Fatalf("trove wrote a 0-byte global.json — save path probably broken")
	}
}

func TestInvariant_FuzzedEndpoints(t *testing.T) {
	fixture := t.TempDir()
	writeFixture(t, fixture, fixtureFiles())

	before := manifestOf(t, fixture)

	tr := startTrove(t, fixture)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tr.rescan.Rescan(ctx)

	// Real IDs from the seeded scan, plus a junk ID, so the fuzzer
	// hits both the "id found" and "id not found" branches.
	realIDs := []string{}
	for _, s := range tr.listSecrets() {
		realIDs = append(realIDs, s.ID)
	}
	if len(realIDs) == 0 {
		t.Fatalf("scan produced no secrets")
	}
	realIDs = append(realIDs, "blake3:does-not-exist", "../../../etc/passwd", "")

	// Deterministic seed so a CI failure is reproducible by re-running
	// with -run TestInvariant_FuzzedEndpoints.
	rng := mathrand.New(mathrand.NewSource(0xF00D))

	const iterations = 250
	for i := 0; i < iterations; i++ {
		id := realIDs[rng.Intn(len(realIDs))]
		body := randomJSON(rng)
		switch rng.Intn(4) {
		case 0:
			tr.do("POST", "/api/secrets/"+url.PathEscape(id)+"/reveal", body)
		case 1:
			tr.do("PUT", "/api/secrets/"+url.PathEscape(id)+"/annotation", body)
		case 2:
			tr.do("POST", "/api/secrets/"+url.PathEscape(id)+"/stale", body)
		case 3:
			tr.do("POST", "/api/secrets/"+url.PathEscape(id)+"/rotated", body)
		}
	}

	after := manifestOf(t, fixture)
	if changed := before.diff(after); len(changed) != 0 {
		t.Fatalf("fuzzed endpoints mutated fixture (%d path(s) changed):\n  %s",
			len(changed), strings.Join(changed, "\n  "))
	}
}

// randomJSON returns a small JSON payload composed of arbitrary keys
// and value types. The fuzzer's job is not to produce *valid* trove
// requests — it's to produce inputs that exercise unhappy paths in the
// handler so we can prove they still don't write to disk.
func randomJSON(rng *mathrand.Rand) []byte {
	switch rng.Intn(6) {
	case 0:
		return []byte("")
	case 1:
		return []byte("{}")
	case 2:
		return []byte("not json at all")
	case 3:
		return []byte(`{"source_index": -1}`)
	case 4:
		return []byte(`{"source_index": 9999999}`)
	case 5:
		// Random JSON object with random keys and values. The keys are
		// drawn from a mix of legitimate annotation fields and pure
		// junk so the unmarshal path sees both well-formed and
		// surprising shapes.
		obj := map[string]any{}
		keys := []string{"source_url", "owner", "notes", "rotate_url", "tags", "stale", "id", "..", "_proto_", strings.Repeat("a", 200)}
		for j := 0; j < rng.Intn(5)+1; j++ {
			k := keys[rng.Intn(len(keys))]
			switch rng.Intn(4) {
			case 0:
				obj[k] = randomString(rng, 32)
			case 1:
				obj[k] = rng.Intn(100000) - 50000
			case 2:
				obj[k] = []string{randomString(rng, 8), randomString(rng, 8)}
			case 3:
				obj[k] = nil
			}
		}
		b, _ := json.Marshal(obj)
		return b
	}
	return []byte("{}")
}

func randomString(rng *mathrand.Rand, n int) string {
	const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_/."
	b := make([]byte, n)
	for i := range b {
		b[i] = alpha[rng.Intn(len(alpha))]
	}
	return string(b)
}

// writeRecorder is a fsnotify watcher specialised for "did anyone write
// under this root?" — it filters out non-write ops and records events
// in a goroutine-safe slice the test can snapshot at the end.
type writeRecorder struct {
	w      *fsnotify.Watcher
	events []string
	mu     sync.Mutex
	closed atomic.Bool
}

func newWriteRecorder(root string) (*writeRecorder, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	r := &writeRecorder{w: w}
	if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return w.Add(p)
		}
		return nil
	}); err != nil {
		_ = w.Close()
		return nil, err
	}
	go r.loop()
	return r, nil
}

// loop drains the watcher's channels until close. Only Write/Create/
// Remove/Rename/Chmod ops count as "trove wrote here"; pure metadata
// reads don't show up at all on Linux, so any event we record is a
// genuine mutation.
func (r *writeRecorder) loop() {
	for {
		select {
		case ev, ok := <-r.w.Events:
			if !ok {
				return
			}
			if r.closed.Load() {
				continue
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename|fsnotify.Chmod) != 0 {
				r.mu.Lock()
				r.events = append(r.events, ev.String())
				r.mu.Unlock()
			}
		case _, ok := <-r.w.Errors:
			if !ok {
				return
			}
		}
	}
}

func (r *writeRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.events))
	copy(out, r.events)
	return out
}

func (r *writeRecorder) close() {
	r.closed.Store(true)
	_ = r.w.Close()
}
