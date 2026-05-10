// Package perf is the performance-budget side of trove's behavior tests.
// It stands up a real HTTP server, a real fsnotify-driven rescanner, and
// a noise generator that simulates a busy $HOME, then asserts that
// /api/secrets reads stay inside their P50/P95/P99 budgets.
//
// This test is intentionally heavy (multiple seconds) and gated by
// -short so unit-test loops aren't slowed down. CI runs it without
// -short. The real-world bug it pins: on a noisy filesystem the
// rescanner used to hold the doc lock for the whole scan, blocking
// every concurrent HTTP read; this fixture reproduces that by spamming
// 2000 fs events/second under a scan root and watching read latencies.
package perf_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/docstore"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/eventbus"
	rescanpkg "github.com/Raftersecurity/rafter-cli/inventory-tool/internal/rescan"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/server"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/watch"
)

const (
	noiseDuration   = 3 * time.Second
	noiseRatePerSec = 2000
	probeCount      = 100
	probeInterval   = 30 * time.Millisecond
	probeDeadline   = time.Second

	budgetP50 = 50 * time.Millisecond
	budgetP95 = 200 * time.Millisecond
	budgetP99 = 500 * time.Millisecond
)

// TestWatcher_HTTPLatencyUnderChurn reproduces the production hang where
// /api/secrets times out on a busy $HOME. Pre-fix, the rescanner held
// the doc mutex during scan, so concurrent HTTP reads queued behind it
// for seconds at a time; this test fails (P95 budget violation or 5xx /
// timeout) on that revision and passes once the lock-free read path +
// bounded rescan land.
func TestWatcher_HTTPLatencyUnderChurn(t *testing.T) {
	if testing.Short() {
		t.Skip("perf test skipped under -short")
	}

	root := t.TempDir()
	seedSecrets(t, root)
	// Bulk fixture: enough secret-bearing files that scan.Run takes
	// long enough for the lock-hold-during-scan bug to bite. On the
	// pre-fix code each Rescan holds the doc lock for the duration of
	// scan.Run, which on a real $HOME means seconds; here we approximate
	// that with ~200 .env files so each scan takes 50-150ms. Probes that
	// land during one of those scans block on the lock.
	seedBulkSecrets(t, root, 600)

	// Noise subtree lives inside the scan root so the watcher actually
	// fires on it. The store dir is excluded so save→event→rescan can't
	// loop the way it does in main.
	busyDir := filepath.Join(root, "busy")
	if err := os.Mkdir(busyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	storeDir := filepath.Join(t.TempDir(), "store")
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	storePath := filepath.Join(storeDir, "global.json")

	doc := storage.Empty()
	doc.ScanConfig.Roots = []string{root}
	doc.ScanConfig.Excludes = []string{} // noise dir intentionally NOT excluded — that's the worst case.

	store := docstore.New(doc, func(g *storage.Global) error {
		return storage.Save(storePath, g)
	})
	bus := eventbus.New()

	// Wire a real watcher + rescanner against the doc.
	wch, err := watch.NewWithConfig(watch.Config{
		Roots:       doc.ScanConfig.Roots,
		Debounce:    100 * time.Millisecond,
		ExcludeDirs: []string{storeDir},
	})
	if err != nil {
		t.Fatalf("watch.New: %v", err)
	}
	rs, err := rescanpkg.New(rescanpkg.Config{
		Store:   store,
		Bus:     bus,
		Watcher: wch,
	})
	if err != nil {
		t.Fatalf("rescan.New: %v", err)
	}

	rsCtx, rsCancel := context.WithCancel(context.Background())
	defer rsCancel()
	go func() { _ = rs.Run(rsCtx) }()

	// Prime the doc with a real scan so /api/secrets has something to
	// return.
	rs.Rescan(rsCtx)

	// Drive rescans in a tight loop concurrently with the noise. This
	// stands in for the production pattern where bursty fs activity has
	// occasional lulls long enough for the watcher's debounce timer to
	// fire — without it, the noise generator alone would never let the
	// timer expire, and the bug (lock held during scan) wouldn't bite.
	driverCtx, driverCancel := context.WithCancel(rsCtx)
	defer driverCancel()
	driverDone := make(chan struct{})
	go func() {
		defer close(driverDone)
		for {
			if driverCtx.Err() != nil {
				return
			}
			rs.Rescan(driverCtx)
		}
	}()
	t.Cleanup(func() {
		driverCancel()
		<-driverDone
	})

	srv, err := server.New(server.Config{
		IdleTimeout: time.Hour,
		Bus:         bus,
		Store:       store,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	srvCtx, srvCancel := context.WithCancel(context.Background())
	defer srvCancel()
	go func() { _ = srv.Run(srvCtx) }()
	t.Cleanup(func() {
		shCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shCtx)
	})

	baseURL, token := parseLaunchURL(t, srv.URL())

	// Spawn the noise generator: ~2000 fs ops/sec for noiseDuration.
	noiseCtx, noiseCancel := context.WithTimeout(context.Background(), noiseDuration)
	defer noiseCancel()
	noiseDone := make(chan struct{})
	go runNoise(noiseCtx, busyDir, noiseDone)

	// Probe loop: probeCount GETs at probeInterval, recording latency.
	durations := make([]time.Duration, 0, probeCount)
	var (
		statusErrs int32
		clientErrs int32
	)
	client := &http.Client{Timeout: probeDeadline}
	probeStart := time.Now()
	for i := 0; i < probeCount; i++ {
		nextAt := probeStart.Add(time.Duration(i) * probeInterval)
		if d := time.Until(nextAt); d > 0 {
			time.Sleep(d)
		}
		req, _ := http.NewRequest("GET", baseURL+"/api/secrets", nil)
		req.Header.Set("X-Trove-Token", token)
		t0 := time.Now()
		resp, err := client.Do(req)
		dt := time.Since(t0)
		durations = append(durations, dt)
		if err != nil {
			atomic.AddInt32(&clientErrs, 1)
			continue
		}
		if resp.StatusCode >= 500 {
			atomic.AddInt32(&statusErrs, 1)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	// Stop noise BEFORE asserting; the unwedge phase below proves
	// the system gets back to fast even if it's still recovering.
	noiseCancel()
	<-noiseDone

	if e := atomic.LoadInt32(&clientErrs); e > 0 {
		t.Errorf("client errors / timeouts: %d / %d", e, probeCount)
	}
	if e := atomic.LoadInt32(&statusErrs); e > 0 {
		t.Errorf("5xx responses: %d / %d", e, probeCount)
	}

	p50 := percentile(durations, 50)
	p95 := percentile(durations, 95)
	p99 := percentile(durations, 99)
	t.Logf("under-churn latency: P50=%v P95=%v P99=%v (n=%d, noise=%d/s)",
		p50, p95, p99, len(durations), noiseRatePerSec)

	if p50 > budgetP50 {
		t.Errorf("under-churn P50 = %v, want < %v", p50, budgetP50)
	}
	if p95 > budgetP95 {
		t.Errorf("under-churn P95 = %v, want < %v", p95, budgetP95)
	}
	if p99 > budgetP99 {
		t.Errorf("under-churn P99 = %v, want < %v", p99, budgetP99)
	}

	// Unwedge phase: with the noise + rescan driver stopped, 50 reads
	// should consistently land under 50ms p95 — proves the system isn't
	// stuck in a permanent stall. We cancel the driver first so the
	// only thing competing for CPU is whatever rescan was in-flight at
	// the time of cancel.
	driverCancel()
	<-driverDone
	time.Sleep(2 * time.Second) // let any in-flight rescan finish + bus drain
	post := make([]time.Duration, 0, 50)
	for i := 0; i < 50; i++ {
		req, _ := http.NewRequest("GET", baseURL+"/api/secrets", nil)
		req.Header.Set("X-Trove-Token", token)
		t0 := time.Now()
		resp, err := client.Do(req)
		dt := time.Since(t0)
		if err != nil {
			t.Fatalf("post-noise probe %d failed: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		post = append(post, dt)
	}
	postP95 := percentile(post, 95)
	t.Logf("post-churn latency: P95=%v (n=%d)", postP95, len(post))
	if postP95 > 50*time.Millisecond {
		t.Errorf("post-churn P95 = %v, want < 50ms (system did not unwedge)", postP95)
	}
}

// runNoise spams Create / Truncate / Remove on files under dir until
// ctx is cancelled, targeting roughly noiseRatePerSec ops/second. The
// exact rate isn't critical — the goal is to keep fsnotify saturated.
func runNoise(ctx context.Context, dir string, done chan<- struct{}) {
	defer close(done)
	tickEvery := time.Second / time.Duration(noiseRatePerSec)
	if tickEvery < time.Microsecond {
		tickEvery = time.Microsecond
	}
	ticker := time.NewTicker(tickEvery)
	defer ticker.Stop()
	var i int
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			path := filepath.Join(dir, fmt.Sprintf("n%d", i%128))
			i++
			if i%2 == 0 {
				_ = os.WriteFile(path, []byte("noise"), 0o644)
			} else {
				_ = os.Remove(path)
			}
		}
	}
}

// seedBulkSecrets writes n distinct .env files under root, each with a
// unique key=value pair. Used to inflate scan.Run's wall time so the
// lock-hold-during-scan bug shows up at the HTTP layer.
func seedBulkSecrets(t *testing.T, root string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("svc%03d.env", i)
		body := fmt.Sprintf("API_KEY_%03d=key_%03d_abcdef1234567890\n", i, i)
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// seedSecrets drops six dotenv-style secret files into root so the
// inventory has real content to serialise on each /api/secrets read.
func seedSecrets(t *testing.T, root string) {
	t.Helper()
	files := map[string]string{
		".env":         "API_KEY=abcdef1234567890\n",
		".env.local":   "DB_PASSWORD=password-not-a-secret-1234\n",
		"app.env":      "STRIPE_KEY=sk_test_abcdef1234567890\n",
		"backend.env":  "JWT_SECRET=jwt-secret-value-1234567890\n",
		"frontend.env": "NEXT_PUBLIC_KEY=pub_key_1234567890_abc\n",
		"worker.env":   "REDIS_URL=redis://user:pass@host:6379\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// parseLaunchURL splits the server's launch URL ("http://127.0.0.1:N/
// ?token=...") into a base URL and the token. The launch URL is the
// only public way to recover the random session token from outside the
// server package.
func parseLaunchURL(t *testing.T, raw string) (base, token string) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	tok := u.Query().Get("token")
	if tok == "" {
		t.Fatalf("server URL has no token: %q", raw)
	}
	u.RawQuery = ""
	u.Path = ""
	return u.String(), tok
}

// percentile returns the pth percentile of ds (linear interpolation
// not needed at probeCount=100). Returns 0 when ds is empty.
func percentile(ds []time.Duration, p int) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	cp := make([]time.Duration, len(ds))
	copy(cp, ds)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	idx := (p * len(cp)) / 100
	if idx >= len(cp) {
		idx = len(cp) - 1
	}
	return cp[idx]
}
