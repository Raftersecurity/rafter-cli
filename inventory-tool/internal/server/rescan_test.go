package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// newTestServerWithRescan returns a server whose Rescan closure
// captures call counts + returns a configurable (started, accepted)
// tuple so each test can exercise both the 202 and 409 paths.
func newTestServerWithRescan(t *testing.T, fn func() (time.Time, bool)) (*Server, *httptest.Server) {
	t.Helper()
	s, err := New(Config{
		IdleTimeout: time.Hour,
		Rescan:      fn,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = s.listener.Close()
	mux := http.NewServeMux()
	s.routes(mux)
	ts := httptest.NewServer(s.requireToken(mux))
	t.Cleanup(ts.Close)
	return s, ts
}

func TestRescan_ReturnsAccepted(t *testing.T) {
	now := time.Now().UTC()
	s, ts := newTestServerWithRescan(t, func() (time.Time, bool) { return now, true })
	req := authedReq(t, "POST", ts.URL+"/api/rescan", s.token, nil)
	body := doJSON(t, req, http.StatusAccepted)
	var resp rescanResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.Accepted {
		t.Errorf("Accepted: got false, want true")
	}
	if !resp.StartedAt.Equal(now) {
		t.Errorf("StartedAt: got %v, want %v", resp.StartedAt, now)
	}
}

func TestRescan_409WhenAlreadyInFlight(t *testing.T) {
	in := time.Now().UTC().Add(-2 * time.Second)
	s, ts := newTestServerWithRescan(t, func() (time.Time, bool) { return in, false })
	req := authedReq(t, "POST", ts.URL+"/api/rescan", s.token, nil)
	body := doJSON(t, req, http.StatusConflict)
	var resp rescanResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Accepted {
		t.Errorf("Accepted: got true, want false")
	}
	if !resp.StartedAt.Equal(in) {
		t.Errorf("StartedAt: got %v, want %v (in-flight time)", resp.StartedAt, in)
	}
}

func TestRescan_AuthRequired(t *testing.T) {
	_, ts := newTestServerWithRescan(t, func() (time.Time, bool) { return time.Now(), true })
	req, _ := http.NewRequest("POST", ts.URL+"/api/rescan", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", resp.StatusCode)
	}
}

func TestRescan_503WhenNotConfigured(t *testing.T) {
	s, err := New(Config{IdleTimeout: time.Hour})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = s.listener.Close()
	mux := http.NewServeMux()
	s.routes(mux)
	ts := httptest.NewServer(s.requireToken(mux))
	defer ts.Close()
	req := authedReq(t, "POST", ts.URL+"/api/rescan", s.token, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("got %d, want 503", resp.StatusCode)
	}
}

// Concurrent POSTs against the same Rescan closure: ensure the
// handler doesn't add its own serialization on top of the closure's
// (the closure is the source of truth for coalescing).
func TestRescan_HandlerDoesNotSerializeCalls(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	fn := func() (time.Time, bool) {
		mu.Lock()
		calls++
		mu.Unlock()
		return time.Now(), true
	}
	s, ts := newTestServerWithRescan(t, fn)
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := authedReq(t, "POST", ts.URL+"/api/rescan", s.token, nil)
			_ = doJSON(t, req, http.StatusAccepted)
		}()
	}
	wg.Wait()
	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 5 {
		t.Errorf("expected 5 calls to Rescan closure, got %d", got)
	}
}
