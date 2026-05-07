package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestServer returns a Server with the in-memory test http.Server set up
// against an httptest.Server so we can exercise the auth middleware.
func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	s, err := New(Config{IdleTimeout: time.Hour})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Replace the real listener with httptest's so we control the URL.
	_ = s.listener.Close()
	mux := http.NewServeMux()
	s.routes(mux)
	ts := httptest.NewServer(s.requireToken(mux))
	t.Cleanup(ts.Close)
	return s, ts
}

func TestAuth_NoTokenReturns401(t *testing.T) {
	_, ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
}

func TestAuth_HeaderTokenAccepted(t *testing.T) {
	s, ts := newTestServer(t)
	req, _ := http.NewRequest("GET", ts.URL+"/api/status", nil)
	req.Header.Set(headerName, s.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
}

func TestAuth_QueryTokenRedirectsAndSetsCookie(t *testing.T) {
	s, ts := newTestServer(t)
	// httptest client follows redirects by default; disable so we can inspect.
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Get(ts.URL + "/?token=" + s.token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("got %d, want 303", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if strings.Contains(loc, "token=") {
		t.Fatalf("redirect Location still contains token: %q", loc)
	}
	var found bool
	for _, c := range resp.Cookies() {
		if c.Name == cookieName && c.Value == s.token {
			found = true
		}
	}
	if !found {
		t.Fatalf("session cookie not set on query-token auth")
	}
}

func TestAuth_WrongTokenRejected(t *testing.T) {
	_, ts := newTestServer(t)
	req, _ := http.NewRequest("GET", ts.URL+"/api/status", nil)
	req.Header.Set(headerName, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token accepted: got %d, want 401", resp.StatusCode)
	}
}
