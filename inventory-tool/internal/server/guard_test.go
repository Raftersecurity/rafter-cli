package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// guardedServer wires the full guard→requireToken→routes chain (the real
// production handler order) against an httptest listener.
func guardedServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	s, err := New(Config{IdleTimeout: time.Hour})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = s.listener.Close()
	mux := http.NewServeMux()
	s.routes(mux)
	ts := httptest.NewServer(s.guard(s.requireToken(mux)))
	t.Cleanup(ts.Close)
	return s, ts
}

func TestGuard_RejectsNonLoopbackHost(t *testing.T) {
	s, ts := guardedServer(t)
	req, _ := http.NewRequest("GET", ts.URL+"/api/status", nil)
	req.Header.Set(headerName, s.token)
	req.Host = "evil.example.com" // DNS-rebinding: attacker Host, valid token
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("rebinding Host got %d, want 403", resp.StatusCode)
	}
}

func TestGuard_RejectsForeignOriginOnMutation(t *testing.T) {
	s, ts := guardedServer(t)
	req, _ := http.NewRequest("POST", ts.URL+"/api/heartbeat", nil)
	req.Header.Set(headerName, s.token)
	req.Header.Set("Origin", "https://evil.example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign Origin mutation got %d, want 403", resp.StatusCode)
	}
}

func TestGuard_AllowsLoopback(t *testing.T) {
	s, ts := guardedServer(t)
	// Default Host from httptest is 127.0.0.1:port — loopback, allowed.
	req, _ := http.NewRequest("GET", ts.URL+"/api/status", nil)
	req.Header.Set(headerName, s.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("loopback request got %d, want 200", resp.StatusCode)
	}
}

func TestValidLoopbackHost(t *testing.T) {
	for _, c := range []struct {
		host string
		want bool
	}{
		{"127.0.0.1:4321", true},
		{"localhost:8080", true},
		{"[::1]:9999", true},
		{"127.0.0.2", true},
		{"evil.com", false},
		{"evil.com:1234", false},
		{"169.254.169.254", false},
		{"", false},
	} {
		if got := validLoopbackHost(c.host); got != c.want {
			t.Errorf("validLoopbackHost(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}
