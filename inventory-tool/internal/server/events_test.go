package server

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/eventbus"
)

// newTestServerWithBus is the eventbus-aware twin of newTestServer.
// We can't share the helper because newTestServer constructs Server
// with no bus, and SSE-related tests need one wired in.
func newTestServerWithBus(t *testing.T, bus *eventbus.Bus) (*Server, *httptest.Server) {
	t.Helper()
	s, err := New(Config{IdleTimeout: time.Hour, Bus: bus})
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

func TestEvents_StreamsPublishedEvents(t *testing.T) {
	bus := eventbus.New()
	s, ts := newTestServerWithBus(t, bus)

	req, _ := http.NewRequest("GET", ts.URL+"/api/events", nil)
	req.Header.Set(headerName, s.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/events: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", got)
	}

	// Wait for the bus to register the subscriber before publishing,
	// otherwise the event is dropped on the floor.
	deadline := time.Now().Add(time.Second)
	for bus.SubscriberCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("server never subscribed to bus")
		}
		time.Sleep(5 * time.Millisecond)
	}

	bus.Publish(eventbus.Event{Type: eventbus.EventSecretCreated, KeyName: "FOO"})

	// Read frames until we find one with our event type.
	rdr := bufio.NewReader(resp.Body)
	deadline = time.Now().Add(2 * time.Second)
	var sawEvent, sawData bool
	for time.Now().Before(deadline) {
		line, err := rdr.ReadString('\n')
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "event: "+eventbus.EventSecretCreated {
			sawEvent = true
		}
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, `"key_name":"FOO"`) {
			sawData = true
		}
		if sawEvent && sawData {
			return
		}
	}
	t.Fatalf("did not see event/data frame within deadline (event=%v data=%v)", sawEvent, sawData)
}

func TestEvents_NoBusReturns503(t *testing.T) {
	s, ts := newTestServer(t)
	req, _ := http.NewRequest("GET", ts.URL+"/api/events", nil)
	req.Header.Set(headerName, s.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}
