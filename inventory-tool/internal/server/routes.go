package server

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("/api/close", s.handleClose)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/events", s.handleEvents)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(indexHTML))
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.life.beat()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.life.close()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"version": "0.0.0-scaffold",
		"name":    "trove",
	})
}

// handleEvents is the Server-Sent Events stream for drift updates.
// The connection is held open until the client disconnects or the
// server shuts down; events flow as `data: {json}\n\n` frames.
//
// SSE was chosen over WebSocket because every event is server→client
// and the browser's native EventSource handles auto-reconnect with
// no library code. CSP-wise it's a same-origin GET, no upgrade dance.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if s.bus == nil {
		http.Error(w, "event bus not configured", http.StatusServiceUnavailable)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Comment frame nudges proxies to flush the response head and gives
	// the browser EventSource a definite "stream is open" signal.
	_, _ = fmt.Fprintf(w, ": ok\n\n")
	flusher.Flush()

	ctx := r.Context()
	ch, _ := s.bus.Subscribe(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			payload, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			// One frame per event. The "event:" line lets clients use
			// addEventListener(<type>, ...) to route by Type without
			// parsing the JSON envelope.
			if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, payload); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>trove — scaffold</title>
<style>
  body { font: 14px/1.5 ui-sans-serif, system-ui, sans-serif; max-width: 640px; margin: 4em auto; padding: 0 1em; color: #222; }
  code { background: #f3f3f3; padding: 0.1em 0.3em; border-radius: 3px; }
  .pill { display: inline-block; padding: 2px 8px; border-radius: 999px; background: #eef; font-size: 12px; }
</style>
</head>
<body>
  <h1>trove <span class="pill">scaffold</span></h1>
  <p>Runtime shell only. Scanners, storage, UI not implemented yet.</p>
  <p>Spec: Inventory Tool v1, Rafter 2.0 Secret Management.</p>
  <p>Status endpoint: <code>GET /api/status</code></p>
  <h2>Live drift events</h2>
  <ul id="events" aria-live="polite"></ul>
  <script>
    // Heartbeat every 30s so the binary knows the tab is open.
    setInterval(() => {
      fetch("/api/heartbeat", { method: "POST", credentials: "same-origin" });
    }, 30_000);
    // Close beacon on tab close so the binary exits promptly.
    window.addEventListener("pagehide", () => {
      navigator.sendBeacon("/api/close");
    });
    // Subscribe to drift events. EventSource auto-reconnects on drop.
    const list = document.getElementById("events");
    const es = new EventSource("/api/events");
    const log = (label, data) => {
      const li = document.createElement("li");
      li.textContent = label + ": " + data;
      list.appendChild(li);
      while (list.children.length > 100) list.removeChild(list.firstChild);
    };
    ["scan_started", "scan_complete",
     "secret_created", "secret_refreshed", "secret_drifted"
    ].forEach(t => es.addEventListener(t, e => log(t, e.data)));
  </script>
</body>
</html>
`
