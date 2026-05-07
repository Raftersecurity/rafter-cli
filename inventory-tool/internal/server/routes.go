package server

import (
	"encoding/json"
	"net/http"
)

func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("/api/close", s.handleClose)
	mux.HandleFunc("/api/status", s.handleStatus)
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
  <script>
    // Heartbeat every 30s so the binary knows the tab is open.
    setInterval(() => {
      fetch("/api/heartbeat", { method: "POST", credentials: "same-origin" });
    }, 30_000);
    // Close beacon on tab close so the binary exits promptly.
    window.addEventListener("pagehide", () => {
      navigator.sendBeacon("/api/close");
    });
  </script>
</body>
</html>
`
