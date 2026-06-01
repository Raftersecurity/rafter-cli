package server

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// routes wires every URL pattern handled by the trove HTTP surface.
//
// Patterns use Go 1.22's method-aware ServeMux so the per-handler
// method check is enforced declaratively. Unlisted methods on listed
// paths fall through to 405; unlisted paths fall through to 404.
func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("POST /api/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("POST /api/close", s.handleClose)
	mux.HandleFunc("GET /api/events", s.handleEvents)

	mux.HandleFunc("GET /api/secrets", s.handleSecretsList)
	mux.HandleFunc("POST /api/secrets/{id}/reveal", s.handleSecretReveal)
	mux.HandleFunc("PUT /api/secrets/{id}/annotation", s.handleSecretAnnotate)
	mux.HandleFunc("POST /api/secrets/{id}/stale", s.handleSecretMarkStale)
	mux.HandleFunc("POST /api/secrets/{id}/rotated", s.handleSecretMarkRotated)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// Lock the page down to its own origin. The load-bearing directive is
	// connect-src 'self': the UI reveals plaintext secrets, so even if an
	// XSS slipped past the textContent/escapeHtml discipline in app.js, the
	// browser would refuse to ship those values to any other host — the
	// "nothing leaves this computer" promise enforced below the JS layer.
	// 'unsafe-inline' is needed only for style (the embedded <style> block
	// and a handful of inline style attributes); scripts stay 'self' with
	// no inline-script escape hatch.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; "+
			"script-src 'self'; "+
			"style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data:; "+
			"connect-src 'self'; "+
			"base-uri 'none'; "+
			"form-action 'none'; "+
			"frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	_, _ = w.Write(indexHTML)
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	s.life.beat()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleClose(w http.ResponseWriter, r *http.Request) {
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
