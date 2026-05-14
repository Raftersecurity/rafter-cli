package server

import (
	"encoding/json"
	"net/http"
	"time"
)

// rescanResponse is the wire shape for POST /api/rescan. `accepted`
// distinguishes 202 (we kicked off a new scan) from 409 (one was
// already in flight). `started_at` is RFC3339 in both cases — for 202
// it's "the scan you just asked for" and for 409 it's "the scan
// already running".
type rescanResponse struct {
	StartedAt time.Time `json:"started_at"`
	Accepted  bool      `json:"accepted"`
}

// handleRescan triggers a filesystem rescan. The actual scan runs
// asynchronously inside the rescanner; this handler only kicks it off
// and reports whether it was accepted. Progress events flow through
// the existing SSE stream as scan_started + scan_complete.
//
// Coalescing lives in the Rescan closure: if a scan is already in
// flight the closure returns (in_flight_started_at, false) and this
// handler returns 409 so the UI can show a single "rescanning" state
// regardless of how many clicks land during it.
func (s *Server) handleRescan(w http.ResponseWriter, r *http.Request) {
	if s.rescanFn == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, "rescan not configured")
		return
	}
	started, accepted := s.rescanFn()
	resp := rescanResponse{StartedAt: started.UTC(), Accepted: accepted}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if accepted {
		w.WriteHeader(http.StatusAccepted)
	} else {
		w.WriteHeader(http.StatusConflict)
	}
	_ = json.NewEncoder(w).Encode(&resp)
}
