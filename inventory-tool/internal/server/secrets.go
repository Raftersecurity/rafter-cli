// HTTP handlers for the secrets inventory API.
//
// All handlers acquire the docstore.Store's lock for the duration of
// the read or mutation; the rescanner uses the same lock so a click
// in the UI during a rescan blocks briefly rather than racing the
// scanner.
//
// Auth is handled by the surrounding requireToken middleware: every
// handler here can assume the request carries a valid session.

package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/scan"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
)

// secretsListResponse is the wire shape for GET /api/secrets. The
// `secrets` slice is a deep-enough copy of the doc's secrets that
// callers don't accidentally hold pointers into the live slice; the
// other fields are read-only summaries.
type secretsListResponse struct {
	Secrets      []storage.Secret   `json:"secrets"`
	ScanConfig   storage.ScanConfig `json:"scan_config"`
	RevealPolicy string             `json:"reveal_policy"`
}

func (s *Server) handleSecretsList(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "store not configured", http.StatusServiceUnavailable)
		return
	}
	// Marshal under the docstore lock so the snapshot is consistent
	// across concurrent Upserts; do the network write outside the
	// lock so a slow client can't stall the rescanner.
	var buf bytes.Buffer
	var marshalErr error
	s.store.Read(func(g *storage.Global) {
		resp := secretsListResponse{
			Secrets:      g.Secrets,
			ScanConfig:   g.ScanConfig,
			RevealPolicy: g.RevealPolicy,
		}
		marshalErr = json.NewEncoder(&buf).Encode(&resp)
	})
	if marshalErr != nil {
		writeJSONErr(w, http.StatusInternalServerError, "marshal: "+marshalErr.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

type revealRequest struct {
	// SourceIndex selects which entry of found_in[] to read. Defaults
	// to the first file-source. Out-of-range or non-file sources
	// produce 422.
	SourceIndex *int `json:"source_index,omitempty"`
}

type revealResponse struct {
	Value      string `json:"value"`
	SourceType string `json:"source_type"`
	Path       string `json:"path,omitempty"`
}

func (s *Server) handleSecretReveal(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "store not configured", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	var req revealRequest
	// Body is optional. A missing/empty body → default source index.
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}
	}

	var (
		keyName string
		found   storage.FoundIn
		ok      bool
	)
	s.store.Read(func(g *storage.Global) {
		for i := range g.Secrets {
			if g.Secrets[i].ID != id {
				continue
			}
			sec := &g.Secrets[i]
			keyName = sec.KeyName
			idx := 0
			if req.SourceIndex != nil {
				idx = *req.SourceIndex
			} else {
				// Default: first file source. Fall back to index 0 if
				// no file source exists so the unsupported branch hits
				// for keystore-only secrets.
				for j, f := range sec.FoundIn {
					if f.Path != "" {
						idx = j
						break
					}
				}
			}
			if idx < 0 || idx >= len(sec.FoundIn) {
				return
			}
			found = sec.FoundIn[idx]
			ok = true
			return
		}
	})
	if !ok {
		http.Error(w, "secret not found", http.StatusNotFound)
		return
	}

	// File reads happen outside the docstore lock so a slow disk
	// doesn't stall a concurrent rescan or annotate request.
	value, err := scan.ResolveValue(found, keyName)
	switch {
	case errors.Is(err, scan.ErrUnsupportedSource):
		writeJSONErr(w, http.StatusUnprocessableEntity, "source not supported for reveal")
		return
	case errors.Is(err, scan.ErrSecretNotFound):
		writeJSONErr(w, http.StatusGone, "value not present at source — drift may not be rescanned yet")
		return
	case err != nil:
		writeJSONErr(w, http.StatusInternalServerError, "reveal failed: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(revealResponse{
		Value:      value,
		SourceType: found.SourceType,
		Path:       found.Path,
	})
}

// annotationPatch is the wire shape for PUT /api/secrets/{id}/annotation.
// The Stale flag is intentionally NOT included — toggling stale is a
// distinct user gesture (mark stale / un-stale via a future undo) and
// is exposed through dedicated endpoints, not piggy-backed on free-form
// edits.
type annotationPatch struct {
	SourceURL string   `json:"source_url"`
	Owner     string   `json:"owner"`
	Notes     string   `json:"notes"`
	RotateURL string   `json:"rotate_url"`
	Tags      []string `json:"tags"`
}

func (s *Server) handleSecretAnnotate(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "store not configured", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	var p annotationPatch
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	// Normalise: tags slice is always serialised as an array (per
	// schema), so a missing tags key arrives as nil — convert to empty.
	if p.Tags == nil {
		p.Tags = []string{}
	}

	var found bool
	if err := s.store.Update(func(g *storage.Global) bool {
		for i := range g.Secrets {
			if g.Secrets[i].ID != id {
				continue
			}
			a := &g.Secrets[i].Annotation
			a.SourceURL = p.SourceURL
			a.Owner = p.Owner
			a.Notes = p.Notes
			a.RotateURL = p.RotateURL
			a.Tags = p.Tags
			// Stale is preserved; only the dedicated endpoint flips it.
			found = true
			return true
		}
		return false
	}); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "save failed: "+err.Error())
		return
	}
	if !found {
		http.Error(w, "secret not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSecretMarkStale(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "store not configured", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	var ok bool
	if err := s.store.Update(func(g *storage.Global) bool {
		ok = g.MarkStale(id)
		return ok
	}); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "save failed: "+err.Error())
		return
	}
	if !ok {
		http.Error(w, "secret not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSecretMarkRotated(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "store not configured", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	var ok bool
	if err := s.store.Update(func(g *storage.Global) bool {
		ok = g.MarkRotated(id, now)
		return ok
	}); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "save failed: "+err.Error())
		return
	}
	if !ok {
		http.Error(w, "secret not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeJSONErr writes a small {"error": "..."} envelope at the given
// status. Plain http.Error sets text/plain, which the in-page client
// can't pull a structured message out of.
func writeJSONErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
