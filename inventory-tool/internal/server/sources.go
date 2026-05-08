// Source-level remediation handlers.
//
// Distinct from secrets.go (which is keyed on secret IDs): a "source"
// is a file on disk where one or more secrets live. Tightening file
// mode is a property of the path, not the secret, so the surface here
// is path-keyed.
//
// Note on the zero-mutation invariant: trove's read-only guarantee is
// about *content* of secret-bearing files. chmod 0600 strictly tightens
// access (never widens) and never changes a single byte of the file —
// the byte-identity assertion in tests/invariant/ continues to hold.
// The static lint in scripts/no-write-syscalls.sh deliberately scopes
// out internal/server, so a deliberate, user-initiated remediation is
// allowed here while scanners stay strictly read-only.

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
)

// chmod600Request carries the source path the user wants tightened.
// Only paths already known to trove (i.e. recorded in some secret's
// FoundIn) are honoured — this prevents the endpoint from being a
// generic chmod gadget for arbitrary filesystem paths.
type chmod600Request struct {
	Path string `json:"path"`
}

type chmod600Response struct {
	Path        string `json:"path"`
	Permissions string `json:"permissions"`
	NoOp        bool   `json:"no_op,omitempty"`
}

const chmod600Mode fs.FileMode = 0o600

func (s *Server) handleSourceChmod600(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "store not configured", http.StatusServiceUnavailable)
		return
	}
	var req chmod600Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if req.Path == "" {
		writeJSONErr(w, http.StatusBadRequest, "missing path")
		return
	}

	// Only paths trove already knows about are eligible. This is the
	// safety gate: without it, an attacker who somehow obtained the
	// session token could chmod any file on the host.
	known := false
	s.store.Read(func(g *storage.Global) {
		for i := range g.Secrets {
			for _, f := range g.Secrets[i].FoundIn {
				if f.Path == req.Path {
					known = true
					return
				}
			}
		}
	})
	if !known {
		writeJSONErr(w, http.StatusNotFound, "path not in inventory")
		return
	}

	info, err := os.Stat(req.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeJSONErr(w, http.StatusNotFound, "file no longer exists")
			return
		}
		writeJSONErr(w, http.StatusInternalServerError, "stat: "+err.Error())
		return
	}
	if !info.Mode().IsRegular() {
		writeJSONErr(w, http.StatusUnprocessableEntity, "not a regular file")
		return
	}

	noop := info.Mode().Perm() == chmod600Mode
	if !noop {
		if err := os.Chmod(req.Path, chmod600Mode); err != nil {
			writeJSONErr(w, http.StatusInternalServerError, "chmod: "+err.Error())
			return
		}
	}

	// Refresh in-doc permissions so the UI reflects the change without
	// waiting for the watcher-triggered rescan to roll the value in.
	// The drift watcher will still observe the chmod event, debounce,
	// and rescan — that pass is idempotent because Upsert just folds in
	// the same permissions string we just wrote.
	newPerms := fmt.Sprintf("%04o", chmod600Mode)
	_ = s.store.Update(func(g *storage.Global) bool {
		changed := false
		for i := range g.Secrets {
			for j := range g.Secrets[i].FoundIn {
				f := &g.Secrets[i].FoundIn[j]
				if f.Path == req.Path && f.Permissions != newPerms {
					f.Permissions = newPerms
					changed = true
				}
			}
		}
		return changed
	})

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(chmod600Response{
		Path:        req.Path,
		Permissions: newPerms,
		NoOp:        noop,
	})
}
