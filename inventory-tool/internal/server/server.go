package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/docstore"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/eventbus"
)

type Config struct {
	// IdleTimeout: exit after this long with no client heartbeat.
	IdleTimeout time.Duration

	// Bus, if non-nil, is the source for the /api/events SSE stream.
	// The route is registered unconditionally; with no bus configured
	// it returns 503 so a misconfigured launch fails loudly instead of
	// silently dropping drift updates on the floor.
	Bus *eventbus.Bus

	// Store, if non-nil, is the doc the secrets API reads and mutates.
	// /api/secrets and friends return 503 when nil; this matches Bus's
	// "fail loud" pattern for misconfigured launches.
	Store *docstore.Store
}

type Server struct {
	httpSrv  *http.Server
	listener net.Listener
	token    string
	url      string
	life     *lifecycle
	bus      *eventbus.Bus
	store    *docstore.Store
}

// New binds to a random port on 127.0.0.1 and prepares (but does not start)
// the HTTP server. Call Run to serve.
func New(cfg Config) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("bind localhost: %w", err)
	}

	tok, err := randomToken(32)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("session token: %w", err)
	}

	s := &Server{
		listener: ln,
		token:    tok,
		life:     newLifecycle(cfg.IdleTimeout),
		bus:      cfg.Bus,
		store:    cfg.Store,
	}
	addr := ln.Addr().(*net.TCPAddr)
	s.url = fmt.Sprintf("http://127.0.0.1:%d/?token=%s", addr.Port, tok)

	mux := http.NewServeMux()
	s.routes(mux)

	s.httpSrv = &http.Server{
		Handler:           s.requireToken(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s, nil
}

func (s *Server) URL() string { return s.url }

// Run serves HTTP until ctx is cancelled or the lifecycle watchdog fires.
func (s *Server) Run(ctx context.Context) error {
	go s.life.watch(ctx, func() {
		// Idle timeout: trigger graceful shutdown.
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(shCtx)
	})

	// Mark heartbeat now so the idle watchdog has a starting point.
	s.life.beat()

	err := s.httpSrv.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

func randomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
