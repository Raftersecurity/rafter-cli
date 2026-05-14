package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/browser"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/docstore"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/eventbus"
	rescanpkg "github.com/Raftersecurity/rafter-cli/inventory-tool/internal/rescan"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/scan"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/server"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/watch"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/wizard"
)

const defaultIdleTimeout = 30 * time.Minute

func main() {
	var (
		noOpen      = flag.Bool("no-open", false, "do not auto-open browser")
		idleTimeout = flag.Duration("idle-timeout", defaultIdleTimeout, "exit after this long with no client heartbeat")
		rescan      = flag.Bool("rescan", false, "run a filesystem scan and exit (no UI)")
	)
	flag.Parse()

	storePath, err := storage.DefaultPath()
	if err != nil {
		log.Fatalf("trove: resolve store path: %v", err)
	}
	doc, err := storage.Load(storePath)
	if err != nil {
		log.Fatalf("trove: load store: %v", err)
	}

	// First-run gate: if no roots configured, walk the user through
	// the wizard before doing anything else. Persist the result so
	// subsequent launches skip the prompt.
	if len(doc.ScanConfig.Roots) == 0 {
		if err := wizard.FirstRun(os.Stdin, os.Stderr, doc); err != nil {
			log.Fatalf("trove: first-run wizard: %v", err)
		}
		if err := storage.Save(storePath, doc); err != nil {
			log.Fatalf("trove: save store: %v", err)
		}
	}

	if *rescan {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		res, err := scan.Run(ctx, doc, doc.ScanConfig)
		if err != nil {
			log.Fatalf("trove: scan: %v", err)
		}
		if err := storage.Save(storePath, doc); err != nil {
			log.Fatalf("trove: save store: %v", err)
		}
		fmt.Fprintf(os.Stderr,
			"trove: scanned %d file(s); %d secret observation(s); %d error(s)\n",
			res.FilesScanned, res.SecretsFound, len(res.Errors))
		return
	}

	store := docstore.New(doc, func(d *storage.Global) error {
		return storage.Save(storePath, d)
	})

	bus := eventbus.New()

	// The watcher is constructed asynchronously after the URL is printed.
	// NewWithConfig walks every root to register inotify watches; on a
	// busy $HOME that takes minutes, so doing it on the main goroutine
	// would hide the URL for that long. atomic.Pointer keeps the
	// /api/status closure race-free while the bg goroutine swaps it in.
	var wch atomic.Pointer[watch.Watcher]
	var rscn atomic.Pointer[rescanpkg.Rescanner]
	storeDir := filepath.Dir(storePath)

	homeDir, _ := os.UserHomeDir()

	srv, err := server.New(server.Config{
		IdleTimeout: *idleTimeout,
		Bus:         bus,
		Store:       store,
		HomeDir:     homeDir,
		StatusExtras: func() map[string]any {
			extras := map[string]any{}
			if w := wch.Load(); w != nil {
				extras["watch_events_dropped"] = w.EventsDropped()
			}
			return extras
		},
		Rescan: func() (time.Time, bool) {
			r := rscn.Load()
			if r == nil {
				// Watcher/rescanner still booting; report as in-flight
				// from now so the UI surfaces "we're trying" rather than
				// a hard failure during the brief startup window.
				return time.Now(), false
			}
			return r.Trigger(context.Background())
		},
	})
	if err != nil {
		log.Fatalf("trove: %v", err)
	}

	url := srv.URL()
	fmt.Fprintf(os.Stderr, "trove: serving on %s\n", url)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Translate signals into a graceful Shutdown so Run returns cleanly.
	go func() {
		<-ctx.Done()
		shCtx, shCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shCancel()
		_ = srv.Shutdown(shCtx)
	}()

	// Register inotify watches + bring up the rescanner asynchronously.
	// NewWithConfig walks every root to add watches and on a busy $HOME
	// that takes a while; we don't want HTTP and drift events to wait.
	// /api/status omits watch_events_dropped from the extras map until
	// the watcher pointer is assigned.
	go func() {
		w, wErr := watch.NewWithConfig(watch.Config{
			Roots:           doc.ScanConfig.Roots,
			ExcludeDirs:     []string{storeDir},
			ExcludePatterns: doc.ScanConfig.Excludes,
		})
		if wErr != nil {
			fmt.Fprintf(os.Stderr, "trove: watcher partial setup: %v\n", wErr)
		}
		wch.Store(w)
		rs, rsErr := rescanpkg.New(rescanpkg.Config{
			Store:   store,
			Bus:     bus,
			Watcher: w,
			OnError: func(err error) {
				fmt.Fprintf(os.Stderr, "trove: %v\n", err)
			},
		})
		if rsErr != nil {
			fmt.Fprintf(os.Stderr, "trove: rescanner setup: %v\n", rsErr)
		}
		if rs != nil {
			rscn.Store(rs)
			if err := rs.Run(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "trove: watcher exited: %v\n", err)
			}
		}
	}()

	if !*noOpen {
		if err := browser.Open(url); err != nil {
			fmt.Fprintf(os.Stderr, "trove: could not open browser (%v); paste the URL above instead\n", err)
		}
	}

	// Run blocks until lifecycle watchdog, signal handler, or close-beacon
	// triggers a shutdown.
	if err := srv.Run(ctx); err != nil {
		log.Fatalf("trove: server: %v", err)
	}
}
