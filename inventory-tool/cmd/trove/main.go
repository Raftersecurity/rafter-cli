package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
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

	// Watcher is constructed before the server so the status endpoint
	// can read its events_dropped counter even if the rescanner
	// couldn't fully wire up (e.g. one root unreadable).
	storeDir := filepath.Dir(storePath)
	wch, wchErr := watch.NewWithConfig(watch.Config{
		Roots:           doc.ScanConfig.Roots,
		ExcludeDirs:     []string{storeDir},
		ExcludePatterns: doc.ScanConfig.Excludes,
	})
	if wchErr != nil {
		fmt.Fprintf(os.Stderr, "trove: watcher partial setup: %v\n", wchErr)
	}

	srv, err := server.New(server.Config{
		IdleTimeout: *idleTimeout,
		Bus:         bus,
		Store:       store,
		StatusExtras: func() map[string]any {
			extras := map[string]any{}
			if wch != nil {
				extras["watch_events_dropped"] = wch.EventsDropped()
			}
			return extras
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

	// Bring up the rescanner. The watcher is already constructed above
	// (before the server) so /api/status can surface its dropped-event
	// counter. A partial watcher-setup error (e.g. one root unreadable)
	// is logged but doesn't abort: the other roots are still watched,
	// and the user can fix config without restarting.
	rs, rsErr := rescanpkg.New(rescanpkg.Config{
		Store:   store,
		Bus:     bus,
		Watcher: wch,
		OnError: func(err error) {
			fmt.Fprintf(os.Stderr, "trove: %v\n", err)
		},
	})
	if rsErr != nil {
		fmt.Fprintf(os.Stderr, "trove: watcher partial setup: %v\n", rsErr)
	}
	if rs != nil {
		go func() {
			if err := rs.Run(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "trove: watcher exited: %v\n", err)
			}
		}()
	}

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
