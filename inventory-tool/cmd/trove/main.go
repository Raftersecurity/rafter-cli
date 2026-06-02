package main

import (
	"context"
	"errors"
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

	// Give the process as many file descriptors as the OS will allow
	// before the watcher starts opening them. macOS defaults the soft
	// limit to 256, which a whole-disk watch blows through almost
	// instantly; raising soft→hard buys the headroom the watcher cap
	// then bounds. Best-effort — a failure here just means we lean
	// harder on the cap.
	if _, err := raiseFileLimit(); err != nil {
		fmt.Fprintf(os.Stderr, "trove: could not raise open-file limit (%v); continuing with watch caps\n", err)
	}

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
	srv, err := server.New(server.Config{
		IdleTimeout: *idleTimeout,
		Bus:         bus,
		Store:       store,
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

	// Bring up the fsnotify drift watcher. A partial-setup error
	// (e.g. one root unreadable) is logged but doesn't abort: the
	// other roots are still watched, and the user can fix config
	// without restarting.
	// Exclude the trove store directory itself from the watcher; if a
	// scan root is set to $HOME (the spec default), the store-save
	// landing under ~/.config/trove would otherwise re-fire the
	// watcher and loop forever.
	storeDir := filepath.Dir(storePath)
	wch, wchErr := watch.NewWithConfig(watch.Config{
		Roots:       doc.ScanConfig.Roots,
		ExcludeDirs: []string{storeDir},
		// Hand the watcher the SAME excludes the scanner uses so it
		// prunes node_modules/.git/caches/Library instead of opening a
		// file descriptor for every one of them. Without this a $HOME-
		// wide scope exhausts FDs and the UI dies with "too many open
		// files" — the exact failure reported on a whole-disk run.
		Excludes: doc.ScanConfig.Excludes,
	})
	if errors.Is(wchErr, watch.ErrWatchLimit) {
		fmt.Fprintf(os.Stderr, "trove: watching a subset of your scan scope (%s); trove will still re-scan periodically and on changes it can see. Narrow your scan roots in settings for full live coverage.\n", wchErr)
	} else if wchErr != nil {
		fmt.Fprintf(os.Stderr, "trove: watcher partial setup: %v\n", wchErr)
	}

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
		// Kick off one scan immediately so the UI shows the current
		// inventory on launch instead of an empty list that only fills
		// in when a watched file later changes. Runs in the background
		// so the server is already accepting connections (and the SSE
		// scan_started/scan_complete frames drive the UI's loading
		// state) while a large $HOME is walked.
		go rs.Rescan(ctx)
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
