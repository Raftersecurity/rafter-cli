package watch

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestNew_RegistersAllSubdirs(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "a", "b", "c"), 0o755); err != nil {
		t.Fatal(err)
	}
	w, err := New([]string{root}, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()
	got := len(w.added)
	// root + a + a/b + a/b/c = 4
	if got != 4 {
		t.Errorf("watched dirs = %d, want 4", got)
	}
}

func TestRun_DebouncesEvents(t *testing.T) {
	root := t.TempDir()
	w, err := New([]string{root}, 80*time.Millisecond)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var fires int32
	done := make(chan struct{})
	go func() {
		_ = w.Run(ctx, func() {
			atomic.AddInt32(&fires, 1)
		}, nil)
		close(done)
	}()

	// Three rapid writes should collapse into one onChange call.
	for i := 0; i < 3; i++ {
		path := filepath.Join(root, "f")
		if err := os.WriteFile(path, []byte{byte(i)}, 0o644); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Wait for debounce + slack.
	time.Sleep(250 * time.Millisecond)

	if got := atomic.LoadInt32(&fires); got != 1 {
		t.Errorf("debounced fires = %d, want 1", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestRun_PicksUpNewSubdirectory(t *testing.T) {
	root := t.TempDir()
	w, err := New([]string{root}, 80*time.Millisecond)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fires := make(chan struct{}, 8)
	done := make(chan struct{})
	go func() {
		_ = w.Run(ctx, func() {
			select {
			case fires <- struct{}{}:
			default:
			}
		}, nil)
		close(done)
	}()

	// Create a subdir, then create a file inside it. The watcher must
	// have added the subdir on its Create event so the inner file
	// generates an event we see.
	sub := filepath.Join(root, "newsub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// Drain the first onChange caused by the mkdir.
	select {
	case <-fires:
	case <-time.After(time.Second):
		t.Fatal("no onChange after mkdir")
	}

	// The watcher needs a moment to process the Create event and
	// register the new subdir before we write into it.
	time.Sleep(50 * time.Millisecond)

	if err := os.WriteFile(filepath.Join(sub, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case <-fires:
	case <-time.After(time.Second):
		t.Fatal("no onChange after writing inside newly-created subdir")
	}

	cancel()
	<-done
}

func TestRun_RequiresOnChange(t *testing.T) {
	root := t.TempDir()
	w, err := New([]string{root}, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := w.Run(ctx, nil, nil); err == nil {
		t.Fatal("Run should reject nil onChange")
	}
}

func TestExcludeDirs_Suppresses(t *testing.T) {
	root := t.TempDir()
	excluded := filepath.Join(root, "store")
	if err := os.Mkdir(excluded, 0o755); err != nil {
		t.Fatal(err)
	}

	w, err := NewWithConfig(Config{
		Roots:       []string{root},
		Debounce:    80 * time.Millisecond,
		ExcludeDirs: []string{excluded},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	// The excluded dir itself should not be in the watch set.
	if _, ok := w.added[excluded]; ok {
		t.Error("excluded dir was registered with fsnotify")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var fires int32
	done := make(chan struct{})
	go func() {
		_ = w.Run(ctx, func() {
			atomic.AddInt32(&fires, 1)
		}, nil)
		close(done)
	}()

	// Writing inside the excluded subtree should not trigger onChange.
	// Note: fsnotify may still report the create on the parent
	// (excluded itself is a child of root), but the per-event
	// isExcluded check suppresses it.
	if err := os.WriteFile(filepath.Join(excluded, "global.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)

	if got := atomic.LoadInt32(&fires); got != 0 {
		t.Errorf("excluded write fired onChange %d times, want 0", got)
	}

	// Sanity: a write OUTSIDE the excluded subtree still fires.
	if err := os.WriteFile(filepath.Join(root, "ok"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	if got := atomic.LoadInt32(&fires); got != 1 {
		t.Errorf("non-excluded write fires = %d, want 1", got)
	}

	cancel()
	<-done
}

func TestRoots_CopiedAndCanonicalised(t *testing.T) {
	root := t.TempDir()
	// Pass a path with a trailing slash; canonicalisation strips it.
	w, err := New([]string{root + "/"}, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()
	roots := w.Roots()
	if len(roots) != 1 {
		t.Fatalf("Roots() = %v, want 1 entry", roots)
	}
	// Mutating returned slice shouldn't affect internal state.
	roots[0] = "tampered"
	if w.Roots()[0] == "tampered" {
		t.Error("Roots() returned a shared slice")
	}
}

func TestNewWithConfig_AppliesScanExcludes(t *testing.T) {
	root := t.TempDir()
	// A real source dir we DO want watched, and a node_modules tree we
	// do NOT — exactly the shape that exhausts FDs on a $HOME scan.
	if err := os.MkdirAll(filepath.Join(root, "src", "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "node_modules", "left-pad", "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	w, err := NewWithConfig(Config{
		Roots:    []string{root},
		Excludes: []string{"**/node_modules/"},
	})
	if err != nil {
		t.Fatalf("NewWithConfig: %v", err)
	}
	defer w.Close()

	for p := range w.added {
		if filepath.Base(p) == "node_modules" ||
			filepath.Dir(p) == filepath.Join(root, "node_modules") ||
			filepath.Base(p) == "left-pad" || filepath.Base(p) == "deep" {
			t.Errorf("watched an excluded path: %s", p)
		}
	}
	// root + src + src/pkg = 3; node_modules subtree excluded.
	if got := len(w.added); got != 3 {
		t.Errorf("watched dirs = %d, want 3 (node_modules pruned)", got)
	}
}

func TestNewWithConfig_CapsWatchedDirs(t *testing.T) {
	root := t.TempDir()
	// 10 sibling dirs under root → 11 candidate dirs (root + 10).
	for i := 0; i < 10; i++ {
		if err := os.MkdirAll(filepath.Join(root, "d"+string(rune('0'+i))), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	w, err := NewWithConfig(Config{Roots: []string{root}, MaxWatchDirs: 4})
	if err == nil {
		t.Fatalf("expected ErrWatchLimit, got nil")
	}
	if err != ErrWatchLimit {
		t.Fatalf("err = %v, want ErrWatchLimit", err)
	}
	defer w.Close()
	if got := len(w.added); got > 4 {
		t.Errorf("watched dirs = %d, want <= cap 4", got)
	}
	if !w.Limited() {
		t.Error("Limited() = false, want true after hitting the cap")
	}
}
