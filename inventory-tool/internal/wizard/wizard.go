// Package wizard implements trove's first-run setup prompt.
//
// FirstRun runs once, on a host that has never produced a global.json,
// to populate ScanConfig.Roots and ScanConfig.Excludes. The user is
// shown the spec's default scope ($HOME with a curated exclude list)
// plus any common workspace directories detected under $HOME, and
// either accepts the defaults or pastes a custom list. The wizard
// never reads or writes secret-bearing files; all it touches is the
// in-memory storage.Global the caller passes in.
package wizard

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
)

// FirstRun populates doc.ScanConfig from prompts on in / messages on
// out. If doc.ScanConfig.Roots is non-empty, FirstRun returns nil
// immediately — the contract is that this is a first-run gate, not a
// re-configuration UI. (The settings page handles ongoing edits.)
//
// Empty input on every prompt accepts every default. The caller is
// responsible for persisting doc to disk after FirstRun returns.
func FirstRun(in io.Reader, out io.Writer, doc *storage.Global) error {
	if doc == nil {
		return fmt.Errorf("wizard: nil doc")
	}
	// Idempotency: if Roots is already configured, this isn't a first
	// run — bail out without touching the doc.
	if len(doc.ScanConfig.Roots) > 0 {
		return nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("wizard: resolve home dir: %w", err)
	}

	defaultRoots := []string{home}
	detected := detectCommonLayouts(home)

	fmt.Fprintln(out, "Welcome to trove! Let's set up your secret scan scope.")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "Default scan root: %s\n", home)
	fmt.Fprintln(out, "Default excludes will skip system caches, build dirs, and VCS metadata.")
	fmt.Fprintln(out)

	if len(detected) > 0 {
		fmt.Fprintln(out, "Detected common workspace layouts under your home directory:")
		for _, d := range detected {
			fmt.Fprintf(out, "  - %s\n", d)
		}
		fmt.Fprintln(out)
	}

	r := bufio.NewReader(in)

	// Prompt 1: accept default root or paste a custom set. We don't
	// expose an "add to defaults" knob — the spec calls out "$HOME with
	// excludes" as the right answer for v1; advanced users can edit
	// global.json or use the settings page later.
	fmt.Fprintf(out, "Use default root (%s)? [Y/n] ", home)
	ans := readLine(r)
	roots := defaultRoots
	if isNo(ans) {
		fmt.Fprint(out, "Enter scan roots (one per line, blank line to finish):\n")
		roots = readPaths(r, out, home)
		if len(roots) == 0 {
			roots = defaultRoots
		}
	}

	// Prompt 2: optional excludes on top of the spec defaults. We
	// always pre-load the spec excludes — they're the load-bearing
	// performance/correctness ones (no recursing into ~/Library, no
	// node_modules, etc.). Users can add more here.
	excludes := DefaultExcludes()
	fmt.Fprintf(out, "Use default excludes (recommended)? [Y/n] ")
	ans = readLine(r)
	if isNo(ans) {
		fmt.Fprintln(out, "Enter additional excludes (one per line, blank line to finish):")
		extras := readPaths(r, out, home)
		excludes = append(excludes, extras...)
	}

	doc.ScanConfig.Roots = roots
	doc.ScanConfig.Excludes = excludes
	fmt.Fprintln(out)
	fmt.Fprintf(out, "Configured %d root(s) and %d exclude(s).\n", len(roots), len(excludes))
	return nil
}

// commonLayoutNames are the workspace directory names we surface to
// the user when they exist under $HOME. The list is intentionally
// short — we want to nudge people who already have a discoverable code
// dir, not list every tool's cache.
var commonLayoutNames = []string{
	"code", "git", "src", "Projects", "projects", "work", "dev", "Code",
}

// detectCommonLayouts returns absolute paths of well-known workspace
// dirs that exist under home. Order is stable (commonLayoutNames
// order) so the wizard's output is deterministic.
func detectCommonLayouts(home string) []string {
	var out []string
	for _, name := range commonLayoutNames {
		p := filepath.Join(home, name)
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

// DefaultExcludes returns the spec-pinned default exclude list. The
// list is also exported so the settings UI can show "currently using
// defaults" without re-deriving them.
//
// Patterns mirror Inventory-Tool-Spec.md "Default search roots &
// excludes". Anything added here must also be safe to scan past — the
// list trades some completeness for a sane default scan time.
func DefaultExcludes() []string {
	return []string{
		"~/Library/",
		"~/.Trash/",
		"~/.local/share/Trash/",
		"**/node_modules/",
		"**/.git/",
		"**/vendor/",
		"**/.venv/",
		"**/venv/",
		"**/__pycache__/",
		"**/target/",
		"**/dist/",
		"**/build/",
		"**/out/",
		"**/.cache/",
		"**/.npm/",
		"**/.cargo/",
		"**/.gradle/",
		"**/.m2/",
		"**/.next/",
		"**/.nuxt/",
		"**/.DS_Store",
	}
}

// readLine reads a single line of user input, stripping the newline.
// On EOF it returns "" so the wizard can interpret it as "accept
// default" instead of erroring out.
func readLine(r *bufio.Reader) string {
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	return strings.TrimRight(line, "\r\n")
}

// readPaths reads one path per line until a blank line. Each path is
// `~/...`-expanded against home so users can type their config the way
// it appears in the spec.
func readPaths(r *bufio.Reader, out io.Writer, home string) []string {
	var paths []string
	for {
		fmt.Fprint(out, "> ")
		line := readLine(r)
		if line == "" {
			return paths
		}
		if strings.HasPrefix(line, "~/") {
			line = filepath.Join(home, strings.TrimPrefix(line, "~/"))
		}
		paths = append(paths, line)
	}
}

// isNo returns true for any user response that should be read as
// "no, override the default". Empty / unrecognised input is treated
// as "yes, accept the default" so blind-Enter walks happily through
// the wizard.
func isNo(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "n", "no":
		return true
	}
	return false
}
