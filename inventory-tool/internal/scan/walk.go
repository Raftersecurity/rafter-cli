package scan

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/excludes"
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
)

// walkRoot is the top-of-recursion entry. It seeds the ancestor chain
// with the canonical root so any symlink that resolves back to the
// root itself is detected as a cycle on the very first descent.
func walkRoot(
	ctx context.Context,
	root string,
	allRoots []string,
	excludeMatchers []excludes.Matcher,
	seen map[string]struct{},
	doc *storage.Global,
	r *Result,
	now time.Time,
) {
	info, err := os.Lstat(root)
	if err != nil {
		r.Errors = append(r.Errors, err)
		return
	}
	walkOne(ctx, root, info, allRoots, excludeMatchers, seen, doc, r, now, []string{root})
}

// walkOne handles a single directory entry: dispatches to a scanner
// for credential-bearing files, recurses into directories, and applies
// the symlink-boundary + cycle rules.
//
// ancestors is the chain of canonical directory paths from the root
// down to this entry's parent. We use it for parent-dir cycle detection:
// a symlink whose target is one of our ancestors would loop forever.
func walkOne(
	ctx context.Context,
	path string,
	info fs.FileInfo,
	allRoots []string,
	excludeMatchers []excludes.Matcher,
	seen map[string]struct{},
	doc *storage.Global,
	r *Result,
	now time.Time,
	ancestors []string,
) {
	if err := ctx.Err(); err != nil {
		return
	}

	// Symlink resolution happens before exclude/dispatch so the
	// "follow into root, never out of root" rule applies uniformly to
	// links that point at directories AND links that point at files.
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			// Dangling or unreadable symlink — record and skip rather
			// than abort. A misconfigured symlink shouldn't kill the
			// whole scan.
			r.Errors = append(r.Errors, err)
			return
		}
		if !insideAny(target, allRoots) {
			// Hard rule from the spec: symlinks are followed INTO scan
			// roots, NEVER OUT of them.
			return
		}
		// Cycle: target is an ancestor we're already inside.
		for _, a := range ancestors {
			if target == a {
				return
			}
		}
		// Cycle: target was visited via some other path earlier in
		// this run.
		if _, ok := seen[target]; ok {
			return
		}
		// Replace path/info with the resolved target so subsequent
		// dispatch + walk operate on the real filesystem object.
		ti, err := os.Lstat(target)
		if err != nil {
			r.Errors = append(r.Errors, err)
			return
		}
		path = target
		info = ti
	}

	if info.IsDir() {
		if excludes.Match(path, true, excludeMatchers) {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}

		entries, err := os.ReadDir(path)
		if err != nil {
			r.Errors = append(r.Errors, err)
			return
		}
		next := append(ancestors, path)
		for _, e := range entries {
			if err := ctx.Err(); err != nil {
				return
			}
			full := filepath.Join(path, e.Name())
			child, err := os.Lstat(full)
			if err != nil {
				r.Errors = append(r.Errors, err)
				continue
			}
			walkOne(ctx, full, child, allRoots, excludeMatchers, seen, doc, r, now, next)
		}
		return
	}

	if !info.Mode().IsRegular() {
		// Devices, pipes, sockets — never credential files.
		return
	}
	if excludes.Match(path, false, excludeMatchers) {
		return
	}
	scan, ok := scannerFor(path)
	if !ok {
		return
	}
	r.FilesScanned++
	found, err := scan(path)
	if err != nil {
		r.Errors = append(r.Errors, err)
		return
	}
	for _, fs := range found {
		out := doc.Upsert(storage.Upsertable{
			KeyName: fs.KeyName,
			Value:   fs.Value,
			Found:   fs.Source,
			Now:     now,
		})
		r.SecretsFound++
		if out.Secret != nil {
			r.Changes = append(r.Changes, Change{
				Outcome:  out.Outcome,
				SecretID: out.Secret.ID,
				KeyName:  out.Secret.KeyName,
				Path:     fs.Source.Path,
			})
		}
	}
}

// insideAny reports whether target sits at or under any of the
// configured roots. Used by the symlink boundary check; the caller
// must pre-canonicalise both target and roots so the comparison is a
// pure prefix test.
func insideAny(target string, roots []string) bool {
	sep := string(filepath.Separator)
	for _, root := range roots {
		if target == root || strings.HasPrefix(target, root+sep) {
			return true
		}
	}
	return false
}
