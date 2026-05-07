// Package scan is trove's filesystem orchestrator. It walks the user's
// configured scan roots, dispatches each recognised credential-bearing
// file to the matching read-only scanner in internal/scanners/*, and
// folds the resulting observations into the global store via
// storage.Global.Upsert.
//
// The orchestrator is deliberately the only place in trove that opens
// directories. Every individual scanner already opens files O_RDONLY;
// here we add the matching guarantee for traversal: no file is created,
// renamed, or deleted, and symlinks pointing OUT of the configured roots
// are not followed (track devices: TestScan_NeverWritesAnyFile pins this).
package scan

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
)

// Result is the per-Run summary returned to the caller. The same shape
// drives the optional telemetry payload (Inventory-Tool-Spec.md
// "Telemetry"). Counters are best-effort: a single secret seen at three
// paths increments FilesScanned three times but SecretsFound only once.
type Result struct {
	FilesScanned            int
	SecretsFound            int
	KeystoreEntriesFound    int
	FilesInGitRepos         int
	FilesCommittedInHistory int

	// Errors is the list of non-fatal problems hit during the walk
	// (unreadable file, dangling symlink, malformed config). The walk
	// continues past each one. A truly fatal error (e.g. nil doc) is
	// returned from Run instead.
	Errors []error
}

// Run walks every root in cfg, scans recognised files, and writes
// findings into doc via Upsert. The host clock is sampled once at the
// start of the run; every Secret created or refreshed during this Run
// shares the same FirstSeen/LastSeen value so a partial scan still
// produces a coherent timeline.
//
// Run never mutates any source file. It is safe to invoke repeatedly
// against the same doc — Upsert handles dedup, drift, and re-observation.
func Run(ctx context.Context, doc *storage.Global, cfg storage.ScanConfig) (*Result, error) {
	if doc == nil {
		return nil, errors.New("scan: nil doc")
	}
	r := &Result{}
	excludes := compileExcludes(cfg.Excludes)

	roots := canonicalRoots(cfg.Roots, r)
	if len(roots) == 0 {
		return r, nil
	}

	seen := make(map[string]struct{})
	now := time.Now().UTC()
	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		walkRoot(ctx, root, roots, excludes, seen, doc, r, now)
	}
	return r, nil
}

// canonicalRoots resolves each configured root to an absolute,
// symlink-resolved path. Roots that fail to resolve are dropped with an
// error appended to r.Errors so a misconfigured entry never aborts the
// rest of the scan.
func canonicalRoots(in []string, r *Result) []string {
	out := make([]string, 0, len(in))
	for _, root := range in {
		abs, err := filepath.Abs(expandHome(root))
		if err != nil {
			r.Errors = append(r.Errors, err)
			continue
		}
		// EvalSymlinks fails if the root is missing; that's a real
		// configuration error worth surfacing but not aborting on.
		real, err := filepath.EvalSymlinks(abs)
		if err != nil {
			r.Errors = append(r.Errors, err)
			continue
		}
		out = append(out, real)
	}
	return out
}
