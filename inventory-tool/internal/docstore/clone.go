package docstore

import (
	"github.com/Raftersecurity/rafter-cli/inventory-tool/internal/storage"
)

// Clone returns a deep copy of g safe to mutate without affecting any
// other holder of the original pointer. Used by Update before handing
// fn a private copy and by callers (e.g. the rescanner) that need to
// scan into a sandbox before atomically publishing the result.
//
// Slices that the JSON schema requires to be non-null (Secrets,
// ScanConfig.Roots, ScanConfig.Excludes, Annotation.Tags, ValueHistory)
// are preserved as non-nil empty slices when the source has none, so
// the wire shape stays stable across clones.
func Clone(g *storage.Global) *storage.Global {
	if g == nil {
		return nil
	}
	out := *g
	out.ScanConfig.Roots = cloneStrings(g.ScanConfig.Roots)
	out.ScanConfig.Excludes = cloneStrings(g.ScanConfig.Excludes)
	out.Secrets = make([]storage.Secret, len(g.Secrets))
	for i := range g.Secrets {
		out.Secrets[i] = cloneSecret(&g.Secrets[i])
	}
	return &out
}

func cloneSecret(s *storage.Secret) storage.Secret {
	out := *s
	out.FoundIn = make([]storage.FoundIn, len(s.FoundIn))
	for i := range s.FoundIn {
		out.FoundIn[i] = cloneFoundIn(&s.FoundIn[i])
	}
	out.Annotation.Tags = cloneStrings(s.Annotation.Tags)
	if s.ValueHistory != nil {
		out.ValueHistory = append([]storage.ValueHistoryEntry(nil), s.ValueHistory...)
	} else {
		out.ValueHistory = []storage.ValueHistoryEntry{}
	}
	return out
}

func cloneFoundIn(f *storage.FoundIn) storage.FoundIn {
	out := *f
	if f.InGitRepo != nil {
		v := *f.InGitRepo
		out.InGitRepo = &v
	}
	if f.InGitignore != nil {
		v := *f.InGitignore
		out.InGitignore = &v
	}
	if f.AppearsInGitHistory != nil {
		v := *f.AppearsInGitHistory
		out.AppearsInGitHistory = &v
	}
	return out
}

// cloneStrings copies a string slice; nil → empty slice so consumers
// don't have to handle the absent-vs-empty case.
func cloneStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
