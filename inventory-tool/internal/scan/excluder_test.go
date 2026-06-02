package scan

import (
	"path/filepath"
	"testing"
)

func TestExcluder_MatchDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	e := NewExcluder([]string{"**/node_modules/", "**/.git/", "~/Library/"})
	cases := []struct {
		path string
		want bool
	}{
		// `**/X/` basename rules match the directory itself; the walk
		// then SkipDirs it, so descendants are never visited and need
		// not match on their own.
		{"/code/app/node_modules", true},
		{"/code/app/node_modules/left-pad", false},
		{"/code/app/.git", true},
		{"/code/app/src", false},
		// `~/X/` is absolute-anchored: the dir AND every descendant match.
		{filepath.Join(home, "Library"), true},
		{filepath.Join(home, "Library", "Caches"), true},
		{filepath.Join(home, "code"), false},
	}
	for _, c := range cases {
		if got := e.MatchDir(c.path); got != c.want {
			t.Errorf("MatchDir(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestExcluder_NilForEmpty(t *testing.T) {
	if NewExcluder(nil) != nil {
		t.Error("NewExcluder(nil) should be nil")
	}
	var e *Excluder
	if e.MatchDir("/anything") {
		t.Error("nil *Excluder.MatchDir should be false")
	}
}
