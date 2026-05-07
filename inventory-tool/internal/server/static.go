package server

import (
	"embed"
	"io/fs"
)

// Static assets bundled into the trove binary. The browser UI is a
// single-page application: index.html is served at /, and any sibling
// asset (app.js, future css) is served from /static/<name>. All paths
// are bounded by the embed directive so no host filesystem is read at
// runtime.
//
//go:embed static
var staticEmbedFS embed.FS

// staticFS is the io/fs.FS rooted at the static/ subdirectory so
// /static/app.js maps to static/app.js without a re-prefix step at
// request time.
var staticFS = mustSub(staticEmbedFS, "static")

// indexHTML is read once from the embed FS at init so handleIndex can
// write it without touching fs.FS on every request.
var indexHTML = mustReadIndex()

func mustSub(f embed.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		panic("server: bad static FS prefix: " + err.Error())
	}
	return sub
}

func mustReadIndex() []byte {
	b, err := fs.ReadFile(staticFS, "index.html")
	if err != nil {
		panic("server: cannot read embedded index.html: " + err.Error())
	}
	return b
}
