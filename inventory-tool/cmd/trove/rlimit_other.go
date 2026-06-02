//go:build !unix

package main

// raiseFileLimit is a no-op on platforms without POSIX rlimits (e.g.
// Windows). trove ships for macOS and Linux today; this keeps the build
// green if someone compiles elsewhere. The watcher's directory cap still
// bounds descriptor use.
func raiseFileLimit() (uint64, error) { return 0, nil }
