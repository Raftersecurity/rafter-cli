#!/usr/bin/env bash
#
# no-write-syscalls.sh — fail if any package whose job is to *read*
# user secret files imports a syscall that could write to those paths.
#
# This is the static half of trove's "zero mutations to user files"
# guarantee. The dynamic half lives in tests/invariant/. They cover
# different escape routes:
#   - The invariant test catches *behavior* (what trove actually does
#     at runtime against a real fixture).
#   - This lint catches *intent* (a contributor adding os.WriteFile to
#     a scanner is rejected before the test ever runs).
#
# Scope: only the packages that walk and read source files. The store
# package legitimately writes — it owns global.json — so it is not
# included. cmd/trove and the server are out of scope too: they wire
# things up but never touch scanned files directly.
#
# Detection: pure text search. We do NOT try to be clever about Go
# AST — a banned identifier as a string literal is rare enough that
# false positives can be silenced with a // nolint:no-write-syscalls
# comment, while a genuine slip-up shows up as a clear hit.
#
# Run from the repo root or from inventory-tool/. CI calls this from
# inventory-tool/.
set -euo pipefail

# Resolve script-relative paths so the lint runs identically regardless
# of caller cwd.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$script_dir/.." && pwd)"

# Symbols that can mutate the host filesystem. Calls to any of these
# from a read-only package are rejected. New write-style calls added
# to the stdlib should be appended here when discovered.
#
# os.OpenFile is dual-use — it's the only safe way to take a flag-
# controlled file handle, and our scanners use it with os.O_RDONLY
# specifically. The match below drops O_RDONLY lines so the lint
# fires only when a scanner opens a file in a write mode.
banned=(
    "os.Create"
    "os.WriteFile"
    "os.OpenFile"
    "os.Remove"
    "os.RemoveAll"
    "os.Rename"
    "os.Mkdir"
    "os.MkdirAll"
    "os.Chmod"
    "os.Chown"
    "os.Truncate"
    "os.Symlink"
    "os.Link"
    "ioutil.WriteFile"
    "ioutil.TempFile"
    "ioutil.TempDir"
)

# Read-only packages. Anything inside these trees must NOT call the
# banned symbols. If you genuinely need a writer here, the right move
# is almost certainly to factor it out into a different package, not
# to silence the lint.
scope=(
    "$root/internal/scanners"
    "$root/internal/scan"
    "$root/internal/watch"
    "$root/internal/rescan"
)

fail=0

for path in "${scope[@]}"; do
    if [[ ! -d "$path" ]]; then
        echo "no-write-syscalls: scope path missing: $path" >&2
        fail=1
        continue
    fi
    for sym in "${banned[@]}"; do
        # -F treats the dotted symbol as a literal (no regex meta).
        # -R recurses; --include limits to .go; --exclude='*_test.go'
        # because tests legitimately set up fixtures.
        # -n shows line numbers so a hit is grep-jumpable from $EDITOR.
        # || true suppresses grep's "no match → exit 1"; we drive the
        # decision off captured output.
        hits=$(grep -RFn --include='*.go' --exclude='*_test.go' -- "$sym" "$path" 2>/dev/null || true)
        # os.OpenFile is allowed when the call site pins it to O_RDONLY
        # on the same line. Anything else (O_WRONLY, O_RDWR, O_CREATE,
        # O_APPEND, O_TRUNC) keeps tripping the lint.
        if [[ "$sym" == "os.OpenFile" && -n "$hits" ]]; then
            hits=$(printf '%s\n' "$hits" | grep -v 'os\.O_RDONLY' || true)
        fi
        if [[ -n "$hits" ]]; then
            echo "no-write-syscalls: BANNED \`$sym\` in $path:" >&2
            echo "$hits" | sed 's/^/  /' >&2
            fail=1
        fi
    done
done

if (( fail != 0 )); then
    echo >&2
    echo "no-write-syscalls: trove's zero-mutation invariant requires the above" >&2
    echo "packages to be read-only. Move write logic into internal/storage or" >&2
    echo "internal/docstore, which are the only packages allowed to persist." >&2
    exit 1
fi

echo "no-write-syscalls: clean (${#scope[@]} package(s), ${#banned[@]} symbol(s))"
