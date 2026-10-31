"""Scan a repository's git history with the patterns engine (sable-28lv)."""
from __future__ import annotations

import os
import subprocess
import tempfile

from ..utils.git_diff import AddedLineParser
from .regex_scanner import RegexScanner, ScanResult


def git_repo_root(dir_path: str) -> str:
    """The repository root containing dir_path.

    Raises when dir_path is not inside a git work tree, so `--history` never
    reports a clean scan of a history it could not read.
    """
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=dir_path, capture_output=True, text=True,
        )
    except OSError as exc:
        raise RuntimeError(f"--history: git is not available: {exc}") from exc
    if r.returncode != 0:
        raise RuntimeError(f"--history: not a git repository: {dir_path}")
    return r.stdout.strip()


def scan_git_history(dir_path: str, custom_patterns=None) -> list[ScanResult]:
    """Scan every line ever added in the repository's history.

    Reads the same commits as `betterleaks git` (`git log -p -U0
    --full-history --all`), streamed line by line, so memory holds one line
    plus the findings, whatever the size of the history.

    Files are reported as absolute paths under the repo root and lines as the
    line number in the commit that added them, the same shape betterleaks
    history results take once made absolute, so the union merges the two.
    """
    repo_root = git_repo_root(dir_path)
    scanner = RegexScanner(custom_patterns)
    parser = AddedLineParser()
    by_file: dict[str, dict[tuple, object]] = {}

    cmd = [
        "git", "-c", "core.quotePath=false", "log", "-p", "-U0", "--no-color",
        "--no-ext-diff", "--no-textconv", "--full-history", "--all", "--format=commit %H",
    ]
    # stderr goes to a file: a pipe nobody drains until stdout ends could fill
    # and stall git.
    with tempfile.TemporaryFile() as errf:
        proc = subprocess.Popen(cmd, cwd=repo_root, stdout=subprocess.PIPE, stderr=errf)
        assert proc.stdout is not None
        # Split on \n only (as the Node scanner does); a bare CR inside a line
        # is content, not a line break.
        for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace").rstrip("\n")
            if line.endswith("\r"):
                line = line[:-1]
            added = parser.feed(line)
            if added is None:
                continue
            for m in scanner.scan_line(added.text, added.line):
                found = by_file.setdefault(os.path.join(repo_root, added.file), {})
                # The same secret re-added at the same place in a later commit is one finding.
                found.setdefault((m.line, m.column, m.match), m)
        code = proc.wait()
        errf.seek(0)
        stderr = errf.read().decode("utf-8", errors="replace")
    # An empty repository has no history to read; git says so with exit 128.
    if code != 0 and "does not have any commits" not in stderr:
        raise RuntimeError(f"--history: git log failed (exit {code}): {stderr.strip()}")

    return [ScanResult(file=f, matches=list(found.values())) for f, found in by_file.items()]
