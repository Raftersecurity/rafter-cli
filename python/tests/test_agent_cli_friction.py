"""Regression tests for a set of real agent-transcript friction points with
``rafter secrets``:

  1. Several paths in one invocation used to error "No such command" (Click
     tried to resolve the second path as a subcommand of the `secrets` group).
  2. `-a`/`--agent` was only recognized before the subcommand name.
  3. `--json`/`--format json` had no way to write to a file, so a sandboxed
     agent without shell redirects couldn't capture the result.
  4. A clean text-mode result didn't say the scan covered secrets only.

(5, a leaked raw git error outside a repository, was already clean on the
Python side — see node/tests/agent-cli-friction.test.ts for the Node fix.)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

from typer.testing import CliRunner

from rafter_cli.__main__ import app as root_app

runner = CliRunner()


def test_secrets_scans_every_path_and_merges_findings(tmp_path):
    app_dir = tmp_path / "app"
    infra_dir = tmp_path / "infra"
    app_dir.mkdir()
    infra_dir.mkdir()
    (app_dir / "a.py").write_text("x = 1\n")
    (app_dir / "b.py").write_text('AWS_KEY = "AKIAIOSFODNN7ABCDEFG"\n')
    (infra_dir / "c.tf").write_text('resource "x" {}\n')

    result = runner.invoke(root_app, [
        "secrets", str(app_dir / "a.py"), str(app_dir / "b.py"), str(infra_dir / "c.tf"),
        "--engine", "patterns", "--json",
    ])

    assert result.exit_code == 1, result.output
    out = json.loads(result.stdout)
    # Only b.py carries a secret; a clean single-path scan of a.py or c.tf
    # alone would report zero results, so this proves all three paths were
    # actually scanned rather than the run failing on the second argument.
    assert len(out["results"]) == 1
    assert out["results"][0]["file"].endswith("b.py")


def test_agent_flag_accepted_after_subcommand(tmp_path):
    (tmp_path / "clean.txt").write_text("nothing secret here\n")
    env = {**os.environ, "HOME": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, "-m", "rafter_cli", "secrets", str(tmp_path), "-a"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    combined = result.stdout + result.stderr
    assert "unknown option" not in combined.lower()
    assert "no such option" not in combined.lower()
    assert "[OK]" in combined
    assert result.returncode == 0, combined


def test_out_flag_writes_json_to_file_instead_of_stdout(tmp_path):
    (tmp_path / "clean.txt").write_text("nothing secret here\n")
    out_file = tmp_path / "result.json"

    result = runner.invoke(root_app, [
        "secrets", str(tmp_path), "--json", "--out", str(out_file),
    ])

    assert result.exit_code == 0, result.output
    assert out_file.exists()
    parsed = json.loads(out_file.read_text())
    assert parsed["scan_mode"] == "local"
    # The payload went to the file, not stdout.
    assert "scan_mode" not in result.output


def test_clean_text_result_notes_secrets_only_scope(tmp_path):
    (tmp_path / "clean.txt").write_text("nothing secret here\n")

    result = runner.invoke(root_app, ["secrets", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "No secrets detected" in result.output
    assert "not a code security review" in result.output
