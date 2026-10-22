"""sable-lu0j — policy/suppression must be discovered and anchored from the scan
target, not the process cwd. An ambient `.rafter.yml` in cwd must not suppress
real secrets in a scan of a different tree, and a relative ignore glob must not
match absolute paths outside the policy's own tree."""
from __future__ import annotations

import json
import os

import pytest
import typer

from rafter_cli.commands.scan import scan_local

SECRET = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7ABCDEFG\n"


def _run_scan(target: str, capsys) -> tuple[dict, int]:
    with pytest.raises(typer.Exit) as exc:
        scan_local(
            path=target,
            quiet=True,
            json_output=True,
            format="json",
            staged=False,
            diff=None,
            engine="patterns",
            baseline=False,
            watch=False,
            history=False,
            gitignore=False,
            auto_update=False,
        )
    return json.loads(capsys.readouterr().out), exc.value.exit_code


def test_ambient_cwd_policy_does_not_suppress_another_tree(tmp_path, monkeypatch, capsys):
    cwd_dir = tmp_path / "cwd"
    cwd_dir.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    leaf = target.name
    # Ambient policy in the cwd tree: a broad ignore keyed on the target's leaf.
    (cwd_dir / ".rafter.yml").write_text(
        f'ignore:\n  - paths: ["**/{leaf}/**"]\n    reason: ambient\n'
    )
    (target / "creds.env").write_text(SECRET)

    monkeypatch.chdir(cwd_dir)
    out, code = _run_scan(str(target), capsys)
    # The secret in the other tree must be found, not suppressed by cwd's policy.
    assert len(out["results"]) >= 1
    assert code == 1


def test_policy_in_scanned_tree_still_suppresses(tmp_path, monkeypatch, capsys):
    root = tmp_path / "repo"
    (root / "fixtures").mkdir(parents=True)
    (root / ".rafter.yml").write_text(
        'ignore:\n  - paths: ["fixtures/**"]\n    reason: ok\n'
    )
    (root / "fixtures" / "creds.env").write_text(SECRET)

    monkeypatch.chdir(root)
    out, code = _run_scan(str(root), capsys)
    # The normal case: a policy in the scanned tree still suppresses.
    assert out["results"] == []
    assert len(out.get("_suppressed", [])) >= 1
