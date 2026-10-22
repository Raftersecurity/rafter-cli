"""sable-ilbx — a file that could not be read must not be reported as a clean
scan. The CLI surfaces it in an `unreadable` field and exits non-zero, and the
MCP scan reports it in a separate block, so neither surface can read "could not
open" as "no secrets"."""
from __future__ import annotations

import asyncio
import json

import pytest
import typer

from rafter_cli.commands.agent import _output_scan_results, _scan_directory
from rafter_cli.commands.mcp_server import create_mcp_server


def _unreadable_dir(tmp_path):
    f = tmp_path / "secret.env"
    f.write_text("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIabcdef1234567890ABCDEFGHIJKL\n")
    f.chmod(0o000)
    return f


def test_json_output_lists_unreadable_and_exits_2(tmp_path, capsys):
    f = _unreadable_dir(tmp_path)
    try:
        results = _scan_directory(str(tmp_path), "patterns")
        with pytest.raises(typer.Exit) as exc:
            _output_scan_results(results, json_output=True, quiet=True)
        assert exc.value.exit_code == 2
        out = json.loads(capsys.readouterr().out)
        assert out["results"] == []
        assert len(out["unreadable"]) == 1
        assert out["unreadable"][0]["file"] == str(f)
    finally:
        f.chmod(0o644)


def test_text_output_does_not_claim_clean_for_unreadable(tmp_path, capsys):
    f = _unreadable_dir(tmp_path)
    try:
        results = _scan_directory(str(tmp_path), "patterns")
        with pytest.raises(typer.Exit) as exc:
            _output_scan_results(results, json_output=False, quiet=False)
        assert exc.value.exit_code == 2
        assert "No secrets detected" not in capsys.readouterr().out
    finally:
        f.chmod(0o644)


def test_mcp_scan_reports_unreadable_block(tmp_path):
    f = _unreadable_dir(tmp_path)
    try:
        result = asyncio.run(create_mcp_server().call_tool(
            "scan_secrets", {"path": str(f), "engine": "patterns"},
        ))
        content = result[0] if isinstance(result, tuple) else result
        blocks = [json.loads(c.text) for c in content]
        assert blocks[0] == []
        meta = next(b for b in blocks if isinstance(b, dict) and "unreadable" in b)
        assert meta["unreadable_count"] == 1
        assert meta["unreadable"][0]["file"] == str(f)
    finally:
        f.chmod(0o644)
