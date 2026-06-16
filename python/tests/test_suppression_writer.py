"""Tests for the .rafter.yml suppression writer + MCP suppress_finding handler."""
from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from rafter_cli.commands.mcp_server import handle_suppress_finding
from rafter_cli.core.suppression_writer import write_suppression


@pytest.fixture
def in_tmp(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def read_policy(tmp_path: Path) -> dict:
    return yaml.safe_load((tmp_path / ".rafter.yml").read_text())


def test_creates_rafter_yml_when_absent(in_tmp):
    res = write_suppression(["test/fixtures/**"], rules=["AWS Access Key"], reason="fixtures")
    assert res["action"] == "created"
    assert res["suppression_count"] == 1
    assert (in_tmp / ".rafter.yml").exists()
    policy = read_policy(in_tmp)
    assert policy["ignore"] == [
        {"paths": ["test/fixtures/**"], "rules": ["AWS Access Key"], "reason": "fixtures"}
    ]


def test_appends_without_clobbering_other_keys(in_tmp):
    (in_tmp / ".rafter.yml").write_text(
        yaml.safe_dump({"risk_level": "moderate", "ignore": [{"paths": ["a/**"], "reason": "first"}]})
    )
    res = write_suppression(["b/**"], reason="second")
    assert res["action"] == "appended"
    assert res["suppression_count"] == 2
    policy = read_policy(in_tmp)
    assert policy["risk_level"] == "moderate"
    assert policy["ignore"][1] == {"paths": ["b/**"], "reason": "second"}


def test_updates_reason_in_place_for_same_scope(in_tmp):
    write_suppression(["a/**"], rules=["X"], reason="old")
    res = write_suppression(["a/**"], rules=["X"], reason="new reason")
    assert res["action"] == "updated"
    assert res["suppression_count"] == 1
    policy = read_policy(in_tmp)
    assert len(policy["ignore"]) == 1
    assert policy["ignore"][0]["reason"] == "new reason"


def test_dedup_is_order_insensitive(in_tmp):
    write_suppression(["a/**", "b/**"], rules=["X", "Y"], reason="first")
    res = write_suppression(["b/**", "a/**"], rules=["Y", "X"], reason="second")
    assert res["action"] == "updated"
    assert res["suppression_count"] == 1


def test_omits_rules_when_none_given(in_tmp):
    write_suppression(["docs/**"], reason="docs")
    policy = read_policy(in_tmp)
    assert policy["ignore"][0] == {"paths": ["docs/**"], "reason": "docs"}
    assert "rules" not in policy["ignore"][0]


def test_empty_paths_raises(in_tmp):
    with pytest.raises(ValueError):
        write_suppression([])


def test_mcp_handler_returns_ok(in_tmp):
    out = handle_suppress_finding("test/fixtures/**", rules=["AWS Access Key"], reason="fixtures")
    assert out["ok"] is True
    assert out["action"] == "created"
    assert out["entry"]["paths"] == ["test/fixtures/**"]
    assert out["suppression_count"] == 1
