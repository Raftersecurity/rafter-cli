"""Tests for docs parsing in policy loader and the docs_loader resolution module."""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from rafter_cli.core.policy_loader import _map_policy, _validate_policy


class TestDocsParsing:
    """docs: section parsing + validation."""

    def test_parses_path_and_url_entries(self, capsys):
        raw = {
            "docs": [
                {
                    "path": "docs/security/secure.md",
                    "description": "Internal rules",
                    "tags": ["owasp", "internal"],
                },
                {
                    "url": "https://example.com/policy.md",
                    "cache": {"ttl_seconds": 3600},
                },
            ]
        }
        policy = _validate_policy(_map_policy(raw), raw)
        docs = policy["docs"]
        assert len(docs) == 2
        assert docs[0]["id"] == "secure"
        assert docs[0]["path"] == "docs/security/secure.md"
        assert docs[0]["tags"] == ["owasp", "internal"]
        assert docs[1]["url"] == "https://example.com/policy.md"
        assert docs[1]["cache"]["ttl_seconds"] == 3600
        # URL id is 8-char hex
        assert len(docs[1]["id"]) == 8
        int(docs[1]["id"], 16)  # raises if not hex

    def test_explicit_id_wins(self):
        raw = {"docs": [{"id": "custom", "path": "rules.md"}]}
        policy = _validate_policy(_map_policy(raw), raw)
        assert policy["docs"][0]["id"] == "custom"

    def test_skips_both_path_and_url(self, capsys):
        raw = {
            "docs": [
                {"id": "good", "path": "a.md"},
                {"id": "both", "path": "b.md", "url": "https://x"},
                {"id": "neither", "description": "x"},
            ]
        }
        policy = _validate_policy(_map_policy(raw), raw)
        err = capsys.readouterr().err
        assert 'exactly one of "path"' in err
        assert len(policy["docs"]) == 1
        assert policy["docs"][0]["id"] == "good"

    def test_duplicate_ids_skipped(self, capsys):
        raw = {
            "docs": [
                {"id": "dup", "path": "a.md"},
                {"id": "dup", "path": "b.md"},
            ]
        }
        policy = _validate_policy(_map_policy(raw), raw)
        err = capsys.readouterr().err
        assert 'duplicate id "dup"' in err
        assert len(policy["docs"]) == 1
        assert policy["docs"][0]["path"] == "a.md"

    def test_cache_ignored_on_path_entries(self, capsys):
        raw = {"docs": [{"id": "p", "path": "x.md", "cache": {"ttl_seconds": 100}}]}
        policy = _validate_policy(_map_policy(raw), raw)
        err = capsys.readouterr().err
        assert "cache is only valid" in err
        assert "cache" not in policy["docs"][0]

    def test_unknown_keys_warned(self, capsys):
        raw = {"docs": [{"id": "p", "path": "x.md", "weird": True}]}
        _validate_policy(_map_policy(raw), raw)
        err = capsys.readouterr().err
        assert 'unknown key "weird"' in err

    def test_invalid_ttl_ignored(self, capsys):
        raw = {"docs": [{"id": "u", "url": "https://x", "cache": {"ttl_seconds": -1}}]}
        policy = _validate_policy(_map_policy(raw), raw)
        err = capsys.readouterr().err
        assert "cache.ttl_seconds" in err
        assert "cache" not in policy["docs"][0]

    def test_docs_is_valid_top_level_key(self, capsys):
        raw = {"docs": []}
        _validate_policy(_map_policy(raw), raw)
        err = capsys.readouterr().err
        assert '"docs"' not in err  # no "unknown key" warning for docs


class TestDocsLoader:
    """Resolve, list, and fetch documents."""

    @pytest.fixture
    def tmp_project(self, tmp_path, monkeypatch):
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
        monkeypatch.chdir(tmp_path)
        # Isolate ~/.rafter for cache
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        # Reload to pick up new HOME for cache dir resolution
        import rafter_cli.core.config_schema as cs
        importlib.reload(cs)
        import rafter_cli.core.docs_loader as dl
        importlib.reload(dl)
        return tmp_path

    def test_list_reports_cache_status(self, tmp_project):
        (tmp_project / ".rafter.yml").write_text(
            "docs:\n"
            "  - id: local\n"
            "    path: a.md\n"
            "  - id: remote\n"
            "    url: https://example.com/p.md\n"
        )
        import rafter_cli.core.docs_loader as dl
        importlib.reload(dl)
        docs = dl.list_docs()
        by_id = {d.id: d for d in docs}
        assert by_id["local"].cache_status == "local"
        assert by_id["local"].source_kind == "path"
        assert by_id["remote"].cache_status == "not-cached"
        assert by_id["remote"].source_kind == "url"

    def test_resolve_selector_id_then_tag(self, tmp_project):
        (tmp_project / ".rafter.yml").write_text(
            "docs:\n"
            "  - id: a\n"
            "    path: a.md\n"
            "    tags: [team-sec]\n"
            "  - id: b\n"
            "    path: b.md\n"
            "    tags: [team-sec, extra]\n"
        )
        import rafter_cli.core.docs_loader as dl
        importlib.reload(dl)
        by_id = dl.resolve_doc_selector("a")
        assert len(by_id) == 1
        assert by_id[0]["id"] == "a"
        by_tag = dl.resolve_doc_selector("team-sec")
        assert {d["id"] for d in by_tag} == {"a", "b"}

    def test_fetch_path_reads_from_git_root(self, tmp_project):
        (tmp_project / ".rafter.yml").write_text(
            "docs:\n"
            "  - id: r\n"
            "    path: rules.md\n"
        )
        (tmp_project / "rules.md").write_text("# Internal Rules\n")
        import rafter_cli.core.docs_loader as dl
        importlib.reload(dl)
        result = dl.fetch_doc({"id": "r", "path": "rules.md"})
        assert result.source_kind == "path"
        assert "Internal Rules" in result.content

    def test_fetch_url_returns_stale_on_network_failure(self, tmp_project, monkeypatch):
        (tmp_project / ".rafter.yml").write_text(
            "docs:\n"
            "  - id: remote\n"
            "    url: https://example.invalid/x.md\n"
        )
        import rafter_cli.core.docs_loader as dl
        importlib.reload(dl)

        # Seed cache with an expired timestamp
        url = "https://example.invalid/x.md"
        key = hashlib.sha256(url.encode("utf-8")).hexdigest()[:32]
        cache_dir = dl.get_rafter_dir() / "docs-cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / f"{key}.txt").write_text("stale body")
        (cache_dir / f"{key}.meta.json").write_text(json.dumps({
            "fetched_at": "2000-01-01T00:00:00+00:00",
            "url": url,
            "content_type": "text/plain",
        }))

        # Force urlopen to fail
        def boom(*args, **kwargs):
            raise OSError("network down")

        monkeypatch.setattr(dl, "urlopen", boom)

        result = dl.fetch_doc({"id": "remote", "url": url})
        assert result.stale is True
        assert result.cached is True
        assert result.content == "stale body"

    def test_fetch_url_writes_cache_on_success(self, tmp_project, monkeypatch):
        (tmp_project / ".rafter.yml").write_text(
            "docs:\n"
            "  - id: remote\n"
            "    url: https://example.com/x.md\n"
        )
        import rafter_cli.core.docs_loader as dl
        importlib.reload(dl)

        class FakeResp:
            headers = {"content-type": "text/markdown"}

            def read(self):
                return b"fresh content"

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def fake_urlopen(req, timeout=None):
            return FakeResp()

        monkeypatch.setattr(dl, "urlopen", fake_urlopen)

        result = dl.fetch_doc({"id": "remote", "url": "https://example.com/x.md"})
        assert result.stale is False
        assert result.content == "fresh content"

        # Cache should now exist and be fresh
        docs = dl.list_docs()
        assert docs[0].cache_status == "cached"
