"""sable-9ddf — the opt-in approval gate for paid Plus scans.

Covers:
- _plus_approval_gate_enabled: OR semantics across global config + project
  policy, the security-critical "policy can tighten but never loosen" property,
  and fail-open on a config/policy read error.
- _confirm_plus_scan: mode gating, the --yes / RAFTER_CONFIRM overrides, the TTY
  prompt path, and the non-interactive refusal (exit 5).
- _do_remote_scan: the gate fires before the billable API call.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import typer

from rafter_cli.commands.backend import (
    _confirm_plus_scan,
    _do_remote_scan,
    _plus_approval_gate_enabled,
)
from rafter_cli.utils.api import EXIT_CONFIRMATION_REQUIRED


def _config_manager_returning(plus_flag):
    """A stand-in ConfigManager instance whose load().agent.scan
    .plus_requires_approval is `plus_flag`."""
    cfg = MagicMock()
    cfg.agent.scan.plus_requires_approval = plus_flag
    mgr = MagicMock()
    mgr.load.return_value = cfg
    return mgr


def _patch_sources(global_flag, policy_flag, config_raises=False):
    """Patch ConfigManager + load_policy where _plus_approval_gate_enabled
    imports them (the core modules)."""
    if config_raises:
        cm = patch(
            "rafter_cli.core.config_manager.ConfigManager",
            side_effect=RuntimeError("corrupt config"),
        )
    else:
        cm = patch(
            "rafter_cli.core.config_manager.ConfigManager",
            return_value=_config_manager_returning(global_flag),
        )
    policy = (
        None if policy_flag is None else {"scan": {"plus_requires_approval": policy_flag}}
    )
    lp = patch("rafter_cli.core.policy_loader.load_policy", return_value=policy)
    return cm, lp


# ── _plus_approval_gate_enabled ─────────────────────────────────────────


class TestGateEnabled:
    def test_off_by_default(self):
        cm, lp = _patch_sources(global_flag=False, policy_flag=None)
        with cm, lp:
            assert _plus_approval_gate_enabled() is False

    def test_on_when_only_global_config(self):
        cm, lp = _patch_sources(global_flag=True, policy_flag=None)
        with cm, lp:
            assert _plus_approval_gate_enabled() is True

    def test_on_when_only_project_policy(self):
        cm, lp = _patch_sources(global_flag=False, policy_flag=True)
        with cm, lp:
            assert _plus_approval_gate_enabled() is True

    def test_policy_cannot_loosen_global_optin(self):
        # SECURITY: machine owner enabled it globally; a hostile repo sets it
        # false. The gate must stay on.
        cm, lp = _patch_sources(global_flag=True, policy_flag=False)
        with cm, lp:
            assert _plus_approval_gate_enabled() is True

    def test_fails_open_on_config_read_error(self):
        cm, lp = _patch_sources(global_flag=None, policy_flag=None, config_raises=True)
        with cm, lp:
            assert _plus_approval_gate_enabled() is False


# ── _confirm_plus_scan ──────────────────────────────────────────────────


class TestConfirmPlusScan:
    def test_noop_for_fast_scan_even_when_gate_on(self, monkeypatch):
        with patch(
            "rafter_cli.commands.backend._plus_approval_gate_enabled", return_value=True
        ):
            # Should not raise.
            _confirm_plus_scan("fast", yes=False)

    def test_noop_for_plus_when_gate_off(self):
        with patch(
            "rafter_cli.commands.backend._plus_approval_gate_enabled", return_value=False
        ):
            _confirm_plus_scan("plus", yes=False)

    def test_proceeds_with_yes(self):
        with patch(
            "rafter_cli.commands.backend._plus_approval_gate_enabled", return_value=True
        ):
            _confirm_plus_scan("plus", yes=True)

    def test_proceeds_with_rafter_confirm_env(self, monkeypatch):
        monkeypatch.setenv("RAFTER_CONFIRM", "1")
        with patch(
            "rafter_cli.commands.backend._plus_approval_gate_enabled", return_value=True
        ):
            _confirm_plus_scan("plus", yes=False)

    def test_refuses_exit_5_non_interactive(self, monkeypatch):
        monkeypatch.delenv("RAFTER_CONFIRM", raising=False)
        with patch(
            "rafter_cli.commands.backend._plus_approval_gate_enabled", return_value=True
        ), patch("sys.stdin.isatty", return_value=False):
            with pytest.raises(typer.Exit) as exc:
                _confirm_plus_scan("plus", yes=False)
            assert exc.value.exit_code == EXIT_CONFIRMATION_REQUIRED

    def test_proceeds_when_prompt_answered_yes(self, monkeypatch):
        monkeypatch.delenv("RAFTER_CONFIRM", raising=False)
        with patch(
            "rafter_cli.commands.backend._plus_approval_gate_enabled", return_value=True
        ), patch("sys.stdin.isatty", return_value=True), patch(
            "builtins.input", return_value="y"
        ):
            _confirm_plus_scan("plus", yes=False)

    def test_refuses_exit_5_when_prompt_answered_no(self, monkeypatch):
        monkeypatch.delenv("RAFTER_CONFIRM", raising=False)
        with patch(
            "rafter_cli.commands.backend._plus_approval_gate_enabled", return_value=True
        ), patch("sys.stdin.isatty", return_value=True), patch(
            "builtins.input", return_value="n"
        ):
            with pytest.raises(typer.Exit) as exc:
                _confirm_plus_scan("plus", yes=False)
            assert exc.value.exit_code == EXIT_CONFIRMATION_REQUIRED


# ── _do_remote_scan integration — gate fires before the API call ─────────


class TestGateIntegration:
    @patch("rafter_cli.commands.backend.requests.post")
    def test_refuses_gated_plus_without_calling_backend(self, mock_post, monkeypatch):
        monkeypatch.delenv("RAFTER_CONFIRM", raising=False)
        with patch(
            "rafter_cli.commands.backend._plus_approval_gate_enabled", return_value=True
        ), patch("sys.stdin.isatty", return_value=False):
            with pytest.raises(typer.Exit) as exc:
                _do_remote_scan(
                    repo="owner/repo",
                    branch="main",
                    api_key="test-key",
                    fmt="json",
                    skip_interactive=True,
                    quiet=True,
                    mode="plus",
                )
            assert exc.value.exit_code == EXIT_CONFIRMATION_REQUIRED
        mock_post.assert_not_called()

    @patch("rafter_cli.commands.backend.requests.post")
    @patch(
        "rafter_cli.commands.backend.detect_repo",
        return_value=("owner/repo", "main", "github", None),
    )
    def test_submits_gated_plus_when_yes(self, _mock_repo, mock_post):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"scan_id": "s-abc"}
        mock_post.return_value = resp

        with patch(
            "rafter_cli.commands.backend._plus_approval_gate_enabled", return_value=True
        ):
            _do_remote_scan(
                repo="owner/repo",
                branch="main",
                api_key="test-key",
                fmt="json",
                skip_interactive=True,
                quiet=True,
                mode="plus",
                yes=True,
            )

        assert mock_post.call_args is not None
        body = mock_post.call_args.kwargs["json"]
        assert body["scan_mode"] == "plus"
