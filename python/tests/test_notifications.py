"""Tests for webhook notification support in audit logger."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from rafter_cli.core.audit_logger import AuditLogger, RISK_SEVERITY
from rafter_cli.core.config_schema import (
    AgentConfig,
    AuditConfig,
    NotificationsConfig,
    RafterConfig,
)


class TestRiskSeverity:
    def test_ordering(self):
        assert RISK_SEVERITY["low"] < RISK_SEVERITY["medium"]
        assert RISK_SEVERITY["medium"] < RISK_SEVERITY["high"]
        assert RISK_SEVERITY["high"] < RISK_SEVERITY["critical"]


class TestNotificationsConfig:
    def test_defaults(self):
        cfg = NotificationsConfig()
        assert cfg.webhook is None
        assert cfg.min_risk_level == "high"

    def test_custom_values(self):
        cfg = NotificationsConfig(webhook="https://example.com/hook", min_risk_level="critical")
        assert cfg.webhook == "https://example.com/hook"
        assert cfg.min_risk_level == "critical"


class TestWebhookNotification:
    @pytest.fixture
    def logger(self, tmp_path: Path) -> AuditLogger:
        return AuditLogger(log_path=tmp_path / "audit.jsonl")

    def _make_config(self, webhook: str | None = None, min_risk: str = "high") -> RafterConfig:
        return RafterConfig(
            agent=AgentConfig(
                audit=AuditConfig(log_all_actions=True),
                notifications=NotificationsConfig(
                    webhook=webhook,
                    min_risk_level=min_risk,
                ),
            ),
        )

    def test_sends_webhook_on_high_risk(self, logger: AuditLogger):
        config = self._make_config(webhook="https://hooks.example.com/test")

        with patch("rafter_cli.core.config_manager.ConfigManager.load", return_value=config), \
             patch("threading.Thread") as mock_thread:
            mock_instance = MagicMock()
            mock_thread.return_value = mock_instance

            logger.log_command_intercepted("git push --force", False, "blocked", "High-risk", "claude-code")

            mock_thread.assert_called_once()
            call_kwargs = mock_thread.call_args
            assert call_kwargs.kwargs["daemon"] is True

            # Execute the target function to verify payload
            target_fn = call_kwargs.kwargs["target"]
            with patch("urllib.request.urlopen") as mock_urlopen:
                target_fn()
                mock_urlopen.assert_called_once()
                req = mock_urlopen.call_args[0][0]
                body = json.loads(req.data.decode())
                assert body["event"] == "command_intercepted"
                assert body["risk"] == "high"
                assert body["command"] == "git push --force"
                assert body["agent"] == "claude-code"
                assert body["timestamp"] is not None
                assert "[rafter]" in body["text"]
                assert "[rafter]" in body["content"]

    def test_no_webhook_on_low_risk(self, logger: AuditLogger):
        config = self._make_config(webhook="https://hooks.example.com/test")

        with patch("rafter_cli.core.config_manager.ConfigManager.load", return_value=config), \
             patch("threading.Thread") as mock_thread:
            logger.log_command_intercepted("ls -la", True, "allowed", None, "claude-code")
            mock_thread.assert_not_called()

    def test_no_webhook_when_unconfigured(self, logger: AuditLogger):
        config = self._make_config(webhook=None)

        with patch("rafter_cli.core.config_manager.ConfigManager.load", return_value=config), \
             patch("threading.Thread") as mock_thread:
            logger.log_secret_detected("config.js", "AWS Key", "blocked", "claude-code")
            mock_thread.assert_not_called()

    def test_critical_only_threshold(self, logger: AuditLogger):
        config = self._make_config(webhook="https://hooks.example.com/test", min_risk="critical")

        with patch("rafter_cli.core.config_manager.ConfigManager.load", return_value=config), \
             patch("threading.Thread") as mock_thread:
            # High-risk should NOT trigger
            logger.log_command_intercepted("git push --force", False, "blocked", "High-risk", "claude-code")
            mock_thread.assert_not_called()

            # Critical should trigger
            logger.log_secret_detected("config.js", "AWS Key", "blocked")
            mock_thread.assert_called_once()

    def test_webhook_failure_does_not_block_logging(self, logger: AuditLogger, tmp_path: Path):
        config = self._make_config(webhook="https://hooks.example.com/test")

        def failing_post():
            raise ConnectionError("network error")

        with patch("rafter_cli.core.config_manager.ConfigManager.load", return_value=config), \
             patch("threading.Thread") as mock_thread:
            mock_instance = MagicMock()
            mock_thread.return_value = mock_instance

            logger.log_secret_detected("config.js", "AWS Key", "blocked")

            # Audit log should still be written
            log_path = tmp_path / "audit.jsonl"
            assert log_path.exists()
            content = log_path.read_text()
            assert "secret_detected" in content

    def test_payload_includes_slack_and_discord_fields(self, logger: AuditLogger):
        config = self._make_config(webhook="https://hooks.example.com/test")

        with patch("rafter_cli.core.config_manager.ConfigManager.load", return_value=config), \
             patch("threading.Thread") as mock_thread:
            mock_instance = MagicMock()
            mock_thread.return_value = mock_instance

            logger.log_secret_detected("config.js", "AWS Key", "blocked", "claude-code")

            target_fn = mock_thread.call_args.kwargs["target"]
            with patch("urllib.request.urlopen") as mock_urlopen:
                target_fn()
                req = mock_urlopen.call_args[0][0]
                body = json.loads(req.data.decode())
                # Slack compatibility
                assert "text" in body
                # Discord compatibility
                assert "content" in body
                assert body["text"] == body["content"]


class TestConfigDeserialization:
    def test_notifications_config_from_dict(self):
        from rafter_cli.core.config_manager import ConfigManager
        raw = {
            "version": "1.0.0",
            "initialized": "2026-01-01T00:00:00Z",
            "agent": {
                "notifications": {
                    "webhook": "https://hooks.slack.com/test",
                    "minRiskLevel": "critical",
                },
            },
        }
        config = ConfigManager._from_dict(raw)
        assert config.agent.notifications.webhook == "https://hooks.slack.com/test"
        assert config.agent.notifications.min_risk_level == "critical"

    def test_notifications_default_when_missing(self):
        from rafter_cli.core.config_manager import ConfigManager
        raw = {
            "version": "1.0.0",
            "initialized": "2026-01-01T00:00:00Z",
            "agent": {},
        }
        config = ConfigManager._from_dict(raw)
        assert config.agent.notifications.webhook is None
        assert config.agent.notifications.min_risk_level == "high"
