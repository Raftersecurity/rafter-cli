"""JSONL audit logger."""
from __future__ import annotations

import ipaddress
import json
import os
import random
import socket
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .config_schema import get_audit_log_path

RISK_SEVERITY: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


def _is_private_ip(addr: str) -> bool:
    """Check if an IP address is private, loopback, link-local, or reserved."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True  # Treat unparseable addresses as private (safe default)
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def validate_webhook_url(raw_url: str) -> None:
    """Validate a webhook URL to prevent SSRF attacks.

    Raises ValueError if the URL is unsafe (non-HTTP(S) scheme, resolves to
    private/internal IP, etc.).
    """
    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Webhook URL must use http or https, got {parsed.scheme!r}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Webhook URL has no hostname: {raw_url}")

    # If hostname is already an IP literal, check directly
    try:
        ipaddress.ip_address(hostname)
        # It parsed as an IP — check if it's private
        if _is_private_ip(hostname):
            raise ValueError(
                f"Webhook URL must not point to a private/internal address: {hostname}"
            )
        return  # Valid public IP
    except ValueError as exc:
        if "private/internal" in str(exc):
            raise  # Re-raise our own private-IP error
        # Not a valid IP literal — fall through to DNS resolution

    # Resolve hostname and check all resulting IPs
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve webhook hostname: {hostname}") from exc

    for info in infos:
        addr = info[4][0]
        if _is_private_ip(addr):
            raise ValueError(
                f"Webhook URL must not point to a private/internal address: "
                f"{hostname} resolved to {addr}"
            )


class AuditLogger:
    def __init__(self, log_path: Path | None = None):
        self._path = log_path or get_audit_log_path()
        self._session_id = f"{int(time.time() * 1000)}-{random.randbytes(4).hex()}"
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def log(self, entry: dict[str, Any]) -> None:
        """Append an audit entry (JSONL)."""
        from .config_manager import ConfigManager
        config = ConfigManager().load()
        if not config.agent.audit.log_all_actions:
            return

        full = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sessionId": self._session_id,
            **entry,
        }
        fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, (json.dumps(full) + "\n").encode())
        finally:
            os.close(fd)

        # Send webhook notification if configured and risk meets threshold
        self._send_notification(full, config)

    def _send_notification(self, entry: dict[str, Any], config: Any) -> None:
        """Send webhook notification for high-risk events (fire-and-forget)."""
        webhook_url = getattr(config.agent.notifications, "webhook", None)
        if not webhook_url:
            return

        action = entry.get("action") or {}
        event_risk = action.get("riskLevel", "low")
        min_risk = getattr(config.agent.notifications, "min_risk_level", "high")

        if RISK_SEVERITY.get(event_risk, 0) < RISK_SEVERITY.get(min_risk, 2):
            return

        event_type = entry.get("eventType", "unknown")
        command = action.get("command")
        summary = f"[rafter] {event_risk}-risk event: {event_type}"
        if command:
            summary += f" \u2014 {command}"

        payload = {
            "event": event_type,
            "risk": event_risk,
            "command": command,
            "timestamp": entry.get("timestamp"),
            "agent": entry.get("agentType"),
            "text": summary,
            "content": summary,
        }

        def _post() -> None:
            try:
                validate_webhook_url(webhook_url)
                import urllib.request
                req = urllib.request.Request(
                    webhook_url,
                    data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass  # Silently ignore webhook failures (including validation)

        threading.Thread(target=_post, daemon=True).start()

    # ------------------------------------------------------------------
    # Convenience loggers
    # ------------------------------------------------------------------

    def log_command_intercepted(
        self,
        command: str,
        passed: bool,
        action_taken: str,
        reason: str | None = None,
        agent_type: str | None = None,
    ) -> None:
        from ..scanners.regex_scanner import RegexScanner
        redacted = RegexScanner().redact(command)
        self.log({
            "eventType": "command_intercepted",
            "agentType": agent_type,
            "action": {"command": redacted, "riskLevel": self._assess_command_risk(command)},
            "securityCheck": {"passed": passed, "reason": reason},
            "resolution": {"actionTaken": action_taken},
        })

    def log_secret_detected(
        self,
        location: str,
        secret_type: str,
        action_taken: str,
        agent_type: str | None = None,
    ) -> None:
        self.log({
            "eventType": "secret_detected",
            "agentType": agent_type,
            "action": {"riskLevel": "critical"},
            "securityCheck": {"passed": False, "reason": f"{secret_type} detected in {location}"},
            "resolution": {"actionTaken": action_taken},
        })


    def log_content_sanitized(
        self,
        content_type: str,
        patterns_matched: int,
        agent_type: str | None = None,
    ) -> None:
        self.log({
            "eventType": "content_sanitized",
            "agentType": agent_type,
            "securityCheck": {
                "passed": False,
                "reason": f"{patterns_matched} sensitive patterns detected",
                "details": {"contentType": content_type, "patternsMatched": patterns_matched},
            },
            "resolution": {"actionTaken": "redacted"},
        })

    # ------------------------------------------------------------------
    # Read / Filter / Cleanup
    # ------------------------------------------------------------------

    def read(
        self,
        event_type: str | None = None,
        agent_type: str | None = None,
        since: datetime | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        if not self._path.exists():
            return []
        entries: list[dict] = []
        for line in self._path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        if event_type:
            entries = [e for e in entries if e.get("eventType") == event_type]
        if agent_type:
            entries = [e for e in entries if e.get("agentType") == agent_type]
        if since:
            iso = since.isoformat()
            entries = [e for e in entries if e.get("timestamp", "") >= iso]
        if limit:
            entries = entries[-limit:]
        return entries

    def cleanup(self, retention_days: int = 30) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        entries = self.read(since=cutoff)
        content = ("\n".join(json.dumps(e) for e in entries) + "\n" if entries else "").encode()
        fd, tmp = tempfile.mkstemp(dir=self._path.parent, prefix=".audit_tmp_")
        try:
            os.write(fd, content)
            os.close(fd)
            os.replace(tmp, self._path)
        except Exception:
            os.close(fd)
            os.unlink(tmp)
            raise

    # ------------------------------------------------------------------

    @staticmethod
    def _assess_command_risk(command: str) -> str:
        from .risk_rules import assess_command_risk
        return assess_command_risk(command)
