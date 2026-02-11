"""JSONL audit logger."""
from __future__ import annotations

import json
import math
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .config_schema import get_audit_log_path


class AuditLogger:
    def __init__(self, log_path: Path | None = None):
        self._path = log_path or get_audit_log_path()
        self._session_id = f"{int(time.time() * 1000)}-{random.randbytes(4).hex()}"
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, entry: dict[str, Any]) -> None:
        """Append an audit entry (JSONL)."""
        full = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": self._session_id,
            **entry,
        }
        with open(self._path, "a") as f:
            f.write(json.dumps(full) + "\n")

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
        self.log({
            "event_type": "command_intercepted",
            "agent_type": agent_type,
            "action": {"command": command, "risk_level": self._assess_command_risk(command)},
            "security_check": {"passed": passed, "reason": reason},
            "resolution": {"action_taken": action_taken},
        })

    def log_secret_detected(
        self,
        location: str,
        secret_type: str,
        action_taken: str,
        agent_type: str | None = None,
    ) -> None:
        self.log({
            "event_type": "secret_detected",
            "agent_type": agent_type,
            "action": {"risk_level": "critical"},
            "security_check": {"passed": False, "reason": f"{secret_type} detected in {location}"},
            "resolution": {"action_taken": action_taken},
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
            entries = [e for e in entries if e.get("event_type") == event_type]
        if agent_type:
            entries = [e for e in entries if e.get("agent_type") == agent_type]
        if since:
            iso = since.isoformat()
            entries = [e for e in entries if e.get("timestamp", "") >= iso]
        if limit:
            entries = entries[-limit:]
        return entries

    def cleanup(self, retention_days: int = 30) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        entries = self.read(since=cutoff)
        self._path.write_text(
            "\n".join(json.dumps(e) for e in entries) + "\n" if entries else ""
        )

    # ------------------------------------------------------------------

    @staticmethod
    def _assess_command_risk(command: str) -> str:
        import re

        critical = [
            r"rm\s+-rf\s+/",
            r":\(\)\{\s*:\|:&\s*\};:",
            r"dd\s+if=.*of=/dev/sd",
            r">\s*/dev/sd",
        ]
        high = [
            r"rm\s+-rf",
            r"sudo\s+rm",
            r"chmod\s+777",
            r"curl.*\|.*sh",
            r"wget.*\|.*sh",
            r"git\s+push\s+--force",
        ]
        medium = [r"sudo", r"chmod", r"chown", r"systemctl"]

        for p in critical:
            if re.search(p, command):
                return "critical"
        for p in high:
            if re.search(p, command):
                return "high"
        for p in medium:
            if re.search(p, command):
                return "medium"
        return "low"
