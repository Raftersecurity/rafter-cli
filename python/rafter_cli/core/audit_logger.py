"""JSONL audit logger."""
from __future__ import annotations

import errno
import hashlib
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


def read_last_line_hash(path: Path) -> str | None:
    """sha256 hex of the last non-empty line of path (including its trailing
    newline), or None if the file is empty / missing."""
    if not path.exists():
        return None
    size = path.stat().st_size
    if size == 0:
        return None
    read_bytes = min(size, 65536)
    with path.open("rb") as f:
        f.seek(size - read_bytes)
        tail = f.read(read_bytes).decode("utf-8", errors="replace")
    for line in reversed(tail.split("\n")):
        if line.strip():
            return hashlib.sha256((line + "\n").encode("utf-8")).hexdigest()
    return None


def acquire_lock(target: Path, max_attempts: int = 20, delay_s: float = 0.025):
    """Best-effort exclusive lock via O_EXCL sibling file. Returns a releaser.
    Degrades gracefully if lock can't be acquired (returns a no-op releaser)."""
    lock_path = target.parent / (target.name + ".lock")
    for _ in range(max_attempts):
        try:
            fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)

            def release() -> None:
                try:
                    os.unlink(lock_path)
                except FileNotFoundError:
                    pass

            return release
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
            # Steal stale locks (>5s old)
            try:
                if time.time() - lock_path.stat().st_mtime > 5:
                    os.unlink(lock_path)
                    continue
            except FileNotFoundError:
                continue
            time.sleep(delay_s)
    return lambda: None


def find_git_repo_root(start_dir: Path, max_depth: int = 20) -> str | None:
    """Walk up from start_dir looking for a .git directory."""
    d = start_dir.resolve()
    for _ in range(max_depth):
        try:
            if (d / ".git").exists():
                return str(d)
        except OSError:
            return None
        if d.parent == d:
            return None
        d = d.parent
    return None


class AuditLogger:
    def __init__(self, log_path: Path | None = None):
        if log_path is not None:
            self._path = log_path
        else:
            # Project-local override from .rafter.yml beats global
            policy_path = None
            try:
                from .config_manager import ConfigManager
                merged = ConfigManager().load_with_policy()
                policy_path = merged.agent.audit.log_path
            except Exception:
                pass
            self._path = Path(policy_path).expanduser() if policy_path else get_audit_log_path()
        self._session_id = f"{int(time.time() * 1000)}-{random.randbytes(4).hex()}"
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def log(self, entry: dict[str, Any]) -> None:
        """Append an audit entry (JSONL)."""
        from .config_manager import ConfigManager
        config = ConfigManager().load()
        if not config.agent.audit.log_all_actions:
            return

        cwd = entry.get("cwd") or os.getcwd()
        git_repo = entry.get("gitRepo")
        if git_repo is None:
            git_repo = find_git_repo_root(Path(cwd))

        release = acquire_lock(self._path)
        try:
            prev_hash = read_last_line_hash(self._path)
            full = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "sessionId": self._session_id,
                "cwd": cwd,
                "gitRepo": git_repo,
                "prevHash": prev_hash,
                **entry,
            }
            fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, (json.dumps(full) + "\n").encode())
            finally:
                os.close(fd)

            # Send webhook notification if configured and risk meets threshold
            self._send_notification(full, config)
        finally:
            release()

    def verify(self) -> list[dict]:
        """Verify hash chain integrity. Returns list of breaks (1-indexed line numbers)."""
        if not self._path.exists():
            return []
        breaks: list[dict] = []
        last_raw: str | None = None
        for i, raw in enumerate(self._path.read_text().split("\n"), start=1):
            if not raw.strip():
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                breaks.append({"line": i, "reason": "malformed JSON"})
                last_raw = raw
                continue
            expected = (
                hashlib.sha256((last_raw + "\n").encode("utf-8")).hexdigest()
                if last_raw is not None
                else None
            )
            actual = entry.get("prevHash")
            if actual != expected:
                if expected is None:
                    breaks.append({"line": i, "reason": f"first entry has prevHash {actual} but expected null"})
                else:
                    breaks.append({"line": i, "reason": f"prevHash {actual!r} does not match expected {expected}"})
            last_raw = raw
        return breaks

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
        cwd: str | None = None,
        git_repo: str | None = None,
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
        if cwd:
            entries = [e for e in entries if cwd in (e.get("cwd") or "")]
        if git_repo:
            entries = [e for e in entries if git_repo in (e.get("gitRepo") or "")]
        if limit:
            entries = entries[-limit:]
        return entries

    def cleanup(self, retention_days: int = 30) -> None:
        """Drop entries older than retention_days and re-seal the hash chain.

        Retention rewrites break the on-disk hash chain by design (some
        entries disappear). To keep verify() meaningful post-cleanup we
        re-seal the chain across surviving entries and record a sidecar
        `audit.retention.log` line capturing the pre-cleanup tip hash and
        pruned count, so a verifier can cross-check that retention — not
        tampering — is what broke the old chain.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        release = acquire_lock(self._path)
        try:
            if not self._path.exists():
                return
            pre_tip_hash = read_last_line_hash(self._path)
            raw_lines = [l for l in self._path.read_text().split("\n") if l.strip()]

            kept: list[dict] = []
            pruned_count = 0
            for line in raw_lines:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    pruned_count += 1
                    continue
                ts = entry.get("timestamp")
                if not ts:
                    pruned_count += 1
                    continue
                try:
                    entry_ts = datetime.fromisoformat(ts)
                except ValueError:
                    pruned_count += 1
                    continue
                if entry_ts >= cutoff:
                    kept.append(entry)
                else:
                    pruned_count += 1

            # Re-seal the chain across surviving entries.
            output: list[str] = []
            prev_line: str | None = None
            for entry in kept:
                entry["prevHash"] = (
                    hashlib.sha256((prev_line + "\n").encode("utf-8")).hexdigest()
                    if prev_line is not None
                    else None
                )
                serialized = json.dumps(entry)
                output.append(serialized)
                prev_line = serialized

            content = ("\n".join(output) + "\n").encode() if output else b""
            fd, tmp = tempfile.mkstemp(dir=self._path.parent, prefix=".audit_tmp_")
            try:
                os.write(fd, content)
                os.close(fd)
                os.chmod(tmp, 0o600)
                os.replace(tmp, self._path)
            except Exception:
                try:
                    os.close(fd)
                except OSError:
                    pass
                try:
                    os.unlink(tmp)
                except FileNotFoundError:
                    pass
                raise

            if pruned_count > 0:
                sidecar = self._path.parent / (self._path.name + ".retention.log")
                note = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "prunedCount": pruned_count,
                    "retainedCount": len(kept),
                    "retentionDays": retention_days,
                    "preCleanupTipHash": pre_tip_hash,
                }
                try:
                    sfd = os.open(sidecar, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                    try:
                        os.write(sfd, (json.dumps(note) + "\n").encode())
                    finally:
                        os.close(sfd)
                except OSError:
                    # sidecar is best-effort — don't fail cleanup if we can't write it
                    pass
        finally:
            release()

    # ------------------------------------------------------------------

    @staticmethod
    def _assess_command_risk(command: str) -> str:
        from .risk_rules import assess_command_risk
        return assess_command_risk(command)
