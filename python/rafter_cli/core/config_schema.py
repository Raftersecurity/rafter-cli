"""Configuration schema and defaults."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal


# Type aliases
RiskLevel = Literal["minimal", "moderate", "aggressive"]
CommandPolicyMode = Literal["allow-all", "approve-dangerous", "deny-list"]
LogLevel = Literal["debug", "info", "warn", "error"]

CONFIG_VERSION = "1.0.0"


@dataclass
class ScanCustomPattern:
    name: str
    regex: str
    severity: Literal["low", "medium", "high", "critical"] = "high"


@dataclass
class CommandPolicyConfig:
    mode: CommandPolicyMode = "approve-dangerous"
    blocked_patterns: list[str] = field(
        default_factory=lambda: list(__import__("rafter_cli.core.risk_rules", fromlist=["DEFAULT_BLOCKED_PATTERNS"]).DEFAULT_BLOCKED_PATTERNS)
    )
    require_approval: list[str] = field(
        default_factory=lambda: list(__import__("rafter_cli.core.risk_rules", fromlist=["DEFAULT_REQUIRE_APPROVAL"]).DEFAULT_REQUIRE_APPROVAL)
    )


@dataclass
class AuditConfig:
    log_all_actions: bool = True
    retention_days: int = 30
    log_level: LogLevel = "info"


@dataclass
class ScanConfig:
    exclude_paths: list[str] = field(default_factory=list)
    custom_patterns: list[ScanCustomPattern] = field(default_factory=list)


@dataclass
class OutputFilteringConfig:
    redact_secrets: bool = True
    block_patterns: bool = True


@dataclass
class EnvironmentConfig:
    enabled: bool = False
    path: str = ""


@dataclass
class EnvironmentsConfig:
    openclaw: EnvironmentConfig = field(default_factory=lambda: EnvironmentConfig(
        path=os.path.join(os.path.expanduser("~"), ".openclaw", "skills", "rafter-security.md"),
    ))
    claude_code: EnvironmentConfig = field(default_factory=lambda: EnvironmentConfig(
        path=os.path.join(os.path.expanduser("~"), ".claude", "mcp", "rafter-security.json"),
    ))


@dataclass
class AgentConfig:
    risk_level: RiskLevel = "moderate"
    environments: EnvironmentsConfig = field(default_factory=EnvironmentsConfig)
    command_policy: CommandPolicyConfig = field(default_factory=CommandPolicyConfig)
    output_filtering: OutputFilteringConfig = field(default_factory=OutputFilteringConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)


@dataclass
class BackendConfig:
    api_key: str | None = None
    endpoint: str = "https://rafter.so/api/"


@dataclass
class RafterConfig:
    version: str = CONFIG_VERSION
    initialized: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    backend: BackendConfig = field(default_factory=BackendConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)


def get_default_config() -> RafterConfig:
    return RafterConfig()


def get_rafter_dir() -> Path:
    return Path.home() / ".rafter"


def get_config_path() -> Path:
    return get_rafter_dir() / "config.json"


def get_audit_log_path() -> Path:
    return get_rafter_dir() / "audit.jsonl"
