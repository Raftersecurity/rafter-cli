"""Configuration manager: load, save, merge, policy overlay."""
from __future__ import annotations

import json
import re as _re
import sys
from dataclasses import asdict, fields as _fields
from pathlib import Path

from .config_schema import (
    CONFIG_VERSION,
    RafterConfig,
    get_config_path,
    get_default_config,
    get_rafter_dir,
)

_VALID_RISK_LEVELS = {"minimal", "moderate", "aggressive"}
_VALID_COMMAND_MODES = {"allow-all", "approve-dangerous", "deny-list"}
_VALID_LOG_LEVELS = {"debug", "info", "warn", "error"}


class ConfigManager:
    def __init__(self, config_path: Path | None = None):
        self._path = config_path or get_config_path()

    # ------------------------------------------------------------------
    # Load / Save
    # ------------------------------------------------------------------

    def load(self) -> RafterConfig:
        if not self._path.exists():
            return get_default_config()
        try:
            raw = json.loads(self._path.read_text())
            if not isinstance(raw, dict):
                print("rafter: config file is not a JSON object — using defaults.", file=sys.stderr)
                return get_default_config()
            self._validate_raw_config(raw)
            config = self._from_dict(raw)
            return self._migrate(config)
        except (json.JSONDecodeError, KeyError) as exc:
            print(f"rafter: malformed config, using defaults: {exc}", file=sys.stderr)
            return get_default_config()
        except OSError as exc:
            print(f"rafter: cannot read config, using defaults: {exc}", file=sys.stderr)
            return get_default_config()

    def save(self, config: RafterConfig) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._to_dict(config), indent=2))

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    def update(self, updates: dict) -> RafterConfig:
        config = self.load()
        d = self._to_dict(config)
        merged = self._deep_merge(d, updates)
        cfg = self._from_dict(merged)
        self.save(cfg)
        return cfg

    def get(self, key_path: str):
        """Get a config value by dot-path (e.g. 'agent.risk_level')."""
        d = self._to_dict(self.load())
        for key in key_path.split("."):
            if isinstance(d, dict) and key in d:
                d = d[key]
            else:
                return None
        return d

    def set(self, key_path: str, value) -> None:
        """Set a config value by dot-path."""
        d = self._to_dict(self.load())
        keys = key_path.split(".")
        current = d
        for k in keys[:-1]:
            if k not in current or not isinstance(current[k], dict):
                current[k] = {}
            current = current[k]
        current[keys[-1]] = value
        cfg = self._from_dict(d)
        self.save(cfg)

    def initialize(self) -> None:
        """Create ~/.rafter/ directory and default config."""
        rafter_dir = get_rafter_dir()
        for sub in [rafter_dir, rafter_dir / "bin", rafter_dir / "patterns"]:
            sub.mkdir(parents=True, exist_ok=True)

        # Write patterns/ README if missing
        patterns_readme = rafter_dir / "patterns" / "README.md"
        if not patterns_readme.exists():
            patterns_readme.write_text(
                "\n".join([
                    "# Custom Secret Patterns",
                    "",
                    "Place custom secret-detection pattern files here.",
                    "Each file should contain one regex pattern per line.",
                    "",
                    "Rafter ships 21 built-in patterns (AWS, GitHub, Stripe, etc.).",
                    "Files in this directory extend that set for your environment.",
                    "",
                    "Support for loading custom patterns from this directory is planned",
                    "for a future release.",
                ]) + "\n"
            )

        if not self._path.exists():
            self.save(get_default_config())

    def exists(self) -> bool:
        return self._path.exists()

    def _migrate(self, config: RafterConfig) -> RafterConfig:
        """Upgrade known-bad config values from older installs."""
        # Fix overly broad curl/wget pipe-to-shell patterns.
        # Old pattern: r"curl.*\|.*sh" — matches any command containing "sh" after a pipe
        # (e.g. `grep "curl\|sh"` or `git stash`). Replace with word-bounded shell names.
        _bad_to_good = {
            r"curl.*\|.*sh": r"curl.*\|\s*(bash|sh|zsh|dash)\b",
            r"wget.*\|.*sh": r"wget.*\|\s*(bash|sh|zsh|dash)\b",
        }
        policy = config.agent.command_policy
        fixed = [_bad_to_good.get(p, p) for p in policy.require_approval]
        if fixed != policy.require_approval:
            policy.require_approval = fixed
            self.save(config)
        return config

    @staticmethod
    def _validate_raw_config(raw: dict) -> None:
        """Validate a raw config dict in-place, warning and fixing invalid fields."""
        defaults = get_default_config()

        if "version" in raw and not isinstance(raw["version"], str):
            print('rafter: config "version" must be a string — using default.', file=sys.stderr)
            raw["version"] = defaults.version

        agent = raw.get("agent")
        if not isinstance(agent, dict):
            return

        # risk_level / riskLevel
        rl = agent.get("riskLevel", agent.get("risk_level"))
        if rl is not None and rl not in _VALID_RISK_LEVELS:
            print(f'rafter: config "agent.riskLevel" must be one of: {", ".join(sorted(_VALID_RISK_LEVELS))} — using default.', file=sys.stderr)
            agent.pop("riskLevel", None)
            agent.pop("risk_level", None)

        # commandPolicy / command_policy
        cp = agent.get("commandPolicy") or agent.get("command_policy")
        if isinstance(cp, dict):
            if "mode" in cp and cp["mode"] not in _VALID_COMMAND_MODES:
                print(f'rafter: config "commandPolicy.mode" must be one of: {", ".join(sorted(_VALID_COMMAND_MODES))} — using default.', file=sys.stderr)
                del cp["mode"]
            for key in ("blockedPatterns", "blocked_patterns"):
                if key in cp and (not isinstance(cp[key], list) or not all(isinstance(v, str) for v in cp[key])):
                    print(f'rafter: config "commandPolicy.{key}" must be an array of strings — using default.', file=sys.stderr)
                    del cp[key]
            for key in ("requireApproval", "require_approval"):
                if key in cp and (not isinstance(cp[key], list) or not all(isinstance(v, str) for v in cp[key])):
                    print(f'rafter: config "commandPolicy.{key}" must be an array of strings — using default.', file=sys.stderr)
                    del cp[key]

        # audit
        audit = agent.get("audit")
        if isinstance(audit, dict):
            rd = audit.get("retentionDays", audit.get("retention_days"))
            if rd is not None and not isinstance(rd, (int, float)):
                print('rafter: config "audit.retentionDays" must be a number — using default.', file=sys.stderr)
                audit.pop("retentionDays", None)
                audit.pop("retention_days", None)
            ll = audit.get("logLevel", audit.get("log_level"))
            if ll is not None and ll not in _VALID_LOG_LEVELS:
                print(f'rafter: config "audit.logLevel" must be one of: {", ".join(sorted(_VALID_LOG_LEVELS))} — using default.', file=sys.stderr)
                audit.pop("logLevel", None)
                audit.pop("log_level", None)

        # scan.customPatterns — validate regex compilation
        scan = agent.get("scan")
        if isinstance(scan, dict):
            for key in ("excludePaths", "exclude_paths"):
                if key in scan and (not isinstance(scan[key], list) or not all(isinstance(v, str) for v in scan[key])):
                    print(f'rafter: config "scan.{key}" must be an array of strings — using default.', file=sys.stderr)
                    del scan[key]
            for key in ("customPatterns", "custom_patterns"):
                if key in scan and isinstance(scan[key], list):
                    valid = []
                    for p in scan[key]:
                        if not isinstance(p, dict) or not isinstance(p.get("name"), str) or not p.get("name") or not isinstance(p.get("regex"), str) or not p.get("regex"):
                            print(f'rafter: skipping malformed scan.customPatterns entry — must have name and regex.', file=sys.stderr)
                            continue
                        try:
                            _re.compile(p["regex"])
                        except _re.error as exc:
                            print(f'rafter: skipping custom pattern {p["name"]!r} — invalid regex: {exc}', file=sys.stderr)
                            continue
                        valid.append(p)
                    scan[key] = valid

    # ------------------------------------------------------------------
    # Policy-merged config
    # ------------------------------------------------------------------

    def load_with_policy(self) -> RafterConfig:
        """Load config merged with .rafter.yml policy (policy wins)."""
        from .policy_loader import load_policy

        config = self.load()
        policy = load_policy()
        if not policy:
            return config

        if policy.get("risk_level"):
            config.agent.risk_level = policy["risk_level"]

        cp = policy.get("command_policy")
        if cp:
            if cp.get("mode"):
                config.agent.command_policy.mode = cp["mode"]
            if cp.get("blocked_patterns") is not None:
                config.agent.command_policy.blocked_patterns = cp["blocked_patterns"]
            if cp.get("require_approval") is not None:
                config.agent.command_policy.require_approval = cp["require_approval"]

        scan = policy.get("scan")
        if scan:
            if scan.get("exclude_paths") is not None:
                config.agent.scan.exclude_paths = scan["exclude_paths"]
            if scan.get("custom_patterns") is not None:
                from .config_schema import ScanCustomPattern

                config.agent.scan.custom_patterns = [
                    ScanCustomPattern(**p) for p in scan["custom_patterns"]
                ]

        audit = policy.get("audit")
        if audit:
            if audit.get("retention_days") is not None:
                config.agent.audit.retention_days = audit["retention_days"]
            if audit.get("log_level"):
                config.agent.audit.log_level = audit["log_level"]
            if audit.get("log_path"):
                config.agent.audit.log_path = audit["log_path"]

        return config

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_dict(config: RafterConfig) -> dict:
        return asdict(config)

    @staticmethod
    def _camel_to_snake(name: str) -> str:
        """Convert camelCase to snake_case."""
        return _re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()

    @classmethod
    def _pick_fields(cls, dc_class: type, raw: dict) -> dict:
        """Filter and remap a dict to only valid dataclass fields, handling camelCase."""
        valid = {f.name for f in _fields(dc_class)}
        out: dict = {}
        for k, v in raw.items():
            snake = cls._camel_to_snake(k)
            if snake in valid:
                out[snake] = v
        return out

    @classmethod
    def _from_dict(cls, d: dict) -> RafterConfig:
        from .config_schema import (
            AgentConfig,
            AuditConfig,
            BackendConfig,
            CommandPolicyConfig,
            EnvironmentConfig,
            EnvironmentsConfig,
            NotificationsConfig,
            OutputFilteringConfig,
            ScanConfig,
            ScanCustomPattern,
        )

        backend = BackendConfig(**cls._pick_fields(BackendConfig, d.get("backend") or {}))

        agent_raw = d.get("agent") or {}
        envs_raw = agent_raw.get("environments") or {}
        agent = AgentConfig(
            risk_level=agent_raw.get("riskLevel", agent_raw.get("risk_level", "moderate")),
            environments=EnvironmentsConfig(
                openclaw=EnvironmentConfig(**cls._pick_fields(EnvironmentConfig, envs_raw.get("openclaw") or {})),
                claude_code=EnvironmentConfig(**cls._pick_fields(EnvironmentConfig, envs_raw.get("claudeCode") or envs_raw.get("claude_code") or {})),
                codex=EnvironmentConfig(**cls._pick_fields(EnvironmentConfig, envs_raw.get("codex") or {})),
            ),
            command_policy=CommandPolicyConfig(**cls._pick_fields(CommandPolicyConfig, agent_raw.get("commandPolicy") or agent_raw.get("command_policy") or {})),
            output_filtering=OutputFilteringConfig(**cls._pick_fields(OutputFilteringConfig, agent_raw.get("outputFiltering") or agent_raw.get("output_filtering") or {})),
            audit=AuditConfig(**cls._pick_fields(AuditConfig, agent_raw.get("audit") or {})),
            notifications=NotificationsConfig(**cls._pick_fields(NotificationsConfig, agent_raw.get("notifications") or {})),
            scan=ScanConfig(
                exclude_paths=(agent_raw.get("scan") or {}).get("exclude_paths", (agent_raw.get("scan") or {}).get("excludePaths", [])),
                custom_patterns=[
                    ScanCustomPattern(**cls._pick_fields(ScanCustomPattern, p))
                    for p in (agent_raw.get("scan") or {}).get("custom_patterns", (agent_raw.get("scan") or {}).get("customPatterns", []))
                ],
            ),
            components=agent_raw.get("components") or {},
        )

        return RafterConfig(
            version=d.get("version", "1.0.0"),
            initialized=d.get("initialized", ""),
            backend=backend,
            agent=agent,
        )

    @staticmethod
    def _deep_merge(target: dict, source: dict) -> dict:
        out = {**target}
        for k, v in source.items():
            if isinstance(v, dict) and isinstance(out.get(k), dict):
                out[k] = ConfigManager._deep_merge(out[k], v)
            else:
                out[k] = v
        return out
