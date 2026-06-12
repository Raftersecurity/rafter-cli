"""Resolve whether the PreToolUse hook (and its sub-parts) should act.

Mirror of node/src/core/hook-control.ts — keep the two in lockstep.

SECURITY (secure-design D1): the disable signal is honored ONLY from trusted,
machine-owner-owned sources — the global ``~/.rafter/config.json`` and the
``RAFTER_DISABLE_*`` env vars. It is NEVER read from project-local ``.rafter.yml``,
so cloning a hostile repo cannot silently disable a victim's secret scanning or
command interception. Enforced structurally: this reads ``ConfigManager().load()``
(global only), NOT ``load_with_policy()``, and ``hooks`` is absent from the policy
schema. Precedence (D5): env overrides global. Default (D2): enabled; an unreadable
config or unrecognized value fails safe to enabled.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .config_schema import RafterConfig


@dataclass
class HookControl:
    hook_enabled: bool
    secret_scan_enabled: bool
    command_policy_enabled: bool
    # Attribution per axis: "default" | "global-config" | "env"
    source_hook: str
    source_secret_scan: str
    source_command_policy: str


def _env_tristate(raw: str | None) -> bool | None:
    """True = disable, False = force-enable, None = unset/unrecognized (defer).

    Deliberately strict so a stray value fails safe to "defer" rather than
    silently disabling a security control (secure-design D2).
    """
    if raw is None:
        return None
    v = raw.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return None


def resolve_hook_control(
    config: RafterConfig | None = None,
    env: dict | None = None,
) -> HookControl:
    env = env if env is not None else os.environ

    cfg = config
    if cfg is None:
        try:
            from .config_manager import ConfigManager

            cfg = ConfigManager().load()
        except Exception:
            # Unreadable/corrupt global config must not disable the hook — fail safe.
            cfg = None
    h = cfg.agent.hooks if cfg is not None else None

    def resolve(env_val: bool | None, global_disabled: bool | None) -> tuple[bool, str]:
        # env wins over global; absent → default enabled.
        if env_val is not None:
            return (not env_val, "env")
        if global_disabled is True:
            return (False, "global-config")
        return (True, "default")

    hook_enabled, hook_src = resolve(
        _env_tristate(env.get("RAFTER_DISABLE_HOOKS")),
        True if (h is not None and h.enabled is False) else None,
    )

    if hook_enabled:
        ss_enabled, ss_src = resolve(
            _env_tristate(env.get("RAFTER_DISABLE_SECRET_SCAN")),
            True if (h is not None and h.secret_scan is False) else None,
        )
        cp_enabled, cp_src = resolve(
            _env_tristate(env.get("RAFTER_DISABLE_COMMAND_POLICY")),
            True if (h is not None and h.command_policy is False) else None,
        )
    else:
        # A disabled master switch forces every sub-part off.
        ss_enabled, ss_src = False, hook_src
        cp_enabled, cp_src = False, hook_src

    return HookControl(
        hook_enabled=hook_enabled,
        secret_scan_enabled=ss_enabled,
        command_policy_enabled=cp_enabled,
        source_hook=hook_src,
        source_secret_scan=ss_src,
        source_command_policy=cp_src,
    )
