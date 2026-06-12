"""Mirror of node/tests/hook-control.test.ts + hook-offswitch-integration.test.ts.

Keep the two in lockstep — same cases, same expectations (parity invariant).
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from rafter_cli.core.config_schema import AgentConfig, HooksConfig, RafterConfig
from rafter_cli.core.hook_control import resolve_hook_control


def _cfg(hooks: HooksConfig | None) -> RafterConfig:
    return RafterConfig(agent=AgentConfig(hooks=hooks or HooksConfig()))


# ── Defaults (fail-safe) ──────────────────────────────────────────────────
def test_default_all_enabled():
    c = resolve_hook_control(config=_cfg(None), env={})
    assert (c.hook_enabled, c.secret_scan_enabled, c.command_policy_enabled) == (True, True, True)
    assert (c.source_hook, c.source_secret_scan, c.source_command_policy) == ("default",) * 3


def test_unrecognized_env_does_not_disable():
    c = resolve_hook_control(config=_cfg(None), env={"RAFTER_DISABLE_HOOKS": "maybe"})
    assert c.hook_enabled is True
    assert c.source_hook == "default"


# ── Env disable ───────────────────────────────────────────────────────────
@pytest.mark.parametrize("v", ["1", "true", "yes", "on", "TRUE", " On "])
def test_env_disables_whole_hook(v):
    c = resolve_hook_control(config=_cfg(None), env={"RAFTER_DISABLE_HOOKS": v})
    assert (c.hook_enabled, c.secret_scan_enabled, c.command_policy_enabled) == (False, False, False)
    assert c.source_hook == "env"


def test_env_disables_secret_scan_only():
    c = resolve_hook_control(config=_cfg(None), env={"RAFTER_DISABLE_SECRET_SCAN": "1"})
    assert (c.hook_enabled, c.secret_scan_enabled, c.command_policy_enabled) == (True, False, True)
    assert c.source_secret_scan == "env"


def test_env_disables_command_policy_only():
    c = resolve_hook_control(config=_cfg(None), env={"RAFTER_DISABLE_COMMAND_POLICY": "1"})
    assert (c.hook_enabled, c.secret_scan_enabled, c.command_policy_enabled) == (True, True, False)


# ── Global config disable ─────────────────────────────────────────────────
def test_global_disables_whole_hook():
    c = resolve_hook_control(config=_cfg(HooksConfig(enabled=False)), env={})
    assert c.hook_enabled is False
    assert c.source_hook == "global-config"


def test_global_disables_secret_scan_only():
    c = resolve_hook_control(config=_cfg(HooksConfig(secret_scan=False)), env={})
    assert (c.hook_enabled, c.secret_scan_enabled, c.command_policy_enabled) == (True, False, True)
    assert c.source_secret_scan == "global-config"


def test_explicit_enabled_true_is_on():
    c = resolve_hook_control(config=_cfg(HooksConfig(enabled=True)), env={})
    assert c.hook_enabled is True


# ── Precedence (env wins over global) ─────────────────────────────────────
def test_env_force_enable_overrides_global_disable():
    c = resolve_hook_control(config=_cfg(HooksConfig(enabled=False)), env={"RAFTER_DISABLE_HOOKS": "0"})
    assert c.hook_enabled is True
    assert c.source_hook == "env"


def test_env_disable_overrides_global_enable():
    c = resolve_hook_control(config=_cfg(HooksConfig(enabled=True)), env={"RAFTER_DISABLE_HOOKS": "1"})
    assert c.hook_enabled is False
    assert c.source_hook == "env"


# ── End-to-end via the real CLI (security property) ───────────────────────
SECRET_WRITE = json.dumps({"tool_name": "Write", "tool_input": {"content": "aws_key = AKIAIOSFODNN7EXAMPLE"}})


_PKG_ROOT = str(Path(__file__).resolve().parent.parent)


def _run_hook(cwd: str, extra_env: dict | None = None) -> str:
    # We override HOME so rafter reads its global config from the temp dir (and
    # not the developer's real ~/.rafter). That also moves Python's user
    # site-packages, so pass the parent's full sys.path to the child to keep
    # imports (typer, rafter_cli) resolvable regardless of HOME.
    pythonpath = os.pathsep.join([_PKG_ROOT, *(p for p in sys.path if p)])
    env = {
        **os.environ,
        "HOME": cwd,
        "XDG_CONFIG_HOME": os.path.join(cwd, ".config"),
        "PYTHONPATH": pythonpath,
    }
    if extra_env:
        env.update(extra_env)
    r = subprocess.run(
        [sys.executable, "-m", "rafter_cli", "hook", "pretool"],
        input=SECRET_WRITE, capture_output=True, text=True, cwd=cwd, env=env, timeout=30,
    )
    return json.loads(r.stdout or "{}").get("hookSpecificOutput", {}).get("permissionDecision", "unknown")


def test_e2e_default_denies():
    with tempfile.TemporaryDirectory() as d:
        assert _run_hook(d) == "deny"


def test_e2e_env_disable_allows():
    with tempfile.TemporaryDirectory() as d:
        assert _run_hook(d, {"RAFTER_DISABLE_HOOKS": "1"}) == "allow"


def test_e2e_security_project_local_cannot_disable():
    with tempfile.TemporaryDirectory() as d:
        Path(d, ".rafter.yml").write_text(
            "hooks:\n  enabled: false\n  secretScan: false\n  commandPolicy: false\n"
        )
        os.makedirs(os.path.join(d, ".rafter"), exist_ok=True)
        Path(d, ".rafter", "config.yml").write_text("hooks:\n  enabled: false\n")
        assert _run_hook(d) == "deny"


def test_e2e_global_config_can_disable():
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, ".rafter"), exist_ok=True)
        Path(d, ".rafter", "config.json").write_text(
            json.dumps({"version": "1", "agent": {"hooks": {"enabled": False}}})
        )
        assert _run_hook(d) == "allow"
