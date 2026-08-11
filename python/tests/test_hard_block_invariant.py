"""The hard-block invariant, pinned.

``CommandInterceptor.evaluate()`` returns on ``risk_level == "critical"`` BEFORE
it loads any policy, so a CRITICAL command is denied no matter what policy is
discovered — or whether one is discovered at all. That is the strongest claim
the tool makes ("no policy, mode, or deny-list can opt out of these"), and until
now it was asserted only in a source comment: moving the policy load above the
critical check would have broken it with the suite still green.

These tests use the real discovery path rather than a patched loader — a temp
git repo, a fake HOME, and cwd inside the repo — so they also fail if policy
*merging* ever lets a project file reach the hard-block set. A test that patches
``load_with_policy`` cannot see that class of regression.

Mirrors node/tests/hard-block-invariant.test.ts.
"""
from __future__ import annotations

import json
import subprocess

import pytest

from rafter_cli.core.command_interceptor import CommandInterceptor

# Commands that must never be allowed. One per CRITICAL rule family, written in
# the form that actually destroys a machine rather than the form that merely
# matches the regex.
CRITICAL_COMMANDS = [
    "rm -rf /",
    "rm -rf /etc",
    "rm -fr /usr",
    "rm -r -f /home",
    "dd if=/dev/zero of=/dev/sda",
    "echo x > /dev/sda",
    "mkfs.ext4 /dev/sda1",
    "fdisk /dev/sda",
    "parted /dev/sda mklabel gpt",
    ":(){ :|:& };:",
]

# Policy files that each try, in a different way, to permit the above.
# The first is the *absence* of a policy — security must not depend on one
# being present.
HOSTILE_POLICIES = [
    ("no policy file at all", None),
    (
        "project replaces the deny-list with one unrelated rule",
        'version: "1"\ncommand_policy:\n  blocked_patterns:\n    - dangerous-cmd\n',
    ),
    (
        "project replaces the approval list with one unrelated rule",
        'version: "1"\ncommand_policy:\n  require_approval:\n    - git push\n',
    ),
    ("project sets mode: allow-all", 'version: "1"\ncommand_policy:\n  mode: allow-all\n'),
    (
        "project sets allow-all and empties both lists",
        'version: "1"\ncommand_policy:\n  mode: allow-all\n'
        "  blocked_patterns: []\n  require_approval: []\n",
    ),
    (
        "project names the hard-blocked commands in require_approval",
        'version: "1"\ncommand_policy:\n  mode: allow-all\n  blocked_patterns: []\n'
        "  require_approval:\n    - rm -rf\n    - mkfs\n",
    ),
]

ALLOW_ALL_YAML = (
    'version: "1"\ncommand_policy:\n  mode: allow-all\n'
    "  blocked_patterns: []\n  require_approval: []\n"
)


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """Temp git repo as cwd, fake HOME, both isolated from the real machine."""
    repo = tmp_path / "repo"
    home = tmp_path / "home"
    repo.mkdir()
    home.mkdir()
    # A real git repo: find_policy_file walks from cwd up to the git root, so
    # the walk must terminate inside the fixture and never reach the user's tree.
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    monkeypatch.chdir(repo)
    # Path.home() reads $HOME on POSIX; ConfigManager resolves its path lazily,
    # but set both env vars before constructing the interceptor regardless.
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return repo, home


@pytest.mark.parametrize("command", CRITICAL_COMMANDS)
@pytest.mark.parametrize(
    "policy_yaml", [p[1] for p in HOSTILE_POLICIES], ids=[p[0] for p in HOSTILE_POLICIES]
)
def test_critical_is_denied_under_every_policy_shape(sandbox, command, policy_yaml):
    repo, _ = sandbox
    if policy_yaml is not None:
        (repo / ".rafter.yml").write_text(policy_yaml)

    result = CommandInterceptor().evaluate(command)

    assert result.risk_level == "critical"
    assert result.allowed is False
    # Not merely gated behind an approval prompt — a prompt is something an
    # agent or a user can say yes to.
    assert result.requires_approval is False
    assert result.matched_pattern


def test_holds_with_permissive_global_config_and_permissive_project_policy(sandbox):
    repo, home = sandbox
    rafter_dir = home / ".rafter"
    rafter_dir.mkdir()
    (rafter_dir / "config.json").write_text(
        json.dumps(
            {
                "version": "1.0.0",
                "agent": {
                    "risk_level": "permissive",
                    "command_policy": {
                        "mode": "allow-all",
                        "blocked_patterns": [],
                        "require_approval": [],
                    },
                },
            }
        )
    )
    (repo / ".rafter.yml").write_text(ALLOW_ALL_YAML)

    interceptor = CommandInterceptor()
    for command in CRITICAL_COMMANDS:
        result = interceptor.evaluate(command)
        assert result.allowed is False, f"{command} was allowed"
        assert result.requires_approval is False, f"{command} was only approval-gated"


def test_allow_all_still_allows_a_benign_command(sandbox):
    # Guard against the invariant being "satisfied" by an interceptor that
    # denies everything: allow-all must still allow a benign command.
    repo, _ = sandbox
    (repo / ".rafter.yml").write_text(ALLOW_ALL_YAML)

    result = CommandInterceptor().evaluate("echo hello")

    assert result.allowed is True
    assert result.risk_level == "low"
