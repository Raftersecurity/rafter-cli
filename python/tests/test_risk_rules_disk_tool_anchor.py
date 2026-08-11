"""Disk tools are catastrophic when INVOKED, not when named.

``mkfs``, ``fdisk`` and ``parted`` were bare substrings in CRITICAL_PATTERNS —
the UNCONDITIONAL tier, which no policy, mode, or deny-list can opt out of, and
which DEFAULT_BLOCKED_PATTERNS mirrors byte for byte. So ``vim departed.md``
('departed' contains 'parted') was a hard block the user could not configure
their way out of, on a tool that ships inside agent hooks.

Both directions are pinned here, because the fix is a narrowing and a narrowing
is where a bypass gets in.

Mirrors node/tests/risk-rules-disk-tool-anchor.test.ts.
"""
from __future__ import annotations

import pytest

from rafter_cli.core.risk_rules import assess_command_risk

# Ordinary commands that merely contain the letters of a disk tool.
BENIGN = [
    "vim departed.md",
    "cat notes-parted.txt",
    "man parted",
    "man fdisk",
    "which mkfs",
    "ls /usr/share/doc/parted",
    "git log --grep parted",
    "cargo build -p parted",
    "npm i parted-utils",
    "./sfdisk-wrapper.sh",
    "docker run alpine mkfs --help",
    "pytest tests/test_fdisk.py",
    "python3 test_mkfs_parser.py",
    "git commit -m 'departed from the old approach'",
    "grep -r mkfs docs/",
    "echo parted",
    "rg parted",
    "code src/parted-view.tsx",
    "mv departed.md archive/",
    "less /var/log/parted.log",
    "make test-fdisk",
    "sed -i 's/parted/replaced/' notes.md",
    "curl https://example.com/parted.tar.gz",
]

# Real invocations. The shell-nesting, wrapper, path and assignment forms are
# here because each was measured escaping an anchor that only allowed line-start
# and shell operators — narrowing without them would have traded a false
# positive for a bypass.
INVOCATIONS = [
    "mkfs.ext4 /dev/sda1",
    "mkfs -t ext4 /dev/sdb",
    "mkfs.btrfs /dev/sdc",
    "sudo mkfs.xfs /dev/nvme0n1p1",
    "sudo -E mkfs.ext4 /dev/sda1",
    "fdisk /dev/sda",
    "sudo fdisk /dev/sda",
    "sfdisk /dev/sda < layout.txt",
    "parted /dev/sda mklabel gpt",
    "sudo parted -s /dev/sda mklabel gpt",
    "echo x; mkfs.ext4 /dev/sda1",
    "true && fdisk /dev/sda",
    "true || mkfs.ext4 /dev/sda1",
    "true; mkfs.ext4 /dev/sda1",
    "sh -c 'mkfs.ext4 /dev/sda1'",
    'bash -c "fdisk /dev/sda"',
    "sudo sh -c 'mkfs.ext4 /dev/sda1'",
    "`mkfs.ext4 /dev/sda1`",
    "$(mkfs.ext4 /dev/sda1)",
    "xargs mkfs.ext4",
    "timeout 5 fdisk /dev/sda",
    "nice -n 5 mkfs.ext4 /dev/sda1",
    "if true; then mkfs.ext4 /dev/sda1; fi",
    "for d in sda sdb; do mkfs.ext4 /dev/$d; done",
    "  mkfs.ext4 /dev/sda1",
    "/sbin/mkfs.ext4 /dev/sda1",
    "/usr/sbin/parted /dev/sda mklabel gpt",
    "MKFS=1 mkfs.ext4 /dev/sda1",
    "env DEBIAN_FRONTEND=noninteractive parted /dev/sda mklabel gpt",
    "cd /tmp && sudo parted /dev/sda mklabel gpt",
    "mkfs",
    "parted",
]


@pytest.mark.parametrize("command", BENIGN)
def test_named_not_invoked_is_not_hard_blocked(command):
    assert assess_command_risk(command) != "critical"


@pytest.mark.parametrize("command", INVOCATIONS)
def test_invoked_is_still_hard_blocked(command):
    assert assess_command_risk(command) == "critical"


def test_benign_commands_are_allowed_by_the_interceptor(tmp_path, monkeypatch):
    """The user-visible half of the bug: an editor command was a hard block."""
    from rafter_cli.core.command_interceptor import CommandInterceptor

    monkeypatch.setenv("HOME", str(tmp_path))
    interceptor = CommandInterceptor()
    for command in BENIGN:
        assert interceptor.evaluate(command).risk_level != "critical", command


def test_invocations_stay_unconditional(tmp_path, monkeypatch):
    """An allow-all deny-list must not be able to reach these."""
    from rafter_cli.core.command_interceptor import CommandInterceptor

    monkeypatch.setenv("HOME", str(tmp_path))
    interceptor = CommandInterceptor()
    for command in INVOCATIONS:
        result = interceptor.evaluate(command)
        assert result.allowed is False, command
        assert result.requires_approval is False, command
