/**
 * Disk tools are catastrophic when INVOKED, not when named.
 *
 * `mkfs`, `fdisk` and `parted` were bare substrings in CRITICAL_PATTERNS — the
 * UNCONDITIONAL tier, which no policy, mode, or deny-list can opt out of, and
 * which DEFAULT_BLOCKED_PATTERNS mirrors byte for byte. So `vim departed.md`
 * ('departed' contains 'parted') was a hard block the user could not configure
 * their way out of, on a tool that ships inside agent hooks.
 *
 * Both directions are pinned here, because the fix is a narrowing and a
 * narrowing is where a bypass gets in: every command in INVOCATIONS destroys a
 * disk and must stay critical, and every command in BENIGN must not.
 */
import { describe, it, expect } from "vitest";
import { assessCommandRisk } from "../src/core/risk-rules.js";
import { CommandInterceptor } from "../src/core/command-interceptor.js";

/** Ordinary commands that merely contain the letters of a disk tool. */
const BENIGN = [
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
];

/**
 * Real invocations. The shell-nesting, wrapper, path and assignment forms are
 * here because each one was measured escaping an anchor that only allowed
 * line-start and shell operators — narrowing without them would have traded a
 * false positive for a bypass.
 */
const INVOCATIONS = [
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
];

describe("disk tools named, not invoked", () => {
  it.each(BENIGN)("does not hard-block %j", (command) => {
    expect(assessCommandRisk(command)).not.toBe("critical");
  });

  it("lets the interceptor allow them — the user-visible half of the bug", () => {
    const interceptor = new CommandInterceptor();
    for (const command of BENIGN) {
      const result = interceptor.evaluate(command);
      expect(result.riskLevel, `${command} assessed critical`).not.toBe("critical");
    }
  });
});

describe("disk tools invoked", () => {
  it.each(INVOCATIONS)("still hard-blocks %j", (command) => {
    expect(assessCommandRisk(command)).toBe("critical");
  });

  it("keeps them unconditional — an allow-all deny-list cannot reach them", () => {
    const interceptor = new CommandInterceptor();
    for (const command of INVOCATIONS) {
      const result = interceptor.evaluate(command);
      expect(result.allowed, `${command} was allowed`).toBe(false);
      expect(result.requiresApproval, `${command} was only approval-gated`).toBe(false);
    }
  });
});
