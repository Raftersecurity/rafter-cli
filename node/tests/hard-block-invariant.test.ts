/**
 * The hard-block invariant, pinned.
 *
 * `CommandInterceptor.evaluate()` returns on `riskLevel === "critical"` BEFORE
 * it loads any policy, so a CRITICAL command is denied no matter what policy is
 * discovered — or whether one is discovered at all. That is the strongest claim
 * the tool makes ("no policy, mode, or deny-list can opt out of these"), and
 * until now it was asserted only in a source comment: moving the policy load
 * above the critical check would have broken it with the suite still green.
 *
 * These tests use the real discovery path rather than a stubbed loader — a temp
 * git repo, a fake HOME, and cwd inside the repo — so they also fail if policy
 * *merging* ever lets a project file reach the hard-block set. A test that
 * stubs `loadWithPolicy` cannot see that class of regression.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { randomBytes } from "crypto";

/**
 * Commands that must never be allowed. One per CRITICAL rule family, written
 * in the form that actually destroys a machine rather than the form that merely
 * matches the regex.
 */
const CRITICAL_COMMANDS: string[] = [
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
];

/**
 * Policy files that each try, in a different way, to permit the above. Shape 1
 * is the absence of a policy — security must not depend on one being present.
 */
const HOSTILE_POLICIES: Array<{ name: string; yaml: string | null }> = [
  {
    name: "no policy file at all",
    yaml: null,
  },
  {
    name: "project replaces the deny-list with one unrelated rule",
    yaml: `version: "1"\ncommand_policy:\n  blocked_patterns:\n    - dangerous-cmd\n`,
  },
  {
    name: "project replaces the approval list with one unrelated rule",
    yaml: `version: "1"\ncommand_policy:\n  require_approval:\n    - git push\n`,
  },
  {
    name: "project sets mode: allow-all",
    yaml: `version: "1"\ncommand_policy:\n  mode: allow-all\n`,
  },
  {
    name: "project sets allow-all and empties both lists",
    yaml: `version: "1"\ncommand_policy:\n  mode: allow-all\n  blocked_patterns: []\n  require_approval: []\n`,
  },
  {
    name: "project names the hard-blocked commands in require_approval",
    yaml: `version: "1"\ncommand_policy:\n  mode: allow-all\n  blocked_patterns: []\n  require_approval:\n    - rm -rf\n    - mkfs\n`,
  },
];

let tmpRoot: string;
let repoDir: string;
let fakeHome: string;
let originalCwd: string;
let originalHome: string | undefined;

beforeAll(() => {
  originalCwd = process.cwd();
  originalHome = process.env.HOME;
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), `rafter-hardblock-${randomBytes(4).toString("hex")}-`));
  repoDir = path.join(tmpRoot, "repo");
  fakeHome = path.join(tmpRoot, "home");
  fs.mkdirSync(repoDir, { recursive: true });
  fs.mkdirSync(fakeHome, { recursive: true });
  // A real git repo: findPolicyFile walks from cwd up to the git root, so the
  // walk must terminate inside the fixture and never reach the user's tree.
  execFileSync("git", ["init", "-q"], { cwd: repoDir });
});

afterAll(() => {
  process.chdir(originalCwd);
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

beforeEach(() => {
  // os.homedir() reads $HOME on POSIX, and ConfigManager resolves its path in
  // the constructor — so set HOME before constructing the interceptor.
  process.env.HOME = fakeHome;
  process.chdir(repoDir);
});

afterEach(() => {
  process.chdir(originalCwd);
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  for (const f of [".rafter.yml", ".rafter.yaml"]) {
    fs.rmSync(path.join(repoDir, f), { force: true });
  }
  fs.rmSync(path.join(fakeHome, ".rafter", "config.json"), { force: true });
});

/** Import fresh so the interceptor is constructed under the fixture's HOME. */
async function newInterceptor() {
  const { CommandInterceptor } = await import("../src/core/command-interceptor.js");
  return new CommandInterceptor();
}

describe("CRITICAL hard-block survives every policy shape", () => {
  for (const policy of HOSTILE_POLICIES) {
    describe(policy.name, () => {
      for (const command of CRITICAL_COMMANDS) {
        it(`denies ${JSON.stringify(command)}`, async () => {
          if (policy.yaml !== null) {
            fs.writeFileSync(path.join(repoDir, ".rafter.yml"), policy.yaml);
          }
          const result = (await newInterceptor()).evaluate(command);

          expect(result.riskLevel).toBe("critical");
          expect(result.allowed).toBe(false);
          // Not merely gated behind an approval prompt — a prompt is something
          // an agent or a user can say yes to.
          expect(result.requiresApproval).toBe(false);
          expect(result.matchedPattern).toBeTruthy();
        });
      }
    });
  }

  it("holds when a permissive global config and a permissive project policy are combined", async () => {
    fs.mkdirSync(path.join(fakeHome, ".rafter"), { recursive: true });
    fs.writeFileSync(
      path.join(fakeHome, ".rafter", "config.json"),
      JSON.stringify({
        version: "1.0.0",
        agent: {
          riskLevel: "permissive",
          commandPolicy: { mode: "allow-all", blockedPatterns: [], requireApproval: [] },
        },
      })
    );
    fs.writeFileSync(
      path.join(repoDir, ".rafter.yml"),
      `version: "1"\ncommand_policy:\n  mode: allow-all\n  blocked_patterns: []\n  require_approval: []\n`
    );

    const interceptor = await newInterceptor();
    for (const command of CRITICAL_COMMANDS) {
      const result = interceptor.evaluate(command);
      expect(result.allowed, `${command} was allowed`).toBe(false);
      expect(result.requiresApproval, `${command} was only approval-gated`).toBe(false);
    }
  });

  it("still lets the same policies do their job on non-critical commands", async () => {
    // Guard against the invariant being "satisfied" by an interceptor that
    // denies everything: allow-all must still allow a benign command.
    fs.writeFileSync(
      path.join(repoDir, ".rafter.yml"),
      `version: "1"\ncommand_policy:\n  mode: allow-all\n  blocked_patterns: []\n  require_approval: []\n`
    );
    const result = (await newInterceptor()).evaluate("echo hello");
    expect(result.allowed).toBe(true);
    expect(result.riskLevel).toBe("low");
  });
});
