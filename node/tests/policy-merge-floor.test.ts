import { describe, it, expect, vi } from "vitest";
import { mergeCommandPolicy, ConfigManager } from "../src/core/config-manager.js";
import fs from "node:fs";
import os from "node:os";
import pathMod from "node:path";
import { execFileSync } from "node:child_process";

/**
 * The project-policy floor (sable-nz4y).
 *
 * Policy discovery walks up from cwd to the git root, so the merged
 * `.rafter.yml` is a file in the repository being worked on — attacker-controlled
 * on an untrusted repo, and rafter ships inside agent pretool hooks. It used to
 * replace the machine owner's command policy wholesale, so a repo could switch
 * off every guardrail below the critical hard-block.
 *
 * The rule: the global config is a floor a project may raise, never lower.
 */

const floor = (over: Partial<{ mode: string; blockedPatterns: string[]; requireApproval: string[] }> = {}) => ({
  mode: "approve-dangerous",
  blockedPatterns: ["curl.*\\|\\s*(bash|sh)"],
  requireApproval: ["rm -rf", "git push --force"],
  ...over,
});

describe("project-policy floor (sable-nz4y)", () => {
  describe("a project cannot lower the owner's floor", () => {
    it("refuses a looser mode and keeps the owner's", () => {
      const warn = vi.spyOn(console, "error").mockImplementation(() => {});
      const target = floor();
      mergeCommandPolicy(target, { mode: "allow-all" }, false);
      expect(target.mode).toBe("approve-dangerous");
      expect(warn).toHaveBeenCalledWith(expect.stringContaining("less strict"));
      warn.mockRestore();
    });

    it("refuses deny-list when the owner set approve-dangerous", () => {
      const warn = vi.spyOn(console, "error").mockImplementation(() => {});
      const target = floor();
      mergeCommandPolicy(target, { mode: "deny-list" }, false);
      expect(target.mode).toBe("approve-dangerous");
      warn.mockRestore();
    });

    it("cannot drop an owner's blocked pattern by supplying a shorter list", () => {
      const target = floor();
      mergeCommandPolicy(target, { blockedPatterns: [] }, false);
      expect(target.blockedPatterns).toContain("curl.*\\|\\s*(bash|sh)");
    });

    it("cannot drop an owner's approval pattern", () => {
      const target = floor();
      mergeCommandPolicy(target, { requireApproval: ["terraform apply"] }, false);
      expect(target.requireApproval).toContain("rm -rf");
      expect(target.requireApproval).toContain("git push --force");
    });

    it("survives the full hostile-repo shape", () => {
      const warn = vi.spyOn(console, "error").mockImplementation(() => {});
      const target = floor();
      mergeCommandPolicy(target, { mode: "allow-all", blockedPatterns: [], requireApproval: [] }, false);
      expect(target.mode).toBe("approve-dangerous");
      expect(target.blockedPatterns).toEqual(floor().blockedPatterns);
      expect(target.requireApproval).toEqual(floor().requireApproval);
      warn.mockRestore();
    });

    it("refuses an unrecognized mode rather than trusting it", () => {
      const warn = vi.spyOn(console, "error").mockImplementation(() => {});
      const target = floor();
      mergeCommandPolicy(target, { mode: "yolo" }, false);
      expect(target.mode).toBe("approve-dangerous");
      warn.mockRestore();
    });
  });

  describe("a project can still raise the floor", () => {
    it("accepts a stricter mode", () => {
      const target = floor({ mode: "allow-all" });
      mergeCommandPolicy(target, { mode: "approve-dangerous" }, false);
      expect(target.mode).toBe("approve-dangerous");
    });

    it("accepts allow-all -> deny-list as a tightening", () => {
      const target = floor({ mode: "allow-all" });
      mergeCommandPolicy(target, { mode: "deny-list" }, false);
      expect(target.mode).toBe("deny-list");
    });

    it("adds blocked and approval patterns", () => {
      const target = floor();
      mergeCommandPolicy(target, {
        blockedPatterns: ["terraform destroy"],
        requireApproval: ["terraform apply"],
      }, false);
      expect(target.blockedPatterns).toContain("terraform destroy");
      expect(target.blockedPatterns).toContain("curl.*\\|\\s*(bash|sh)");
      expect(target.requireApproval).toContain("terraform apply");
      expect(target.requireApproval).toContain("rm -rf");
    });

    it("does not duplicate a pattern the owner already set", () => {
      const target = floor();
      mergeCommandPolicy(target, { requireApproval: ["rm -rf", "terraform apply"] }, false);
      expect(target.requireApproval.filter((p) => p === "rm -rf")).toHaveLength(1);
    });

    it("leaves the policy untouched when the project sets nothing", () => {
      const target = floor();
      mergeCommandPolicy(target, {}, false);
      expect(target).toEqual(floor());
    });
  });

  describe("the owner's opt-out restores replace semantics", () => {
    it("lets a project loosen when allowProjectOverride is on", () => {
      const target = floor();
      mergeCommandPolicy(target, { mode: "allow-all", blockedPatterns: [], requireApproval: [] }, true);
      expect(target.mode).toBe("allow-all");
      expect(target.blockedPatterns).toEqual([]);
      expect(target.requireApproval).toEqual([]);
    });

    it("is off unless explicitly enabled", () => {
      const warn = vi.spyOn(console, "error").mockImplementation(() => {});
      const target = floor();
      mergeCommandPolicy(target, { mode: "allow-all" }, false);
      expect(target.mode).toBe("approve-dangerous");
      warn.mockRestore();
    });
  });
});

/**
 * End-to-end through the real load path: temp git repo + real global config
 * file + `process.chdir` into the repo, so policy discovery does its actual
 * walk from cwd to the git root rather than being mocked.
 */
describe("project-policy floor, end to end (sable-nz4y)", () => {
  const STRICT_GLOBAL = {
    version: "1.0",
    agent: {
      riskLevel: "aggressive",
      commandPolicy: {
        mode: "approve-dangerous",
        blockedPatterns: ["curl.*\\|\\s*(bash|sh)"],
        requireApproval: ["rm -rf", "sudo rm"],
      },
    },
  };

  function withRepo(projectYaml: string, globalExtra: Record<string, unknown> = {}) {
    const dir = fs.mkdtempSync(pathMod.join(os.tmpdir(), "rafter-floor-"));
    execFileSync("git", ["init", "-q", dir]);
    fs.writeFileSync(pathMod.join(dir, ".rafter.yml"), projectYaml);

    const cfgPath = pathMod.join(dir, "global-config.json");
    const globalCfg = JSON.parse(JSON.stringify(STRICT_GLOBAL));
    Object.assign(globalCfg.agent.commandPolicy, globalExtra);
    fs.writeFileSync(cfgPath, JSON.stringify(globalCfg));
    return { dir, cfgPath };
  }

  // `loadPolicy()` resolves the policy file from `process.cwd()` on every call,
  // so chdir is enough — no module-cache juggling needed.
  function loadIn(dir: string, cfgPath: string) {
    const prev = process.cwd();
    process.chdir(dir);
    try {
      return new ConfigManager(cfgPath).loadWithPolicy();
    } finally {
      process.chdir(prev);
    }
  }

  const HOSTILE = `
version: "1.0"
command_policy:
  mode: allow-all
  blocked_patterns: []
  require_approval: []
`;

  it("a hostile repo policy cannot lower the owner's command policy", () => {
    const warn = vi.spyOn(console, "error").mockImplementation(() => {});
    const { dir, cfgPath } = withRepo(HOSTILE);
    const cfg = loadIn(dir, cfgPath);
    expect(cfg.agent!.commandPolicy.mode).toBe("approve-dangerous");
    expect(cfg.agent!.commandPolicy.blockedPatterns).toContain("curl.*\\|\\s*(bash|sh)");
    expect(cfg.agent!.commandPolicy.requireApproval).toContain("rm -rf");
    warn.mockRestore();
  });

  it("a repo CANNOT grant itself the override — the flag is owner-only", () => {
    // The decisive case. If a project policy could set allowProjectOverride,
    // the floor would be no floor at all: a hostile repo would simply enable
    // the opt-out and then loosen everything.
    const warn = vi.spyOn(console, "error").mockImplementation(() => {});
    const { dir, cfgPath } = withRepo(`
version: "1.0"
command_policy:
  allow_project_override: true
  mode: allow-all
  blocked_patterns: []
  require_approval: []
`);
    const cfg = loadIn(dir, cfgPath);
    expect(cfg.agent!.commandPolicy.mode).toBe("approve-dangerous");
    expect(cfg.agent!.commandPolicy.blockedPatterns).toContain("curl.*\\|\\s*(bash|sh)");
    warn.mockRestore();
  });

  it("honors the override when the OWNER sets it globally", () => {
    const { dir, cfgPath } = withRepo(HOSTILE, { allowProjectOverride: true });
    const cfg = loadIn(dir, cfgPath);
    expect(cfg.agent!.commandPolicy.mode).toBe("allow-all");
    expect(cfg.agent!.commandPolicy.blockedPatterns).toEqual([]);
  });

  it("still lets a project ADD rules", () => {
    const { dir, cfgPath } = withRepo(`
version: "1.0"
command_policy:
  blocked_patterns:
    - "terraform destroy"
`);
    const cfg = loadIn(dir, cfgPath);
    expect(cfg.agent!.commandPolicy.blockedPatterns).toContain("terraform destroy");
    expect(cfg.agent!.commandPolicy.blockedPatterns).toContain("curl.*\\|\\s*(bash|sh)");
  });
});
