/**
 * A config written by the Python CLI must be readable here.
 *
 * Python writes snake_case (`log_all_actions`, `command_policy`, `risk_level`);
 * this implementation writes and reads camelCase. Nothing rejected the other
 * spelling — it read as `undefined`. So `rafter agent init` under the Python
 * CLI left every Node audit write a silent no-op and the command policy at its
 * defaults, with no error either time. Python has tolerated both spellings
 * since it shipped (ConfigManager._pick_fields); this pins the mirror image.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { randomBytes } from "crypto";
import { ConfigManager, normalizeConfigKeys } from "../src/core/config-manager.js";
import { AuditLogger } from "../src/core/audit-logger.js";

/** A config in exactly the shape `python -m rafter_cli agent init` writes. */
function pythonWrittenConfig() {
  return {
    version: "1.0.0",
    initialized: "2026-08-11T00:00:00.000Z",
    agent: {
      risk_level: "aggressive",
      audit: { log_all_actions: true, retention_days: 30, log_level: "info", log_path: null },
      command_policy: {
        mode: "deny-list",
        blocked_patterns: ["never-run-me"],
        require_approval: ["ask-me-first"],
      },
      scan: { exclude_paths: ["vendor/"], auto_update_betterleaks: false },
      components: { "claude-code.hooks": { enabled: true, updated_at: "2026-08-11T00:00:00Z" } },
    },
  };
}

let tmpDir: string;
let configPath: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `rafter-cfg-${randomBytes(4).toString("hex")}-`));
  configPath = path.join(tmpDir, "config.json");
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("normalizeConfigKeys", () => {
  it("maps snake_case keys to camelCase at every depth", () => {
    const out: any = normalizeConfigKeys(pythonWrittenConfig());
    expect(out.agent.riskLevel).toBe("aggressive");
    expect(out.agent.audit.logAllActions).toBe(true);
    expect(out.agent.audit.retentionDays).toBe(30);
    expect(out.agent.commandPolicy.blockedPatterns).toEqual(["never-run-me"]);
    expect(out.agent.commandPolicy.requireApproval).toEqual(["ask-me-first"]);
    expect(out.agent.scan.excludePaths).toEqual(["vendor/"]);
    expect(out.agent.scan.autoUpdateBetterleaks).toBe(false);
  });

  it("leaves data-keyed maps' keys alone while normalizing their values", () => {
    const out: any = normalizeConfigKeys(pythonWrittenConfig());
    // "claude-code.hooks" is a component ID, not a field name.
    expect(Object.keys(out.agent.components)).toEqual(["claude-code.hooks"]);
    expect(out.agent.components["claude-code.hooks"].updatedAt).toBe("2026-08-11T00:00:00Z");
  });

  it("keeps the camelCase value when a config holds both spellings", () => {
    const out: any = normalizeConfigKeys({
      agent: { audit: { logAllActions: false, log_all_actions: true } },
    });
    expect(out.agent.audit.logAllActions).toBe(false);
  });

  it("leaves an already-camelCase config unchanged", () => {
    const camel = {
      version: "1.0.0",
      agent: { riskLevel: "moderate", audit: { logAllActions: true } },
    };
    expect(normalizeConfigKeys(camel)).toEqual(camel);
  });

  it("passes through non-objects and arrays of scalars", () => {
    expect(normalizeConfigKeys(null)).toBe(null);
    expect(normalizeConfigKeys("a_b")).toBe("a_b");
    expect(normalizeConfigKeys(["a_b", 1])).toEqual(["a_b", 1]);
  });
});

describe("ConfigManager.load on a Python-written config", () => {
  it("reads the policy and audit settings this implementation looks for", () => {
    fs.writeFileSync(configPath, JSON.stringify(pythonWrittenConfig()));
    const cfg = new ConfigManager(configPath).load();

    expect(cfg.agent?.riskLevel).toBe("aggressive");
    expect(cfg.agent?.audit.logAllActions).toBe(true);
    expect(cfg.agent?.commandPolicy.mode).toBe("deny-list");
    expect(cfg.agent?.commandPolicy.blockedPatterns).toEqual(["never-run-me"]);
  });
});

describe("AuditLogger against a Python-written config", () => {
  it("writes the entry instead of silently dropping it", () => {
    fs.writeFileSync(configPath, JSON.stringify(pythonWrittenConfig()));
    const logPath = path.join(tmpDir, "audit.jsonl");
    const logger = new AuditLogger(logPath, new ConfigManager(configPath));

    logger.log({
      eventType: "command_intercepted",
      action: { command: "echo hi", riskLevel: "low" },
      securityCheck: { passed: true },
      resolution: { actionTaken: "allowed" },
    } as any);

    expect(fs.existsSync(logPath)).toBe(true);
    const lines = fs.readFileSync(logPath, "utf-8").trim().split("\n");
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]).action.command).toBe("echo hi");
  });

  it("still honors log_all_actions: false — normalization does not force logging on", () => {
    const cfg = pythonWrittenConfig();
    cfg.agent.audit.log_all_actions = false;
    fs.writeFileSync(configPath, JSON.stringify(cfg));
    const logPath = path.join(tmpDir, "audit.jsonl");
    const logger = new AuditLogger(logPath, new ConfigManager(configPath));

    logger.log({
      eventType: "command_intercepted",
      action: { command: "echo hi", riskLevel: "low" },
      securityCheck: { passed: true },
      resolution: { actionTaken: "allowed" },
    } as any);

    expect(fs.existsSync(logPath)).toBe(false);
  });
});
