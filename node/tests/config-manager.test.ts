import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { ConfigManager } from "../src/core/config-manager.js";
import fs from "fs";
import path from "path";
import os from "os";

describe("ConfigManager", () => {
  const testConfigPath = path.join(os.tmpdir(), `rafter-test-${Date.now()}.json`);
  let manager: ConfigManager;

  beforeEach(() => {
    manager = new ConfigManager(testConfigPath);
  });

  afterEach(() => {
    if (fs.existsSync(testConfigPath)) {
      fs.unlinkSync(testConfigPath);
    }
    vi.restoreAllMocks();
  });

  // ── Basic CRUD ──────────────────────────────────────────────

  it("should create default config", () => {
    const config = manager.load();

    expect(config.version).toBeDefined();
    expect(config.initialized).toBeDefined();
    expect(config.agent).toBeDefined();
    expect(config.agent?.riskLevel).toBe("moderate");
  });

  it("should save and load config", () => {
    const config = manager.load();
    config.agent!.riskLevel = "aggressive";

    manager.save(config);

    const loaded = manager.load();
    expect(loaded.agent?.riskLevel).toBe("aggressive");
  });

  it("should get nested values", () => {
    const config = manager.load();
    config.agent!.riskLevel = "minimal";
    manager.save(config);

    const value = manager.get("agent.riskLevel");

    expect(value).toBe("minimal");
  });

  it("should set nested values", () => {
    manager.set("agent.riskLevel", "aggressive");

    const value = manager.get("agent.riskLevel");
    expect(value).toBe("aggressive");
  });

  it("should handle deep nesting", () => {
    manager.set("agent.commandPolicy.mode", "deny-list");

    const value = manager.get("agent.commandPolicy.mode");
    expect(value).toBe("deny-list");
  });

  it("should return undefined for missing keys", () => {
    const value = manager.get("nonexistent.key");

    expect(value).toBeUndefined();
  });

  it("should deep merge updates", () => {
    manager.set("agent.riskLevel", "minimal");
    manager.set("agent.commandPolicy.mode", "allow-all");

    // Both values should persist
    expect(manager.get("agent.riskLevel")).toBe("minimal");
    expect(manager.get("agent.commandPolicy.mode")).toBe("allow-all");
  });

  it("should check if config exists", () => {
    expect(manager.exists()).toBe(false);

    manager.save(manager.load());

    expect(manager.exists()).toBe(true);
  });

  it("should initialize directory structure", async () => {
    await manager.initialize();

    expect(manager.exists()).toBe(true);
  });

  // ── Migration ───────────────────────────────────────────────

  it("should migrate old broad curl|sh pattern to word-bounded version", () => {
    const oldConfig = manager.load();
    oldConfig.agent!.commandPolicy!.requireApproval = [
      "rm -rf",
      "sudo rm",
      "curl.*\\|.*sh",
      "wget.*\\|.*sh",
      "chmod 777",
    ];
    manager.save(oldConfig);

    const loaded = manager.load();
    const patterns = loaded.agent!.commandPolicy!.requireApproval;

    expect(patterns).toContain("curl.*\\|\\s*(bash|sh|zsh|dash)\\b");
    expect(patterns).toContain("wget.*\\|\\s*(bash|sh|zsh|dash)\\b");
    expect(patterns).not.toContain("curl.*\\|.*sh");
    expect(patterns).not.toContain("wget.*\\|.*sh");
    expect(patterns).toContain("rm -rf");
    expect(patterns).toContain("chmod 777");
  });

  it("should not modify configs that already have the precise pattern", () => {
    const config = manager.load();
    const original = [...config.agent!.commandPolicy!.requireApproval];
    manager.save(config);

    const loaded = manager.load();
    expect(loaded.agent!.commandPolicy!.requireApproval).toEqual(original);
  });

  it("should bump version during migration", () => {
    const config = manager.load();
    config.version = "0.0.1";
    manager.save(config);

    const loaded = manager.load();
    expect(loaded.version).toBe("1.0.0");
  });

  // ── Deep merge ──────────────────────────────────────────────

  describe("deep merge behavior", () => {
    it("should preserve existing keys when merging partial updates", () => {
      const config = manager.load();
      config.agent!.riskLevel = "minimal";
      config.agent!.audit.retentionDays = 60;
      manager.save(config);

      // Update only audit logLevel, riskLevel should stay
      manager.update({ agent: { audit: { logLevel: "debug" } } } as any);

      expect(manager.get("agent.riskLevel")).toBe("minimal");
      expect(manager.get("agent.audit.logLevel")).toBe("debug");
      expect(manager.get("agent.audit.retentionDays")).toBe(60);
    });

    it("should replace arrays instead of merging them", () => {
      const config = manager.load();
      config.agent!.commandPolicy.blockedPatterns = ["rm -rf /", "dd if="];
      manager.save(config);

      manager.update({
        agent: { commandPolicy: { blockedPatterns: ["format c:"] } },
      } as any);

      const patterns = manager.get("agent.commandPolicy.blockedPatterns");
      expect(patterns).toEqual(["format c:"]);
    });

    it("should add new top-level keys via update", () => {
      manager.save(manager.load());
      manager.update({ backend: { apiKey: "test-key" } } as any);

      expect(manager.get("backend.apiKey")).toBe("test-key");
    });

    it("should handle merging into a non-existent nested path", () => {
      manager.save(manager.load());
      manager.update({ agent: { scan: { excludePaths: ["node_modules"] } } } as any);

      expect(manager.get("agent.scan.excludePaths")).toEqual(["node_modules"]);
    });
  });

  // ── set() creates intermediate objects ──────────────────────

  describe("set() with missing intermediate keys", () => {
    it("should create intermediate objects for deeply nested paths", () => {
      manager.save(manager.load());
      manager.set("agent.notifications.webhook", "https://hooks.example.com");

      expect(manager.get("agent.notifications.webhook")).toBe("https://hooks.example.com");
    });

    it("should create entirely new nested paths", () => {
      manager.save(manager.load());
      manager.set("custom.deeply.nested.key", 42);

      expect(manager.get("custom.deeply.nested.key")).toBe(42);
    });

    it("should set a single-segment key", () => {
      manager.save(manager.load());
      manager.set("initialized", "2025-01-01T00:00:00.000Z");

      expect(manager.get("initialized")).toBe("2025-01-01T00:00:00.000Z");
    });
  });

  // ── get() edge cases ───────────────────────────────────────

  describe("get() edge cases", () => {
    it("should return the full config for an empty-string key path", () => {
      manager.save(manager.load());
      // Split("") => [""] — key "" is not in config, should return undefined
      const result = manager.get("");
      expect(result).toBeUndefined();
    });

    it("should return undefined when traversing through a non-object", () => {
      manager.save(manager.load());
      // agent.riskLevel is "moderate" (string), can't go deeper
      expect(manager.get("agent.riskLevel.foo")).toBeUndefined();
    });

    it("should return the whole agent block", () => {
      manager.save(manager.load());
      const agent = manager.get("agent");
      expect(agent).toBeDefined();
      expect(agent.riskLevel).toBe("moderate");
    });
  });

  // ── Validation (validateConfig) ─────────────────────────────

  describe("validation", () => {
    it("should fall back to defaults for non-object config", () => {
      fs.writeFileSync(testConfigPath, JSON.stringify("just a string"), "utf-8");

      const config = manager.load();
      expect(config.agent?.riskLevel).toBe("moderate");
    });

    it("should fall back to defaults for null config", () => {
      fs.writeFileSync(testConfigPath, "null", "utf-8");

      const config = manager.load();
      expect(config.agent?.riskLevel).toBe("moderate");
    });

    it("should reset invalid riskLevel to default", () => {
      const config = manager.load();
      (config.agent as any).riskLevel = "yolo";
      manager.save(config);

      const loaded = manager.load();
      expect(loaded.agent?.riskLevel).toBe("moderate");
    });

    it("should reset invalid commandPolicy.mode to default", () => {
      const config = manager.load();
      (config.agent!.commandPolicy as any).mode = "super-allow";
      manager.save(config);

      const loaded = manager.load();
      expect(loaded.agent?.commandPolicy.mode).toBe("approve-dangerous");
    });

    it("should reset non-array blockedPatterns to default", () => {
      const config = manager.load();
      (config.agent!.commandPolicy as any).blockedPatterns = "not-an-array";
      manager.save(config);

      const loaded = manager.load();
      expect(Array.isArray(loaded.agent?.commandPolicy.blockedPatterns)).toBe(true);
    });

    it("should reset blockedPatterns containing non-strings to default", () => {
      const config = manager.load();
      (config.agent!.commandPolicy as any).blockedPatterns = ["valid", 123];
      manager.save(config);

      const loaded = manager.load();
      // Should have been replaced with defaults
      expect(loaded.agent?.commandPolicy.blockedPatterns.every((v: any) => typeof v === "string")).toBe(true);
      expect(loaded.agent?.commandPolicy.blockedPatterns).not.toContain(123);
    });

    it("should reset non-array requireApproval to default", () => {
      const config = manager.load();
      (config.agent!.commandPolicy as any).requireApproval = { not: "array" };
      manager.save(config);

      const loaded = manager.load();
      expect(Array.isArray(loaded.agent?.commandPolicy.requireApproval)).toBe(true);
    });

    it("should reset invalid retentionDays to default", () => {
      const config = manager.load();
      (config.agent!.audit as any).retentionDays = "thirty";
      manager.save(config);

      const loaded = manager.load();
      expect(loaded.agent?.audit.retentionDays).toBe(30);
    });

    it("should reset NaN retentionDays to default", () => {
      // Write raw JSON with NaN-like value
      const config = manager.load();
      manager.save(config);
      const raw = JSON.parse(fs.readFileSync(testConfigPath, "utf-8"));
      raw.agent.audit.retentionDays = null;
      fs.writeFileSync(testConfigPath, JSON.stringify(raw), "utf-8");

      // null is not a number, but typeof null !== "number", so it should be kept
      // Actually the check is: typeof !== "number" || isNaN — null fails typeof check
      const loaded = manager.load();
      // null is not typeof "number", so it gets reset
      expect(loaded.agent?.audit.retentionDays).toBe(30);
    });

    it("should reset invalid logLevel to default", () => {
      const config = manager.load();
      (config.agent!.audit as any).logLevel = "verbose";
      manager.save(config);

      const loaded = manager.load();
      expect(loaded.agent?.audit.logLevel).toBe("info");
    });

    it("should reset invalid version type to default", () => {
      const raw = { version: 123, agent: { riskLevel: "moderate" } };
      fs.writeFileSync(testConfigPath, JSON.stringify(raw), "utf-8");

      const loaded = manager.load();
      expect(typeof loaded.version).toBe("string");
    });

    it("should reset invalid initialized type to default", () => {
      const raw = { initialized: false, agent: { riskLevel: "moderate" } };
      fs.writeFileSync(testConfigPath, JSON.stringify(raw), "utf-8");

      const loaded = manager.load();
      expect(typeof loaded.initialized).toBe("string");
    });

    it("should reset invalid outputFiltering.redactSecrets to default", () => {
      const config = manager.load();
      (config.agent!.outputFiltering as any).redactSecrets = "yes";
      manager.save(config);

      const loaded = manager.load();
      expect(loaded.agent?.outputFiltering.redactSecrets).toBe(true);
    });

    it("should reset invalid outputFiltering.blockPatterns to default", () => {
      const config = manager.load();
      (config.agent!.outputFiltering as any).blockPatterns = 1;
      manager.save(config);

      const loaded = manager.load();
      expect(loaded.agent?.outputFiltering.blockPatterns).toBe(true);
    });

    it("should reset invalid scan.excludePaths to delete", () => {
      const raw = manager.load();
      (raw as any).agent.scan = { excludePaths: "not-array" };
      manager.save(raw);

      const loaded = manager.load();
      expect(loaded.agent?.scan?.excludePaths).toBeUndefined();
    });

    it("should filter out malformed customPatterns entries", () => {
      const raw = manager.load();
      (raw as any).agent.scan = {
        customPatterns: [
          { name: "valid", regex: "secret_\\w+", severity: "high" },
          { name: "", regex: "abc", severity: "low" },  // empty name
          { regex: "abc", severity: "low" },             // missing name
          { name: "bad-regex", regex: "[invalid", severity: "high" },  // invalid regex
        ],
      };
      manager.save(raw);

      const loaded = manager.load();
      const patterns = loaded.agent?.scan?.customPatterns;
      expect(patterns).toHaveLength(1);
      expect(patterns![0].name).toBe("valid");
    });

    it("should filter out customPatterns with missing regex", () => {
      const raw = manager.load();
      (raw as any).agent.scan = {
        customPatterns: [
          { name: "no-regex", severity: "high" },
        ],
      };
      manager.save(raw);

      const loaded = manager.load();
      expect(loaded.agent?.scan?.customPatterns).toEqual([]);
    });

    it("should accept valid enum values", () => {
      const config = manager.load();
      config.agent!.riskLevel = "aggressive";
      config.agent!.commandPolicy.mode = "deny-list";
      config.agent!.audit.logLevel = "debug";
      manager.save(config);

      const loaded = manager.load();
      expect(loaded.agent?.riskLevel).toBe("aggressive");
      expect(loaded.agent?.commandPolicy.mode).toBe("deny-list");
      expect(loaded.agent?.audit.logLevel).toBe("debug");
    });
  });

  // ── Error handling ──────────────────────────────────────────

  describe("error handling", () => {
    it("should return defaults for invalid JSON on disk", () => {
      fs.writeFileSync(testConfigPath, "{not valid json!!!", "utf-8");

      const config = manager.load();
      expect(config.agent?.riskLevel).toBe("moderate");
    });

    it("should return defaults for empty file", () => {
      fs.writeFileSync(testConfigPath, "", "utf-8");

      const config = manager.load();
      expect(config.agent?.riskLevel).toBe("moderate");
    });

    it("should create parent directories when saving", () => {
      const deepPath = path.join(os.tmpdir(), `rafter-deep-${Date.now()}`, "sub", "config.json");
      const deepManager = new ConfigManager(deepPath);

      deepManager.save(deepManager.load());

      expect(fs.existsSync(deepPath)).toBe(true);

      // cleanup
      fs.rmSync(path.join(os.tmpdir(), path.basename(path.dirname(path.dirname(deepPath)))), {
        recursive: true,
        force: true,
      });
    });
  });

  // ── Policy merge (loadWithPolicy) ──────────────────────────

  describe("loadWithPolicy", () => {
    let policyLoader: typeof import("../src/core/policy-loader.js");

    beforeEach(async () => {
      policyLoader = await import("../src/core/policy-loader.js");
    });

    function mockPolicy(policy: any) {
      vi.spyOn(policyLoader, "loadPolicy").mockReturnValue(policy);
    }

    it("should return plain config when no policy file exists", () => {
      mockPolicy(null);
      manager.save(manager.load());

      const merged = manager.loadWithPolicy();
      expect(merged.agent?.riskLevel).toBe("moderate");
    });

    it("should let policy override riskLevel", () => {
      manager.save(manager.load());
      mockPolicy({ riskLevel: "aggressive" });

      const merged = manager.loadWithPolicy();
      expect(merged.agent?.riskLevel).toBe("aggressive");
    });

    it("should let policy override commandPolicy.mode", () => {
      manager.save(manager.load());
      mockPolicy({ commandPolicy: { mode: "deny-list" } });

      const merged = manager.loadWithPolicy();
      expect(merged.agent?.commandPolicy.mode).toBe("deny-list");
    });

    it("should replace arrays from policy, not append", () => {
      const config = manager.load();
      config.agent!.commandPolicy.blockedPatterns = ["rm -rf /", "dd if="];
      manager.save(config);
      mockPolicy({ commandPolicy: { blockedPatterns: ["policy-pattern-only"] } });

      const merged = manager.loadWithPolicy();
      expect(merged.agent?.commandPolicy.blockedPatterns).toEqual(["policy-pattern-only"]);
    });

    it("should let policy override audit settings", () => {
      manager.save(manager.load());
      mockPolicy({ audit: { retentionDays: 90, logLevel: "debug" } });

      const merged = manager.loadWithPolicy();
      expect(merged.agent?.audit.retentionDays).toBe(90);
      expect(merged.agent?.audit.logLevel).toBe("debug");
    });

    it("should let policy set scan.excludePaths", () => {
      manager.save(manager.load());
      mockPolicy({ scan: { excludePaths: ["vendor/", "dist/"] } });

      const merged = manager.loadWithPolicy();
      expect(merged.agent?.scan?.excludePaths).toEqual(["vendor/", "dist/"]);
    });

    it("should let policy set scan.customPatterns", () => {
      manager.save(manager.load());
      mockPolicy({
        scan: {
          customPatterns: [
            { name: "internal-key", regex: "INTERNAL_\\w+", severity: "high" },
          ],
        },
      });

      const merged = manager.loadWithPolicy();
      expect(merged.agent?.scan?.customPatterns).toHaveLength(1);
      expect(merged.agent?.scan?.customPatterns![0].name).toBe("internal-key");
    });

    it("should preserve config values not overridden by policy", () => {
      const config = manager.load();
      config.agent!.riskLevel = "minimal";
      config.agent!.audit.retentionDays = 60;
      manager.save(config);
      mockPolicy({ riskLevel: "aggressive" });

      const merged = manager.loadWithPolicy();
      expect(merged.agent?.riskLevel).toBe("aggressive");
      expect(merged.agent?.audit.retentionDays).toBe(60);
    });

    it("should handle config with missing agent block during policy merge", () => {
      fs.writeFileSync(testConfigPath, JSON.stringify({ version: "1.0.0", initialized: "now" }), "utf-8");
      mockPolicy({ riskLevel: "aggressive" });

      const merged = manager.loadWithPolicy();
      expect(merged.agent).toBeDefined();
      expect(merged.agent?.riskLevel).toBe("aggressive");
    });

    it("should let policy override requireApproval array", () => {
      const config = manager.load();
      config.agent!.commandPolicy.requireApproval = ["sudo", "rm -rf"];
      manager.save(config);
      mockPolicy({ commandPolicy: { requireApproval: ["policy-only-pattern"] } });

      const merged = manager.loadWithPolicy();
      expect(merged.agent?.commandPolicy.requireApproval).toEqual(["policy-only-pattern"]);
    });

    it("should partially override commandPolicy — mode only, keep arrays", () => {
      const config = manager.load();
      config.agent!.commandPolicy.mode = "allow-all";
      config.agent!.commandPolicy.blockedPatterns = ["rm -rf"];
      manager.save(config);
      mockPolicy({ commandPolicy: { mode: "deny-list" } });

      const merged = manager.loadWithPolicy();
      expect(merged.agent?.commandPolicy.mode).toBe("deny-list");
      expect(merged.agent?.commandPolicy.blockedPatterns).toEqual(["rm -rf"]);
    });

    it("should let policy set audit.retentionDays to 0", () => {
      manager.save(manager.load());
      mockPolicy({ audit: { retentionDays: 0 } });

      const merged = manager.loadWithPolicy();
      // 0 is falsy but != null, so it should be applied
      expect(merged.agent?.audit.retentionDays).toBe(0);
    });
  });

  // ── Precedence integration ──────────────────────────────────

  describe("precedence", () => {
    it("config on disk beats defaults", () => {
      const config = manager.load();
      config.agent!.riskLevel = "aggressive";
      config.agent!.audit.retentionDays = 7;
      manager.save(config);

      const loaded = manager.load();
      expect(loaded.agent?.riskLevel).toBe("aggressive");
      expect(loaded.agent?.audit.retentionDays).toBe(7);
    });

    it("update() merges on top of persisted config", () => {
      const config = manager.load();
      config.agent!.riskLevel = "minimal";
      config.agent!.audit.retentionDays = 90;
      manager.save(config);

      manager.update({ agent: { riskLevel: "aggressive" } } as any);

      expect(manager.get("agent.riskLevel")).toBe("aggressive");
      expect(manager.get("agent.audit.retentionDays")).toBe(90); // untouched
    });

    it("set() overwrites specific path without affecting siblings", () => {
      const config = manager.load();
      config.agent!.commandPolicy.mode = "allow-all";
      config.agent!.commandPolicy.blockedPatterns = ["rm -rf"];
      manager.save(config);

      manager.set("agent.commandPolicy.mode", "deny-list");

      expect(manager.get("agent.commandPolicy.mode")).toBe("deny-list");
      expect(manager.get("agent.commandPolicy.blockedPatterns")).toEqual(["rm -rf"]);
    });
  });

  // ── save() creates directory ────────────────────────────────

  describe("save directory creation", () => {
    it("should not fail when config directory already exists", () => {
      manager.save(manager.load());
      // Save again — directory already exists
      manager.save(manager.load());
      expect(manager.exists()).toBe(true);
    });
  });
});
