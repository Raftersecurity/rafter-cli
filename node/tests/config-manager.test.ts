import { describe, it, expect, beforeEach, afterEach } from "vitest";
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
    // Clean up test config
    if (fs.existsSync(testConfigPath)) {
      fs.unlinkSync(testConfigPath);
    }
  });

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
});
