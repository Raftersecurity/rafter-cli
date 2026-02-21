import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { AuditLogger, RISK_SEVERITY } from "../src/core/audit-logger.js";
import { ConfigManager } from "../src/core/config-manager.js";
import fs from "fs";
import path from "path";
import os from "os";

describe("Webhook Notifications", () => {
  const testDir = path.join(os.tmpdir(), `rafter-notif-test-${Date.now()}`);
  const testLogPath = path.join(testDir, "audit.jsonl");
  const testConfigPath = path.join(testDir, "config.json");

  beforeEach(() => {
    fs.mkdirSync(testDir, { recursive: true });
    vi.restoreAllMocks();
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  describe("RISK_SEVERITY", () => {
    it("should order risk levels correctly", () => {
      expect(RISK_SEVERITY["low"]).toBeLessThan(RISK_SEVERITY["medium"]);
      expect(RISK_SEVERITY["medium"]).toBeLessThan(RISK_SEVERITY["high"]);
      expect(RISK_SEVERITY["high"]).toBeLessThan(RISK_SEVERITY["critical"]);
    });
  });

  describe("sendNotification", () => {
    it("should POST to webhook when risk meets threshold", async () => {
      const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response());

      const configManager = new ConfigManager(testConfigPath);
      const config = configManager.load();
      config.agent!.notifications = {
        webhook: "https://hooks.example.com/test",
        minRiskLevel: "high",
      };
      configManager.save(config);

      const logger = new AuditLogger(testLogPath);
      // Override config manager
      (logger as any).configManager = configManager;

      logger.logCommandIntercepted("git push --force", false, "blocked", "High-risk", "claude-code");

      // fetch is fire-and-forget, give it a tick
      await new Promise(r => setTimeout(r, 50));

      expect(fetchSpy).toHaveBeenCalledOnce();
      const [url, opts] = fetchSpy.mock.calls[0];
      expect(url).toBe("https://hooks.example.com/test");
      expect(opts.method).toBe("POST");

      const body = JSON.parse(opts.body as string);
      expect(body.event).toBe("command_intercepted");
      expect(body.risk).toBe("high");
      expect(body.command).toBe("git push --force");
      expect(body.agent).toBe("claude-code");
      expect(body.timestamp).toBeDefined();
      expect(body.text).toContain("[rafter]");
      expect(body.content).toContain("[rafter]");
    });

    it("should not POST when risk is below threshold", async () => {
      const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response());

      const configManager = new ConfigManager(testConfigPath);
      const config = configManager.load();
      config.agent!.notifications = {
        webhook: "https://hooks.example.com/test",
        minRiskLevel: "high",
      };
      configManager.save(config);

      const logger = new AuditLogger(testLogPath);
      (logger as any).configManager = configManager;

      logger.logCommandIntercepted("ls -la", true, "allowed", undefined, "claude-code");

      await new Promise(r => setTimeout(r, 50));
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("should not POST when webhook is not configured", async () => {
      const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response());

      const configManager = new ConfigManager(testConfigPath);
      const logger = new AuditLogger(testLogPath);
      (logger as any).configManager = configManager;

      logger.logSecretDetected("config.js", "AWS Key", "blocked", "claude-code");

      await new Promise(r => setTimeout(r, 50));
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("should POST for critical events when minRiskLevel is critical", async () => {
      const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response());

      const configManager = new ConfigManager(testConfigPath);
      const config = configManager.load();
      config.agent!.notifications = {
        webhook: "https://hooks.example.com/test",
        minRiskLevel: "critical",
      };
      configManager.save(config);

      const logger = new AuditLogger(testLogPath);
      (logger as any).configManager = configManager;

      // High-risk should NOT trigger
      logger.logPolicyOverride("bypass", "sudo rm", "claude-code");
      await new Promise(r => setTimeout(r, 50));
      expect(fetchSpy).not.toHaveBeenCalled();

      // Critical should trigger
      logger.logSecretDetected("config.js", "AWS Key", "blocked");
      await new Promise(r => setTimeout(r, 50));
      expect(fetchSpy).toHaveBeenCalledOnce();
    });

    it("should silently ignore fetch failures", async () => {
      const fetchSpy = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("network error"));

      const configManager = new ConfigManager(testConfigPath);
      const config = configManager.load();
      config.agent!.notifications = {
        webhook: "https://hooks.example.com/test",
        minRiskLevel: "high",
      };
      configManager.save(config);

      const logger = new AuditLogger(testLogPath);
      (logger as any).configManager = configManager;

      // Should not throw
      expect(() => {
        logger.logSecretDetected("config.js", "AWS Key", "blocked");
      }).not.toThrow();

      await new Promise(r => setTimeout(r, 50));

      // Verify the audit log was still written despite webhook failure
      const logContent = fs.readFileSync(testLogPath, "utf-8");
      expect(logContent).toContain("secret_detected");
    });
  });
});
