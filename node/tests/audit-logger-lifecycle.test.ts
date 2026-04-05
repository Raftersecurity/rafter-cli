import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import dns from "dns/promises";
import fs from "fs";
import os from "os";
import path from "path";
import { AuditLogger } from "../src/core/audit-logger.js";
import { ConfigManager } from "../src/core/config-manager.js";

/**
 * Full lifecycle tests for the AuditLogger with real JSONL files.
 * Covers: creation, entry schema, convenience methods, read/filter,
 * retention cleanup, webhook notifications, session tracking, and edge cases.
 */

function makeConfig(overrides: any = {}) {
  return {
    version: "1",
    agent: {
      riskLevel: "moderate",
      commandPolicy: { mode: "approve-dangerous", blockedPatterns: [], requireApproval: [] },
      audit: { retentionDays: 30, logLevel: "info", logAllActions: true, ...overrides.audit },
      outputFiltering: { redactSecrets: true, blockPatterns: false },
      notifications: { ...overrides.notifications },
      scan: {},
    },
  } as any;
}

describe("AuditLogger lifecycle", () => {
  let tmpDir: string;
  let logPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-lifecycle-"));
    logPath = path.join(tmpDir, "audit.jsonl");
    vi.spyOn(ConfigManager.prototype, "load").mockReturnValue(makeConfig());
  });

  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // ── Log creation and format ──────────────────────────────────────

  describe("log creation and format", () => {
    it("creates audit.jsonl if not exists", () => {
      const logger = new AuditLogger(logPath);
      logger.log({ eventType: "command_intercepted", securityCheck: { passed: true }, resolution: { actionTaken: "allowed" } });
      expect(fs.existsSync(logPath)).toBe(true);
    });

    it("creates parent directory if not exists", () => {
      const deep = path.join(tmpDir, "a", "b", "c", "audit.jsonl");
      new AuditLogger(deep);
      expect(fs.existsSync(path.dirname(deep))).toBe(true);
    });

    it("each entry is valid JSON on its own line (JSONL)", () => {
      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("ls", true, "allowed");
      logger.logSecretDetected("file.js", "AWS Key", "blocked");
      logger.logContentSanitized("output", 2);

      const content = fs.readFileSync(logPath, "utf-8");
      const lines = content.split("\n").filter(l => l.trim());
      expect(lines).toHaveLength(3);
      for (const line of lines) {
        expect(() => JSON.parse(line)).not.toThrow();
      }
    });

    it("entry schema: timestamp (ISO 8601), sessionId, eventType", () => {
      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("echo hello", true, "allowed");

      const entries = logger.read();
      expect(entries).toHaveLength(1);
      const entry = entries[0];

      // ISO 8601 timestamp
      expect(entry.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
      expect(new Date(entry.timestamp).toISOString()).toBeTruthy();

      // sessionId present
      expect(entry.sessionId).toBeDefined();
      expect(typeof entry.sessionId).toBe("string");
      expect(entry.sessionId.length).toBeGreaterThan(0);

      // eventType present
      expect(entry.eventType).toBe("command_intercepted");
    });
  });

  // ── Convenience methods ──────────────────────────────────────────

  describe("convenience methods", () => {
    it("logCommandIntercepted: all fields present", () => {
      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("rm -rf /tmp", false, "blocked", "dangerous command", "claude-code");

      const entries = logger.read();
      expect(entries).toHaveLength(1);
      const e = entries[0];
      expect(e.eventType).toBe("command_intercepted");
      expect(e.agentType).toBe("claude-code");
      expect(e.action?.command).toBe("rm -rf /tmp");
      expect(e.action?.riskLevel).toBeDefined();
      expect(e.securityCheck?.passed).toBe(false);
      expect(e.securityCheck?.reason).toBe("dangerous command");
      expect(e.resolution?.actionTaken).toBe("blocked");
    });

    it("logSecretDetected: all fields present", () => {
      const logger = new AuditLogger(logPath);
      logger.logSecretDetected("config.js", "AWS Access Key ID", "blocked", "claude-code");

      const entries = logger.read();
      expect(entries).toHaveLength(1);
      const e = entries[0];
      expect(e.eventType).toBe("secret_detected");
      expect(e.agentType).toBe("claude-code");
      expect(e.action?.riskLevel).toBe("critical");
      expect(e.securityCheck?.passed).toBe(false);
      expect(e.securityCheck?.reason).toContain("AWS Access Key ID");
      expect(e.securityCheck?.reason).toContain("config.js");
      expect(e.resolution?.actionTaken).toBe("blocked");
    });

    it("logContentSanitized: all fields present", () => {
      const logger = new AuditLogger(logPath);
      logger.logContentSanitized("output", 3, "claude-code");

      const entries = logger.read();
      expect(entries).toHaveLength(1);
      const e = entries[0];
      expect(e.eventType).toBe("content_sanitized");
      expect(e.agentType).toBe("claude-code");
      expect(e.securityCheck?.details?.contentType).toBe("output");
      expect(e.securityCheck?.details?.patternsMatched).toBe(3);
      expect(e.resolution?.actionTaken).toBe("redacted");
    });

    it("logPolicyOverride: all fields present", () => {
      const logger = new AuditLogger(logPath);
      logger.logPolicyOverride("user requested", "npm publish", "claude-code");

      const entries = logger.read();
      expect(entries).toHaveLength(1);
      const e = entries[0];
      expect(e.eventType).toBe("policy_override");
      expect(e.agentType).toBe("claude-code");
      expect(e.action?.command).toBe("npm publish");
      expect(e.action?.riskLevel).toBe("high");
      expect(e.resolution?.actionTaken).toBe("overridden");
      expect(e.resolution?.overrideReason).toBe("user requested");
    });

    it("all 6 event types produce correct eventType strings", () => {
      const logger = new AuditLogger(logPath);

      // 4 convenience methods
      logger.logCommandIntercepted("ls", true, "allowed");
      logger.logSecretDetected("f.js", "key", "blocked");
      logger.logContentSanitized("output", 1);
      logger.logPolicyOverride("reason", "cmd");

      // 2 manual event types
      logger.log({ eventType: "scan_executed", securityCheck: { passed: true }, resolution: { actionTaken: "allowed" } });
      logger.log({ eventType: "config_changed", securityCheck: { passed: true }, resolution: { actionTaken: "allowed" } });

      const entries = logger.read();
      const types = entries.map(e => e.eventType);
      expect(types).toEqual([
        "command_intercepted",
        "secret_detected",
        "content_sanitized",
        "policy_override",
        "scan_executed",
        "config_changed",
      ]);
    });
  });

  // ── Read with filters ────────────────────────────────────────────

  describe("read with filters", () => {
    it("read() with no filters returns all entries", () => {
      const logger = new AuditLogger(logPath);
      for (let i = 0; i < 5; i++) {
        logger.logCommandIntercepted(`cmd-${i}`, true, "allowed");
      }
      expect(logger.read()).toHaveLength(5);
    });

    it("read({eventType}) returns only matching entries", () => {
      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("ls", true, "allowed");
      logger.logSecretDetected("f.js", "key", "blocked");
      logger.logCommandIntercepted("cat", true, "allowed");

      expect(logger.read({ eventType: "secret_detected" })).toHaveLength(1);
      expect(logger.read({ eventType: "command_intercepted" })).toHaveLength(2);
    });

    it("read({since}) returns only entries after date", () => {
      const logger = new AuditLogger(logPath);
      // Write an old entry manually
      fs.writeFileSync(logPath, JSON.stringify({
        timestamp: "2024-01-01T00:00:00.000Z",
        sessionId: "old",
        eventType: "command_intercepted",
      }) + "\n");
      logger.logCommandIntercepted("ls", true, "allowed");

      const filtered = logger.read({ since: new Date("2025-01-01") });
      expect(filtered).toHaveLength(1);
    });

    it("read({limit}) returns max N entries (last N)", () => {
      const logger = new AuditLogger(logPath);
      for (let i = 0; i < 10; i++) {
        logger.logCommandIntercepted(`cmd-${i}`, true, "allowed");
      }
      const limited = logger.read({ limit: 3 });
      expect(limited).toHaveLength(3);
      expect(limited[0].action?.command).toBe("cmd-7");
      expect(limited[2].action?.command).toBe("cmd-9");
    });

    it("read({agentType}) returns agent-specific entries", () => {
      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("ls", true, "allowed", undefined, "claude-code");
      logger.logCommandIntercepted("cat", true, "allowed", undefined, "openclaw");
      logger.logCommandIntercepted("pwd", true, "allowed", undefined, "claude-code");

      const filtered = logger.read({ agentType: "claude-code" });
      expect(filtered).toHaveLength(2);
    });

    it("combined filters: eventType + since + limit", () => {
      const logger = new AuditLogger(logPath);
      // Old entry
      fs.writeFileSync(logPath, JSON.stringify({
        timestamp: "2024-01-01T00:00:00.000Z",
        sessionId: "old",
        eventType: "command_intercepted",
      }) + "\n");
      // New entries
      for (let i = 0; i < 5; i++) {
        logger.logCommandIntercepted(`cmd-${i}`, true, "allowed");
      }
      logger.logSecretDetected("f.js", "key", "blocked");

      const filtered = logger.read({
        eventType: "command_intercepted",
        since: new Date("2025-01-01"),
        limit: 3,
      });
      expect(filtered).toHaveLength(3);
      // Should be last 3 of the 5 new command_intercepted entries
      expect(filtered[0].action?.command).toBe("cmd-2");
    });
  });

  // ── Retention and cleanup ────────────────────────────────────────

  describe("retention and cleanup", () => {
    it("removes entries older than retention period", () => {
      vi.spyOn(ConfigManager.prototype, "load").mockReturnValue(
        makeConfig({ audit: { retentionDays: 7 } })
      );

      const old = new Date();
      old.setDate(old.getDate() - 30);
      fs.writeFileSync(logPath, [
        JSON.stringify({ timestamp: old.toISOString(), sessionId: "old", eventType: "command_intercepted" }),
        JSON.stringify({ timestamp: new Date().toISOString(), sessionId: "new", eventType: "command_intercepted" }),
      ].join("\n") + "\n");

      const logger = new AuditLogger(logPath);
      logger.cleanup();

      const remaining = logger.read();
      expect(remaining).toHaveLength(1);
      expect(remaining[0].sessionId).toBe("new");
    });

    it("preserves recent entries", () => {
      const logger = new AuditLogger(logPath);
      for (let i = 0; i < 5; i++) {
        logger.logCommandIntercepted(`cmd-${i}`, true, "allowed");
      }
      logger.cleanup();
      expect(logger.read()).toHaveLength(5);
    });

    it("handles empty log file", () => {
      fs.writeFileSync(logPath, "");
      const logger = new AuditLogger(logPath);
      expect(() => logger.cleanup()).not.toThrow();
    });

    it("handles malformed entries (skips, doesn't crash)", () => {
      fs.writeFileSync(logPath, [
        "not json at all",
        JSON.stringify({ timestamp: new Date().toISOString(), sessionId: "good", eventType: "test" }),
        '{"broken: true}',
        "null",
      ].join("\n") + "\n");

      const logger = new AuditLogger(logPath);
      expect(() => logger.cleanup()).not.toThrow();
      const remaining = logger.read();
      expect(remaining).toHaveLength(1);
      expect(remaining[0].sessionId).toBe("good");
    });
  });

  // ── Webhook notifications ────────────────────────────────────────

  describe("webhook notifications", () => {
    beforeEach(() => {
      // Mock DNS resolution to return a public IP so validateWebhookUrl passes
      vi.spyOn(dns, "resolve").mockResolvedValue(["93.184.216.34"]);
    });

    it("fires webhook for high-risk events", async () => {
      const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok"));
      vi.spyOn(ConfigManager.prototype, "load").mockReturnValue(
        makeConfig({ notifications: { webhook: "https://example.com/webhook", minRiskLevel: "high" } })
      );

      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("rm -rf /", false, "blocked", "dangerous");

      // Wait for async webhook
      await new Promise(r => setTimeout(r, 100));

      expect(fetchSpy).toHaveBeenCalled();
      const callArgs = fetchSpy.mock.calls[0];
      expect(callArgs[0]).toBe("https://example.com/webhook");
      const body = JSON.parse((callArgs[1] as any).body);
      expect(body.event).toBe("command_intercepted");
    });

    it("minRiskLevel threshold: high fires, low doesn't", async () => {
      const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok"));
      vi.spyOn(ConfigManager.prototype, "load").mockReturnValue(
        makeConfig({ notifications: { webhook: "https://example.com/webhook", minRiskLevel: "high" } })
      );

      const logger = new AuditLogger(logPath);
      // Low risk — should not fire
      logger.logCommandIntercepted("ls", true, "allowed");
      await new Promise(r => setTimeout(r, 50));
      expect(fetchSpy).not.toHaveBeenCalled();

      // High risk — should fire
      logger.logCommandIntercepted("rm -rf /", false, "blocked", "dangerous");
      await new Promise(r => setTimeout(r, 100));
      expect(fetchSpy).toHaveBeenCalled();
    });

    it("payload format includes all required fields", async () => {
      const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok"));
      vi.spyOn(ConfigManager.prototype, "load").mockReturnValue(
        makeConfig({ notifications: { webhook: "https://example.com/webhook", minRiskLevel: "high" } })
      );

      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("rm -rf /", false, "blocked", "danger", "claude-code");
      await new Promise(r => setTimeout(r, 100));

      const body = JSON.parse((fetchSpy.mock.calls[0][1] as any).body);
      expect(body).toHaveProperty("event");
      expect(body).toHaveProperty("risk");
      expect(body).toHaveProperty("command");
      expect(body).toHaveProperty("timestamp");
      expect(body).toHaveProperty("agent");
      expect(body).toHaveProperty("text");
      expect(body).toHaveProperty("content");
      expect(body.text).toContain("[rafter]");
      expect(body.content).toContain("[rafter]");
    });

    it("fire-and-forget: webhook error doesn't affect log write", async () => {
      vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("network error"));
      vi.spyOn(ConfigManager.prototype, "load").mockReturnValue(
        makeConfig({ notifications: { webhook: "https://example.com/webhook", minRiskLevel: "high" } })
      );

      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("rm -rf /", false, "blocked", "dangerous");
      await new Promise(r => setTimeout(r, 100));

      // Log should still be written
      const entries = logger.read();
      expect(entries).toHaveLength(1);
      expect(entries[0].eventType).toBe("command_intercepted");
    });

    it("missing webhook config → no notification attempt", async () => {
      const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok"));
      // Default config has no webhook
      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("rm -rf /", false, "blocked", "dangerous");
      await new Promise(r => setTimeout(r, 50));
      expect(fetchSpy).not.toHaveBeenCalled();
    });
  });

  // ── Session tracking ─────────────────────────────────────────────

  describe("session tracking", () => {
    it("sessionId is consistent within one AuditLogger instance", () => {
      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("ls", true, "allowed");
      logger.logCommandIntercepted("cat", true, "allowed");
      logger.logSecretDetected("f.js", "key", "blocked");

      const entries = logger.read();
      const ids = entries.map(e => e.sessionId);
      expect(new Set(ids).size).toBe(1);
    });

    it("sessionId differs between instances", () => {
      const logger1 = new AuditLogger(logPath);
      logger1.logCommandIntercepted("ls", true, "allowed");

      const logger2 = new AuditLogger(logPath);
      logger2.logCommandIntercepted("cat", true, "allowed");

      const entries = logger2.read();
      expect(entries[0].sessionId).not.toBe(entries[1].sessionId);
    });

    it("sessionId format: timestamp-ms + random hex", () => {
      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("ls", true, "allowed");

      const entry = logger.read()[0];
      // Format: <timestamp_ms>-<hex>
      expect(entry.sessionId).toMatch(/^\d+-[0-9a-f]+$/);
    });
  });

  // ── Edge cases ───────────────────────────────────────────────────

  describe("edge cases", () => {
    it("concurrent log writes (multiple appends)", () => {
      const logger = new AuditLogger(logPath);
      // Simulate concurrent-ish writes
      for (let i = 0; i < 20; i++) {
        logger.logCommandIntercepted(`cmd-${i}`, true, "allowed");
      }
      const entries = logger.read();
      expect(entries).toHaveLength(20);
    });

    it("very large log file (1000+ entries)", () => {
      const logger = new AuditLogger(logPath);
      for (let i = 0; i < 1050; i++) {
        logger.logCommandIntercepted(`cmd-${i}`, true, "allowed");
      }
      const entries = logger.read();
      expect(entries).toHaveLength(1050);
    });

    it("corrupt entry in log: one bad line doesn't break read", () => {
      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("before", true, "allowed");

      // Inject corrupt line
      fs.appendFileSync(logPath, "CORRUPT LINE\n");

      logger.logCommandIntercepted("after", true, "allowed");

      const entries = logger.read();
      expect(entries).toHaveLength(2);
      expect(entries[0].action?.command).toBe("before");
      expect(entries[1].action?.command).toBe("after");
    });

    it("unicode in log entries", () => {
      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("echo '你好世界 🌍'", true, "allowed");

      const entries = logger.read();
      expect(entries).toHaveLength(1);
      expect(entries[0].action?.command).toContain("你好世界");
      expect(entries[0].action?.command).toContain("🌍");
    });

    it("log disabled: no writes when logAllActions is false", () => {
      vi.spyOn(ConfigManager.prototype, "load").mockReturnValue(
        makeConfig({ audit: { logAllActions: false } })
      );

      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("ls", true, "allowed");
      logger.logSecretDetected("f.js", "key", "blocked");

      expect(fs.existsSync(logPath)).toBe(false);
    });
  });
});
