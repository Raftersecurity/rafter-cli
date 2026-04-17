import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { AuditLogger, validateWebhookUrl } from "../src/core/audit-logger.js";
import { ConfigManager } from "../src/core/config-manager.js";

/**
 * Tests for the audit logger — validates the full lifecycle:
 * write events, read/filter, cleanup, and SSRF-safe webhooks.
 */

describe("AuditLogger", () => {
  let tmpDir: string;
  let logPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-audit-"));
    logPath = path.join(tmpDir, "audit.jsonl");

    // Mock ConfigManager to enable logging
    vi.spyOn(ConfigManager.prototype, "load").mockReturnValue({
      version: "1",
      agent: {
        riskLevel: "moderate",
        commandPolicy: { mode: "approve-dangerous", blockedPatterns: [], requireApproval: [] },
        audit: { retentionDays: 30, logLevel: "info", logAllActions: true },
        outputFiltering: { redactSecrets: true, blockPatterns: false },
        notifications: {},
        scan: {},
      },
    } as any);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("creates log directory if it doesn't exist", () => {
    const deep = path.join(tmpDir, "sub", "dir", "audit.jsonl");
    new AuditLogger(deep);
    expect(fs.existsSync(path.dirname(deep))).toBe(true);
  });

  it("writes a log entry as JSON line", () => {
    const logger = new AuditLogger(logPath);
    logger.log({
      eventType: "command_intercepted",
      action: { command: "rm -rf /", riskLevel: "critical" },
      securityCheck: { passed: false, reason: "blocked" },
      resolution: { actionTaken: "blocked" },
    });

    const content = fs.readFileSync(logPath, "utf-8");
    const lines = content.trim().split("\n");
    expect(lines).toHaveLength(1);

    const entry = JSON.parse(lines[0]);
    expect(entry.eventType).toBe("command_intercepted");
    expect(entry.action.command).toBe("rm -rf /");
    expect(entry.timestamp).toBeDefined();
    expect(entry.sessionId).toBeDefined();
  });

  it("appends multiple entries", () => {
    const logger = new AuditLogger(logPath);
    logger.log({ eventType: "command_intercepted", securityCheck: { passed: true }, resolution: { actionTaken: "allowed" } });
    logger.log({ eventType: "secret_detected", securityCheck: { passed: false }, resolution: { actionTaken: "blocked" } });

    const content = fs.readFileSync(logPath, "utf-8");
    const lines = content.trim().split("\n");
    expect(lines).toHaveLength(2);
  });

  describe("convenience logging methods", () => {
    it("logCommandIntercepted writes command event", () => {
      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("rm -rf /tmp", false, "blocked", "dangerous", "claude-code");

      const entries = logger.read();
      expect(entries).toHaveLength(1);
      expect(entries[0].eventType).toBe("command_intercepted");
      expect(entries[0].action?.command).toBe("rm -rf /tmp");
      expect(entries[0].agentType).toBe("claude-code");
    });

    it("logSecretDetected writes secret event", () => {
      const logger = new AuditLogger(logPath);
      logger.logSecretDetected("config.js", "AWS Access Key ID", "blocked");

      const entries = logger.read();
      expect(entries).toHaveLength(1);
      expect(entries[0].eventType).toBe("secret_detected");
      expect(entries[0].action?.riskLevel).toBe("critical");
    });

    it("logContentSanitized writes sanitization event", () => {
      const logger = new AuditLogger(logPath);
      logger.logContentSanitized("output", 3);

      const entries = logger.read();
      expect(entries).toHaveLength(1);
      expect(entries[0].eventType).toBe("content_sanitized");
      expect(entries[0].resolution?.actionTaken).toBe("redacted");
    });

    it("logPolicyOverride writes override event", () => {
      const logger = new AuditLogger(logPath);
      logger.logPolicyOverride("user requested", "npm publish");

      const entries = logger.read();
      expect(entries).toHaveLength(1);
      expect(entries[0].eventType).toBe("policy_override");
      expect(entries[0].action?.riskLevel).toBe("high");
    });

    it("logCommandIntercepted redacts secrets before persisting", () => {
      const logger = new AuditLogger(logPath);
      const token = "ghp_FAKE1234567890abcdefghijklmnopqrstuvwxyz";
      logger.logCommandIntercepted(
        `export GITHUB_TOKEN=${token} && gh repo list`,
        true,
        "allowed",
      );
      const entries = logger.read();
      expect(entries).toHaveLength(1);
      const logged = entries[0].action?.command as string;
      expect(logged).not.toContain(token);
      expect(logged).toMatch(/ghp_\*+/);
      // raw content must not appear anywhere on disk
      const onDisk = fs.readFileSync(logPath, "utf-8");
      expect(onDisk).not.toContain(token);
    });

    it("logPolicyOverride redacts secrets in the command", () => {
      const logger = new AuditLogger(logPath);
      const token = "ghp_FAKE1234567890abcdefghijklmnopqrstuvwxyz";
      logger.logPolicyOverride("user approved", `gh auth login --with-token ${token}`);
      const onDisk = fs.readFileSync(logPath, "utf-8");
      expect(onDisk).not.toContain(token);
    });

    it("auto-populates cwd and gitRepo on every entry", () => {
      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("ls", true, "allowed");
      const entries = logger.read();
      expect(entries[0].cwd).toBeDefined();
      expect(entries[0].cwd).toBe(process.cwd());
      // gitRepo is the rafter-cli root when tests run from crew/lucy
      expect(entries[0].gitRepo).toBeDefined();
    });

    it("filters read() by gitRepo substring", () => {
      const logger = new AuditLogger(logPath);
      // forge entries with different repo paths
      fs.writeFileSync(logPath, [
        JSON.stringify({ timestamp: "2026-01-01T00:00:00Z", sessionId: "s1", eventType: "command_intercepted", gitRepo: "/home/alice/repo-a" }),
        JSON.stringify({ timestamp: "2026-01-01T00:00:00Z", sessionId: "s2", eventType: "command_intercepted", gitRepo: "/home/alice/repo-b" }),
        JSON.stringify({ timestamp: "2026-01-01T00:00:00Z", sessionId: "s3", eventType: "command_intercepted", gitRepo: "/home/bob/repo-a" }),
      ].join("\n") + "\n");

      expect(logger.read({ gitRepo: "repo-a" })).toHaveLength(2);
      expect(logger.read({ gitRepo: "alice" })).toHaveLength(2);
      expect(logger.read({ gitRepo: "nowhere" })).toHaveLength(0);
    });
  });

  describe("read with filters", () => {
    it("filters by eventType", () => {
      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("ls", true, "allowed");
      logger.logSecretDetected("file.js", "AWS Key", "blocked");
      logger.logCommandIntercepted("rm -rf", false, "blocked");

      const filtered = logger.read({ eventType: "command_intercepted" });
      expect(filtered).toHaveLength(2);
    });

    it("filters by since date", () => {
      const logger = new AuditLogger(logPath);
      // Write an old entry manually
      const oldEntry = {
        timestamp: "2024-01-01T00:00:00.000Z",
        sessionId: "old",
        eventType: "command_intercepted",
      };
      fs.writeFileSync(logPath, JSON.stringify(oldEntry) + "\n");

      // Write a new entry
      logger.logCommandIntercepted("ls", true, "allowed");

      const filtered = logger.read({ since: new Date("2025-01-01") });
      expect(filtered).toHaveLength(1);
    });

    it("limits results", () => {
      const logger = new AuditLogger(logPath);
      for (let i = 0; i < 10; i++) {
        logger.logCommandIntercepted(`cmd-${i}`, true, "allowed");
      }

      const limited = logger.read({ limit: 3 });
      expect(limited).toHaveLength(3);
      // Should be the last 3
      expect(limited[2].action?.command).toBe("cmd-9");
    });

    it("returns empty array for missing log file", () => {
      const logger = new AuditLogger(path.join(tmpDir, "nonexistent.jsonl"));
      expect(logger.read()).toEqual([]);
    });

    it("handles malformed JSON lines gracefully", () => {
      fs.writeFileSync(logPath, '{"timestamp":"2025-01-01","eventType":"test"}\nnot json\n{"timestamp":"2025-01-02","eventType":"test2"}\n');
      const logger = new AuditLogger(logPath);
      const entries = logger.read();
      expect(entries).toHaveLength(2);
    });
  });

  describe("cleanup", () => {
    it("removes entries older than retention period", () => {
      vi.spyOn(ConfigManager.prototype, "load").mockReturnValue({
        version: "1",
        agent: {
          riskLevel: "moderate",
          commandPolicy: { mode: "approve-dangerous", blockedPatterns: [], requireApproval: [] },
          audit: { retentionDays: 7, logLevel: "info", logAllActions: true },
          outputFiltering: { redactSecrets: true, blockPatterns: false },
          notifications: {},
          scan: {},
        },
      } as any);

      const old = new Date();
      old.setDate(old.getDate() - 30);
      const oldEntry = JSON.stringify({ timestamp: old.toISOString(), sessionId: "old", eventType: "command_intercepted" });
      const newEntry = JSON.stringify({ timestamp: new Date().toISOString(), sessionId: "new", eventType: "command_intercepted" });
      fs.writeFileSync(logPath, oldEntry + "\n" + newEntry + "\n");

      const logger = new AuditLogger(logPath);
      logger.cleanup();

      const remaining = logger.read();
      expect(remaining).toHaveLength(1);
      expect(remaining[0].sessionId).toBe("new");
    });
  });

  describe("logging disabled", () => {
    it("does not write when logAllActions is false", () => {
      vi.spyOn(ConfigManager.prototype, "load").mockReturnValue({
        version: "1",
        agent: {
          riskLevel: "moderate",
          commandPolicy: { mode: "approve-dangerous", blockedPatterns: [], requireApproval: [] },
          audit: { retentionDays: 30, logLevel: "info", logAllActions: false },
          outputFiltering: { redactSecrets: true, blockPatterns: false },
          notifications: {},
          scan: {},
        },
      } as any);

      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("ls", true, "allowed");

      expect(fs.existsSync(logPath)).toBe(false);
    });
  });
});

// ── SSRF validation ─────────────────────────────────────────────────

describe("validateWebhookUrl", () => {
  it("accepts valid HTTPS URL", async () => {
    // This will attempt DNS resolution, so we just verify it doesn't throw for scheme
    // Use a public domain that resolves
    await expect(validateWebhookUrl("https://example.com/webhook")).resolves.not.toThrow();
  });

  it("rejects non-HTTP scheme (ftp)", async () => {
    await expect(validateWebhookUrl("ftp://example.com/file")).rejects.toThrow("http or https");
  });

  it("rejects javascript: scheme", async () => {
    await expect(validateWebhookUrl("javascript:alert(1)")).rejects.toThrow("http or https");
  });

  it("rejects file: scheme", async () => {
    await expect(validateWebhookUrl("file:///etc/passwd")).rejects.toThrow("http or https");
  });

  it("rejects private IPv4 (127.0.0.1)", async () => {
    await expect(validateWebhookUrl("http://127.0.0.1/webhook")).rejects.toThrow("private");
  });

  it("rejects private IPv4 (10.0.0.1)", async () => {
    await expect(validateWebhookUrl("http://10.0.0.1/webhook")).rejects.toThrow("private");
  });

  it("rejects private IPv4 (192.168.1.1)", async () => {
    await expect(validateWebhookUrl("http://192.168.1.1/webhook")).rejects.toThrow("private");
  });

  it("rejects private IPv4 (172.16.0.1)", async () => {
    await expect(validateWebhookUrl("http://172.16.0.1/webhook")).rejects.toThrow("private");
  });

  it("rejects link-local (169.254.169.254) — AWS metadata", async () => {
    await expect(validateWebhookUrl("http://169.254.169.254/latest/meta-data")).rejects.toThrow("private");
  });

  it("rejects 0.0.0.0", async () => {
    await expect(validateWebhookUrl("http://0.0.0.0/webhook")).rejects.toThrow("private");
  });

  it("rejects IPv6 loopback", async () => {
    await expect(validateWebhookUrl("http://[::1]/webhook")).rejects.toThrow("private");
  });

  it("rejects invalid URL", async () => {
    await expect(validateWebhookUrl("not a url")).rejects.toThrow("Invalid");
  });
});
