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

  describe("convenience logging methods", () => {
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

    // ob-y5ep: a RAFTER_API_KEY env-assignment prefix leaked verbatim because
    // the key's value matches no built-in secret pattern. Redaction must key
    // off the secret-named env var, not just the value's shape.
    it("logCommandIntercepted redacts a RAFTER_API_KEY env-assignment prefix", () => {
      const logger = new AuditLogger(logPath);
      const key = "sk-deadbeefdeadbeef";
      logger.logCommandIntercepted(`RAFTER_API_KEY=${key} rafter scan .`, true, "allowed");
      const entries = logger.read();
      const logged = entries[0].action?.command as string;
      expect(logged).not.toContain(key);
      expect(logged).toContain("RAFTER_API_KEY=");
      expect(logged).toMatch(/\*/);
      // and never on disk
      expect(fs.readFileSync(logPath, "utf-8")).not.toContain(key);
    });

    it("logCommandIntercepted preserves benign env assignments", () => {
      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("FOO=bar NODE_ENV=production rafter scan .", true, "allowed");
      const logged = logger.read()[0].action?.command as string;
      expect(logged).toContain("FOO=bar");
      expect(logged).toContain("NODE_ENV=production");
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

    it("verify() returns no breaks on a pristine chain", () => {
      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("echo 1", true, "allowed");
      logger.logCommandIntercepted("echo 2", true, "allowed");
      logger.logCommandIntercepted("echo 3", true, "allowed");
      expect(logger.verify()).toEqual([]);
    });

    it("verify() passes after an entry longer than the 64 KB read chunk", () => {
      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("echo 1", true, "allowed");
      logger.logCommandIntercepted("x".repeat(140_000), true, "allowed");
      logger.logCommandIntercepted("echo 3", true, "allowed");
      expect(logger.verify()).toEqual([]);
    });

    it("verify() detects an edited entry in the middle of the chain", () => {
      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("echo 1", true, "allowed");
      logger.logCommandIntercepted("echo 2", true, "allowed");
      logger.logCommandIntercepted("echo 3", true, "allowed");
      // Tamper: change "echo 2" to "echo EVIL" in-place
      const tampered = fs.readFileSync(logPath, "utf-8").replace("echo 2", "echo EVIL");
      fs.writeFileSync(logPath, tampered);
      const breaks = logger.verify();
      expect(breaks.length).toBeGreaterThan(0);
      expect(breaks[0].line).toBe(3); // line 3's prevHash no longer matches tampered line 2
    });

    it("verify() detects a deleted entry", () => {
      const logger = new AuditLogger(logPath);
      logger.logCommandIntercepted("echo 1", true, "allowed");
      logger.logCommandIntercepted("echo 2", true, "allowed");
      logger.logCommandIntercepted("echo 3", true, "allowed");
      const lines = fs.readFileSync(logPath, "utf-8").split("\n").filter(l => l);
      // Drop line 2
      fs.writeFileSync(logPath, [lines[0], lines[2]].join("\n") + "\n");
      const breaks = logger.verify();
      expect(breaks.length).toBeGreaterThan(0);
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
    it("returns empty array for missing log file", () => {
      const logger = new AuditLogger(path.join(tmpDir, "nonexistent.jsonl"));
      expect(logger.read()).toEqual([]);
    });
  });

  describe("cleanup", () => {
    it("re-seals the hash chain after retention prune", () => {
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

      // Mix: two old entries that will get pruned, three recent that survive.
      const old1 = new Date(); old1.setDate(old1.getDate() - 30);
      const old2 = new Date(); old2.setDate(old2.getDate() - 20);
      const recent1 = new Date(); recent1.setDate(recent1.getDate() - 2);
      const recent2 = new Date(); recent2.setDate(recent2.getDate() - 1);

      const logger = new AuditLogger(logPath);
      // Use real log() calls so the chain is initially valid.
      logger.logCommandIntercepted("echo old1", true, "allowed");
      logger.logCommandIntercepted("echo old2", true, "allowed");
      logger.logCommandIntercepted("echo recent1", true, "allowed");
      logger.logCommandIntercepted("echo recent2", true, "allowed");
      logger.logCommandIntercepted("echo recent3", true, "allowed");

      // Rewrite first two entries' timestamps to be old.
      const lines = fs.readFileSync(logPath, "utf-8").split("\n").filter(l => l.trim());
      const parsed = lines.map(l => JSON.parse(l));
      parsed[0].timestamp = old1.toISOString();
      parsed[1].timestamp = old2.toISOString();
      fs.writeFileSync(logPath, parsed.map(e => JSON.stringify(e)).join("\n") + "\n");

      logger.cleanup();

      const after = logger.read();
      expect(after).toHaveLength(3);
      // Chain must verify clean after cleanup re-seals it.
      expect(logger.verify()).toEqual([]);

      // Sidecar must record the prune.
      const sidecar = logPath + ".retention.log";
      expect(fs.existsSync(sidecar)).toBe(true);
      const note = JSON.parse(fs.readFileSync(sidecar, "utf-8").trim());
      expect(note.prunedCount).toBe(2);
      expect(note.retainedCount).toBe(3);
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

  it.each(["ftp://example.com/file", "javascript:alert(1)", "file:///etc/passwd"])(
    "rejects non-HTTP scheme (%s)",
    async (url) => {
      await expect(validateWebhookUrl(url)).rejects.toThrow("http or https");
    },
  );

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
