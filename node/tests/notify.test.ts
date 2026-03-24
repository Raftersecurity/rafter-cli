import { describe, it, expect } from "vitest";

// We need to test the formatting functions. Since they're not exported directly,
// we'll test via the command's dry-run behavior, or import the module internals.
// For now, test the command creation and payload formatting logic.

// Import the command to verify it registers correctly
import { createNotifyCommand } from "../src/commands/notify.js";

const SAMPLE_SCAN_CLEAN = {
  status: "completed",
  repository_name: "acme/web-app",
  scan_id: "scan-abc123",
  branch_name: "main",
  findings: [],
  summary: { critical: 0, high: 0, medium: 0, low: 0 },
};

const SAMPLE_SCAN_WITH_FINDINGS = {
  status: "completed",
  repository_name: "acme/api-server",
  scan_id: "scan-def456",
  branch_name: "feature/auth",
  findings: [
    { severity: "critical", title: "SQL Injection", file: "src/db.py" },
    { severity: "high", title: "Hardcoded Secret", location: "config/prod.yml:12" },
    { severity: "medium", title: "Missing CSRF Token", file: "views/form.py" },
  ],
  summary: { critical: 1, high: 1, medium: 1, low: 0 },
};

const SAMPLE_SCAN_FAILED = {
  status: "failed",
  repository_name: "acme/broken",
  scan_id: "scan-fail1",
  findings: [],
  summary: {},
};

describe("Notify Command", () => {
  describe("createNotifyCommand", () => {
    it("should create a valid command", () => {
      const cmd = createNotifyCommand();
      expect(cmd.name()).toBe("notify");
      expect(cmd.description()).toContain("Slack");
      expect(cmd.description()).toContain("Discord");
    });

    it("should accept --webhook option", () => {
      const cmd = createNotifyCommand();
      const webhookOpt = cmd.options.find((o) => o.long === "--webhook");
      expect(webhookOpt).toBeDefined();
      expect(webhookOpt!.short).toBe("-w");
    });

    it("should accept --platform option", () => {
      const cmd = createNotifyCommand();
      const platformOpt = cmd.options.find((o) => o.long === "--platform");
      expect(platformOpt).toBeDefined();
    });

    it("should accept --dry-run option", () => {
      const cmd = createNotifyCommand();
      const dryRunOpt = cmd.options.find((o) => o.long === "--dry-run");
      expect(dryRunOpt).toBeDefined();
    });

    it("should accept --quiet option", () => {
      const cmd = createNotifyCommand();
      const quietOpt = cmd.options.find((o) => o.long === "--quiet");
      expect(quietOpt).toBeDefined();
    });

    it("should accept optional scan_id argument", () => {
      const cmd = createNotifyCommand();
      expect(cmd.registeredArguments.length).toBe(1);
      expect(cmd.registeredArguments[0].required).toBe(false);
    });
  });
});
