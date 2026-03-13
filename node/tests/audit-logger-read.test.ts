import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import path from "path";
import os from "os";
import { AuditLogger } from "../src/core/audit-logger.js";

describe("AuditLogger.read() malformed entry filtering", () => {
  let tmpDir: string;
  let logPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-read-test-"));
    logPath = path.join(tmpDir, "audit.jsonl");
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function writeLines(lines: string[]) {
    fs.writeFileSync(logPath, lines.join("\n") + "\n");
  }

  function makeLogger(): AuditLogger {
    const logger = new AuditLogger(tmpDir);
    // Override the log path to our test file
    (logger as any).logPath = logPath;
    return logger;
  }

  it("returns valid entries and skips malformed JSON", () => {
    writeLines([
      JSON.stringify({ timestamp: "2025-01-01T00:00:00Z", eventType: "scan_completed" }),
      "not json at all",
      JSON.stringify({ timestamp: "2025-01-02T00:00:00Z", eventType: "secret_detected" }),
    ]);
    const entries = makeLogger().read();
    expect(entries).toHaveLength(2);
    expect(entries[0].eventType).toBe("scan_completed");
    expect(entries[1].eventType).toBe("secret_detected");
  });

  it("skips entries missing timestamp", () => {
    writeLines([
      JSON.stringify({ eventType: "scan_completed" }),
      JSON.stringify({ timestamp: "2025-01-01T00:00:00Z", eventType: "valid" }),
    ]);
    const entries = makeLogger().read();
    expect(entries).toHaveLength(1);
    expect(entries[0].eventType).toBe("valid");
  });

  it("skips non-object JSON values", () => {
    writeLines([
      '"just a string"',
      "42",
      "null",
      "true",
      JSON.stringify({ timestamp: "2025-01-01T00:00:00Z", eventType: "valid" }),
    ]);
    const entries = makeLogger().read();
    expect(entries).toHaveLength(1);
  });

  it("handles empty file", () => {
    writeLines([]);
    const entries = makeLogger().read();
    expect(entries).toHaveLength(0);
  });

  it("handles file with only malformed entries", () => {
    writeLines([
      "bad json",
      JSON.stringify({ noTimestamp: true }),
      "null",
    ]);
    const entries = makeLogger().read();
    expect(entries).toHaveLength(0);
  });
});
