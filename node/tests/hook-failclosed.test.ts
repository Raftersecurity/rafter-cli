import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";

// An unexpected throw anywhere in the PreToolUse decision path must DENY, for
// every tool. Each stage is made to throw at the function level (not via a
// malformed file, which the loaders handle by warning and using defaults), and
// each case uses a call that is ALLOWED when nothing throws, so a swallowed
// error would show up as "allow".

const fail = vi.hoisted(() => ({ policy: false, risk: false }));

vi.mock("../src/core/policy-loader.js", async (importOriginal) => {
  const m = await importOriginal<typeof import("../src/core/policy-loader.js")>();
  return {
    ...m,
    loadPolicy: (...a: Parameters<typeof m.loadPolicy>) => {
      if (fail.policy) throw new Error("policy boom");
      return m.loadPolicy(...a);
    },
  };
});

vi.mock("../src/core/risk-rules.js", async (importOriginal) => {
  const m = await importOriginal<typeof import("../src/core/risk-rules.js")>();
  return {
    ...m,
    assessCommandRisk: (c: string) => {
      if (fail.risk) throw new TypeError("risk boom");
      return m.assessCommandRisk(c);
    },
  };
});

import { decidePretool } from "../src/commands/hook/pretool.js";
import { ConfigManager } from "../src/core/config-manager.js";
import { AuditLogger } from "../src/core/audit-logger.js";

const bash = (command: string) => JSON.stringify({ tool_name: "Bash", tool_input: { command } });
const write = JSON.stringify({ tool_name: "Write", tool_input: { file_path: "a.txt", content: "hello" } });

describe("hook pretool — fail closed on any unexpected error", () => {
  let dir: string;
  let prevCwd: string;
  let prevHome: string | undefined;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-failclosed-"));
    prevCwd = process.cwd();
    prevHome = process.env.HOME;
    process.env.HOME = dir;
    process.chdir(dir);
    vi.spyOn(console, "error").mockImplementation(() => {});
  });
  afterEach(() => {
    fail.policy = false;
    fail.risk = false;
    vi.restoreAllMocks();
    process.chdir(prevCwd);
    process.env.HOME = prevHome;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("baseline: the probe calls are allowed when nothing throws", () => {
    expect(decidePretool(bash("ls -la"), "claude").decision).toBe("allow");
    expect(decidePretool(write, "claude").decision).toBe("allow");
  });

  it("a malformed .rafter.yml is handled by the loader, not treated as an error", () => {
    fs.writeFileSync(path.join(dir, ".rafter.yml"), "custom_patterns: [\n  - : :\n");
    expect(decidePretool(bash("ls -la"), "claude").decision).toBe("allow");
  });

  it("config loader throws -> deny", () => {
    vi.spyOn(ConfigManager.prototype, "load").mockImplementation(() => { throw new Error("config boom"); });
    const d = decidePretool(bash("ls -la"), "claude");
    expect(d.decision).toBe("deny");
    expect(d.reason).toBe("rafter hook error: Error: config boom; denying to be safe");
    expect(decidePretool(write, "claude").decision).toBe("deny");
  });

  it("policy loader throws -> deny", () => {
    fail.policy = true;
    expect(decidePretool(bash("ls -la"), "claude").decision).toBe("deny");
    expect(decidePretool(write, "claude").decision).toBe("deny");
  });

  it("risk classification throws -> deny", () => {
    fail.risk = true;
    const d = decidePretool(bash("ls -la"), "claude");
    expect(d.decision).toBe("deny");
    expect(d.reason).toMatch(/^rafter hook error: TypeError: risk boom/);
  });

  it("audit write throws -> the deny stands", () => {
    vi.spyOn(fs, "appendFileSync").mockImplementation(() => { throw new Error("EACCES"); });
    expect(decidePretool(bash("rm -rf /"), "claude").decision).toBe("deny");
    // The logger itself must swallow it (one stderr warning), not the outer catch.
    expect(() => new AuditLogger(path.join(dir, "a.jsonl")).logCommandIntercepted("x", true, "allowed")).not.toThrow();
  });
});
