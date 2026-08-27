/**
 * The audit-log hint the scanner prints must be true.
 *
 * `rafter secrets` ends with "Run 'rafter agent audit' to see the security
 * log", and that log was always empty — only command interception ever wrote
 * to it. Three of seven beta users followed the hint and hit a dead end, one
 * immediately after a correct and useful scan result. The first thing a
 * careful person does with a security finding is look for the record of it.
 *
 * Scans are recorded now, with one hard constraint pinned below: the log must
 * never contain a matched secret. It outlives the terminal, so it must not
 * become a second place secrets live.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

const CLI = path.resolve(__dirname, "../dist/index.js");
const AWS_CANARY = "AKIA" + "IOSFODNN7" + "EXAMPLE";

function rafter(args: string[], home: string): { stdout: string; stderr: string; exitCode: number } {
  try {
    const stdout = execFileSync("node", [CLI, ...args], {
      encoding: "utf-8",
      env: { ...process.env, HOME: home, CI: "1" },
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 60_000,
    });
    return { stdout, stderr: "", exitCode: 0 };
  } catch (e: any) {
    return { stdout: e.stdout || "", stderr: e.stderr || "", exitCode: e.status ?? 1 };
  }
}

let tmp: string;
let home: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-audit-scan-"));
  home = path.join(tmp, "home");
  fs.mkdirSync(home);
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function projectWithSecret(name: string): string {
  const root = path.join(tmp, name);
  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, "cfg.js"), `const k = "${AWS_CANARY}";\n`);
  return root;
}

describe("rafter agent audit after a secrets scan", () => {
  it("records the scan that just pointed the user at the audit log", () => {
    const root = projectWithSecret("proj");

    const scan = rafter(["secrets", root], home);
    expect(scan.stdout).toContain("rafter agent audit");

    const audit = rafter(["agent", "audit"], home);
    expect(audit.stdout).toContain("scan_executed");
    expect(audit.stdout).not.toContain("No audit log entries found");
  });

  it("records a clean scan too", () => {
    const root = path.join(tmp, "clean");
    fs.mkdirSync(root);
    fs.writeFileSync(path.join(root, "ok.js"), "const x = 1;\n");

    rafter(["secrets", root, "--engine", "patterns"], home);

    expect(rafter(["agent", "audit"], home).stdout).toContain("scan_executed");
  });

  it("never writes a matched secret into the audit log", () => {
    const root = projectWithSecret("proj2");

    rafter(["secrets", root], home);

    const log = fs.readFileSync(path.join(home, ".rafter", "audit.jsonl"), "utf-8");
    expect(log).toContain("scan_executed");
    expect(log).not.toContain(AWS_CANARY);
    // Pattern names are fine and useful; values are not.
    expect(log).toContain("AWS Access Key");
  });

  it("does not fail the scan if the audit log cannot be written", () => {
    const root = projectWithSecret("proj3");
    const rafterDir = path.join(home, ".rafter");
    fs.mkdirSync(rafterDir, { recursive: true });
    fs.writeFileSync(path.join(rafterDir, "audit.jsonl"), "");
    fs.chmodSync(path.join(rafterDir, "audit.jsonl"), 0o400);

    // The scan result is the product; logging is a side effect and must never
    // take the product down with it.
    const r = rafter(["secrets", root], home);
    expect(r.exitCode).toBe(1); // findings, not a crash
    expect(r.stdout).toContain("secret(s) detected");

    fs.chmodSync(path.join(rafterDir, "audit.jsonl"), 0o600);
  });
});
