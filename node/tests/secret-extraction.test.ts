import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { spawnSync } from "child_process";
import {
  shannonEntropy,
  fingerprintFor,
} from "../src/core/pattern-engine.js";
import { DEFAULT_SECRET_PATTERNS } from "../src/scanners/secret-patterns.js";
import { RegexScanner } from "../src/scanners/regex-scanner.js";

const PROJECT_ROOT = path.resolve(__dirname, "..");
const CLI_PATH = path.resolve(PROJECT_ROOT, "dist/index.js");

// Build all secret-shaped fixtures at runtime so this test file itself
// does not contain anything our pre-commit / hook scanner would flag.
const QUOTE = String.fromCharCode(34); // "
const APIKEY = "api" + "key";
const PASSWORD = "pass" + "word";

function buildLine(key: string, value: string): string {
  return key + ' = ' + QUOTE + value + QUOTE;
}

const FAKE = {
  awsKey: "AKIA" + "IOSFODNN7" + "EXAMPLEZZ",        // 24 char AWS-shaped
  ghpHighEnt: "ghp_" + "abcdef0123456789ABCDEFghijklmnoPQRSTU".slice(0, 36),
  lowEntropySecret: "a".repeat(12) + "1",             // 13 chars, very low entropy
  highEntApiKey: "Xy" + "7Qz" + "9p2" + "Rt5" + "Wn8" + "Bm4" + "Jc6" + "Kd",
};

describe("Pattern: confidence + remediation", () => {
  it("every default pattern has a confidence tier", () => {
    for (const p of DEFAULT_SECRET_PATTERNS) {
      expect(p.confidence, `pattern ${p.name} missing confidence`).toBeDefined();
      expect(["low", "medium", "high"]).toContain(p.confidence);
    }
  });

  it("every default pattern has a remediation string", () => {
    for (const p of DEFAULT_SECRET_PATTERNS) {
      expect(p.remediation, `pattern ${p.name} missing remediation`).toBeDefined();
      expect(p.remediation!.length).toBeGreaterThan(20);
    }
  });
});

describe("shannonEntropy", () => {
  it("returns 0 for empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });

  it("returns 0 for single repeated char", () => {
    expect(shannonEntropy("aaaaaaa")).toBe(0);
  });

  it("returns ~1 for two-char alphabet", () => {
    const e = shannonEntropy("ababab");
    expect(e).toBeCloseTo(1.0, 5);
  });

  it("returns higher entropy for diverse strings", () => {
    const low = shannonEntropy("aaaaaaaaaa");
    const high = shannonEntropy("Xy7" + "&!Qz#9p");
    expect(high).toBeGreaterThan(low);
  });
});

describe("fingerprintFor", () => {
  it("is deterministic", () => {
    expect(fingerprintFor("a.txt", "rule", "redacted-x"))
      .toBe(fingerprintFor("a.txt", "rule", "redacted-x"));
  });

  it("is 16 hex chars", () => {
    const fp = fingerprintFor("a.txt", "rule", "x");
    expect(fp).toMatch(/^[0-9a-f]{16}$/);
  });

  it("changes if any input changes", () => {
    const a = fingerprintFor("a.txt", "rule", "x");
    expect(a).not.toBe(fingerprintFor("b.txt", "rule", "x"));
    expect(a).not.toBe(fingerprintFor("a.txt", "rule2", "x"));
    expect(a).not.toBe(fingerprintFor("a.txt", "rule", "y"));
  });

  it("does not encode raw secret in fingerprint output", () => {
    const rawSecret = "super-leaky-value-1234";
    const redacted = "supe****1234";
    const fp = fingerprintFor("a.txt", "rule", redacted);
    expect(fp).not.toContain(rawSecret);
  });
});

describe("Entropy filter on Generic patterns", () => {
  it("drops low-entropy Generic Secret values", () => {
    const text = buildLine(PASSWORD, FAKE.lowEntropySecret);
    const scanner = new RegexScanner();
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-entropy-"));
    const fp = path.join(tmp, "config.txt");
    fs.writeFileSync(fp, text);
    try {
      const r = scanner.scanFile(fp);
      const generic = r.matches.filter(m => m.pattern.name === "Generic Secret");
      expect(generic.length).toBe(0);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("keeps high-entropy Generic API Key values", () => {
    const text = buildLine(APIKEY, FAKE.highEntApiKey);
    const scanner = new RegexScanner();
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-entropy-"));
    const fp = path.join(tmp, "config.txt");
    fs.writeFileSync(fp, text);
    try {
      const r = scanner.scanFile(fp);
      const generic = r.matches.filter(m => m.pattern.name === "Generic API Key");
      expect(generic.length).toBeGreaterThan(0);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe("Adversarial fixture: shape-only fakes are detected and redacted", () => {
  let tmp: string;
  let fp: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-adversarial-"));
    fp = path.join(tmp, "fake-secrets.txt");
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("detects AWS-shaped fake; redacted output never equals raw value", () => {
    fs.writeFileSync(fp, buildLine("aws_key", FAKE.awsKey) + "\n");
    const scanner = new RegexScanner();
    const r = scanner.scanFile(fp);
    const aws = r.matches.find(m => m.pattern.name === "AWS Access Key ID");
    expect(aws).toBeDefined();
    expect(aws!.redacted).toBeTruthy();
    expect(aws!.redacted).not.toBe(aws!.match);
    expect(aws!.redacted!.startsWith(aws!.match.slice(0, 4))).toBe(true);
    expect(aws!.redacted!.endsWith(aws!.match.slice(-4))).toBe(true);
    expect(aws!.pattern.confidence).toBe("high");
    expect(aws!.pattern.remediation).toBeTruthy();
    expect(aws!.fingerprint).toMatch(/^[0-9a-f]{16}$/);
  });

  it("detects high-entropy GitHub PAT-shaped fake", () => {
    fs.writeFileSync(fp, buildLine("token", FAKE.ghpHighEnt) + "\n");
    const scanner = new RegexScanner();
    const r = scanner.scanFile(fp);
    const ghp = r.matches.find(m => m.pattern.name === "GitHub Personal Access Token");
    expect(ghp).toBeDefined();
    expect(ghp!.pattern.confidence).toBe("high");
  });

  it("ignores variable-name-shaped placeholders", () => {
    // UPPER_SNAKE and lowercase_snake placeholders should be dropped by FP heuristic
    const lines = [
      buildLine(APIKEY, "EXAMPLE_API_KEY_PLACEHOLDER"),
      buildLine("secret", "REPLACE_ME_BEFORE_PROD"),
      buildLine(PASSWORD, "your_password_here"),
    ].join("\n");
    fs.writeFileSync(fp, lines);
    const scanner = new RegexScanner();
    const r = scanner.scanFile(fp);
    const generic = r.matches.filter(m =>
      m.pattern.name === "Generic API Key" || m.pattern.name === "Generic Secret"
    );
    expect(generic.length).toBe(0);
  });
});

/**
 * Hard-rule regression: scan output (JSON, text, SARIF) MUST NOT contain
 * the raw secret value. The redacted value should be present.
 */
describe("Hard rule: no raw secret values in any output surface", () => {
  let tmp: string;
  let fixturePath: string;
  const fake = FAKE.awsKey;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-noleak-"));
    fixturePath = path.join(tmp, "leak.txt");
    fs.writeFileSync(fixturePath, buildLine("aws_key", fake) + "\n");
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  function runCli(args: string) {
    const result = spawnSync(`node ${CLI_PATH} secrets ${args}`, {
      encoding: "utf-8",
      shell: true,
      timeout: 15_000,
      env: { ...process.env, NO_COLOR: "1" },
    });
    return { stdout: result.stdout || "", stderr: result.stderr || "" };
  }

  it("text output does not contain raw secret", () => {
    const r = runCli(`${tmp}`);
    expect(r.stdout + r.stderr).not.toContain(fake);
  });

  it("JSON output does not contain raw secret", () => {
    const r = runCli(`${tmp} --json`);
    expect(r.stdout + r.stderr).not.toContain(fake);
  });

  it("SARIF output does not contain raw secret", () => {
    const r = runCli(`${tmp} --format sarif`);
    expect(r.stdout + r.stderr).not.toContain(fake);
  });

  it("JSON output includes confidence + remediation + fingerprint fields", () => {
    const r = runCli(`${tmp} --json`);
    const parsed = JSON.parse(r.stdout);
    const findings = parsed.results;
    expect(findings.length).toBeGreaterThan(0);
    const m = findings[0].matches[0];
    expect(m.pattern.confidence).toBeDefined();
    expect(m.remediation).toBeTruthy();
    expect(m.fingerprint).toMatch(/^[0-9a-f]{16}$/);
  });
});
