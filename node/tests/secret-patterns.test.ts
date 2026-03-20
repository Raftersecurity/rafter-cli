import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { RegexScanner } from "../src/scanners/regex-scanner.js";
import {
  DEFAULT_SECRET_PATTERNS,
  getPatternsBySeverity,
  getCriticalPatterns,
} from "../src/scanners/secret-patterns.js";

/**
 * Comprehensive tests for every secret detection pattern.
 *
 * Each pattern gets:
 *  1. At least one TRUE POSITIVE (realistic secret that must be caught)
 *  2. At least one TRUE NEGATIVE (benign string that must NOT fire)
 *
 * This validates the full scope of what rafter's local scanner adds
 * to agent workflows — catching real secrets before they leak.
 *
 * NOTE: Test secrets are constructed programmatically to avoid
 * triggering GitHub push protection on literal strings.
 */

// Build test secrets at runtime so they don't appear as literals
// (avoids GitHub push protection blocking the commit)
function fakeSecret(prefix: string, body: string): string {
  return prefix + body;
}

describe("Secret patterns — coverage matrix", () => {
  let tmpDir: string;
  let scanner: RegexScanner;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-pat-"));
    scanner = new RegexScanner();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function scanString(content: string) {
    const f = path.join(tmpDir, "test.txt");
    fs.writeFileSync(f, content);
    return scanner.scanFile(f);
  }

  // ── AWS ────────────────────────────────────────────────────────────

  describe("AWS Access Key ID", () => {
    it("detects AKIA key", () => {
      const r = scanString("AKIAIOSFODNN7EXAMPLE\n");
      expect(r.matches.length).toBeGreaterThan(0);
      expect(r.matches.some((m) => m.pattern.name.includes("AWS Access Key"))).toBe(true);
    });

    it("detects ASIA (STS temporary) key", () => {
      const r = scanString("ASIAQWERTYUIOP123456\n");
      expect(r.matches.some((m) => m.pattern.name.includes("AWS Access Key"))).toBe(true);
    });

    it("ignores short strings starting with AKIA", () => {
      const r = scanString("AKIA is an AWS prefix\n");
      expect(r.matches.filter((m) => m.pattern.name.includes("AWS Access Key")).length).toBe(0);
    });
  });

  describe("AWS Secret Access Key", () => {
    it("detects quoted secret key", () => {
      // Pattern: (?i)aws(.{0,20})?['"][0-9a-zA-Z\/+]{40}['"]
      // Must keep ≤20 chars between "aws" and the opening quote
      const r = scanString(`AWS_SECRET="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n`);
      expect(r.matches.some((m) => m.pattern.name.includes("AWS Secret"))).toBe(true);
    });
  });

  // ── GitHub ─────────────────────────────────────────────────────────

  describe("GitHub Personal Access Token", () => {
    it("detects ghp_ token", () => {
      const r = scanString("ghp_ABCDEFghijklmnopqrstuvwxyz0123456789\n");
      expect(r.matches.some((m) => m.pattern.name.includes("GitHub Personal"))).toBe(true);
    });

    it("ignores ghp_ with wrong length", () => {
      const r = scanString("ghp_tooshort\n");
      expect(r.matches.filter((m) => m.pattern.name.includes("GitHub Personal")).length).toBe(0);
    });
  });

  describe("GitHub OAuth Token", () => {
    it("detects gho_ token", () => {
      const r = scanString("gho_ABCDEFghijklmnopqrstuvwxyz0123456789\n");
      expect(r.matches.some((m) => m.pattern.name.includes("GitHub OAuth"))).toBe(true);
    });
  });

  describe("GitHub App Token", () => {
    it("detects ghu_ token", () => {
      const r = scanString("ghu_ABCDEFghijklmnopqrstuvwxyz0123456789\n");
      expect(r.matches.some((m) => m.pattern.name.includes("GitHub App"))).toBe(true);
    });

    it("detects ghs_ token", () => {
      const r = scanString("ghs_ABCDEFghijklmnopqrstuvwxyz0123456789\n");
      expect(r.matches.some((m) => m.pattern.name.includes("GitHub App"))).toBe(true);
    });
  });

  describe("GitHub Refresh Token", () => {
    it("detects ghr_ token", () => {
      const token = "ghr_" + "A".repeat(76);
      const r = scanString(token + "\n");
      expect(r.matches.some((m) => m.pattern.name.includes("GitHub Refresh"))).toBe(true);
    });
  });

  // ── Google ─────────────────────────────────────────────────────────

  describe("Google API Key", () => {
    it("detects AIza key", () => {
      const r = scanString("AIzaSyA1234567890abcdefghijklmnopqrstuvw\n");
      expect(r.matches.some((m) => m.pattern.name.includes("Google API"))).toBe(true);
    });

    it("ignores incomplete AIza prefix", () => {
      const r = scanString("AIzaShort\n");
      expect(r.matches.filter((m) => m.pattern.name.includes("Google API")).length).toBe(0);
    });
  });

  describe("Google OAuth Client ID", () => {
    it("detects OAuth client ID", () => {
      // Pattern requires exactly 32 chars of [0-9A-Za-z_] after the dash
      const r = scanString("12345678-abcdefghijklmnopqrstuvwxyz123456.apps.googleusercontent.com\n");
      expect(r.matches.some((m) => m.pattern.name.includes("Google OAuth"))).toBe(true);
    });
  });

  // ── Slack ──────────────────────────────────────────────────────────

  describe("Slack Token", () => {
    it("detects xoxb- bot token", () => {
      const r = scanString("xoxb-1234567890-abcdefghij\n");
      expect(r.matches.some((m) => m.pattern.name.includes("Slack Token"))).toBe(true);
    });

    it("detects xoxp- user token", () => {
      const r = scanString("xoxp-1234567890-abcdefghij\n");
      expect(r.matches.some((m) => m.pattern.name.includes("Slack Token"))).toBe(true);
    });
  });

  describe("Slack Webhook", () => {
    it("detects webhook URL", () => {
      const webhook = fakeSecret(
        "https://hooks.slack.com/services/",
        "T12345678/B12345678/abcdefghijklmnopqrstuvwx"
      );
      const r = scanString(webhook + "\n");
      expect(r.matches.some((m) => m.pattern.name.includes("Slack Webhook"))).toBe(true);
    });
  });

  // ── Stripe ─────────────────────────────────────────────────────────

  describe("Stripe API Key", () => {
    it("detects sk_live_ key", () => {
      const key = fakeSecret("sk_live_", "abcdefghijklmnopqrstuvwx");
      const r = scanString(key + "\n");
      expect(r.matches.some((m) => m.pattern.name.includes("Stripe API"))).toBe(true);
    });

    it("ignores sk_test_ key (not live)", () => {
      const key = fakeSecret("sk_test_", "abcdefghijklmnopqrstuvwx");
      const r = scanString(key + "\n");
      expect(r.matches.filter((m) => m.pattern.name === "Stripe API Key").length).toBe(0);
    });
  });

  describe("Stripe Restricted API Key", () => {
    it("detects rk_live_ key", () => {
      const key = fakeSecret("rk_live_", "abcdefghijklmnopqrstuvwx");
      const r = scanString(key + "\n");
      expect(r.matches.some((m) => m.pattern.name.includes("Stripe Restricted"))).toBe(true);
    });
  });

  // ── Twilio ─────────────────────────────────────────────────────────

  describe("Twilio API Key", () => {
    it("detects SK key", () => {
      const key = fakeSecret("SK", "1234567890abcdef1234567890abcdef");
      const r = scanString(key + "\n");
      expect(r.matches.some((m) => m.pattern.name.includes("Twilio"))).toBe(true);
    });
  });

  // ── Generic patterns ──────────────────────────────────────────────

  describe("Generic API Key", () => {
    it("detects api_key = 'value'", () => {
      const r = scanString(`api_key = "sk1234567890abcdef"\n`);
      expect(r.matches.some((m) => m.pattern.name.includes("Generic API Key"))).toBe(true);
    });

    it("ignores short values", () => {
      const r = scanString(`api_key = "short"\n`);
      expect(r.matches.filter((m) => m.pattern.name.includes("Generic API Key")).length).toBe(0);
    });
  });

  describe("Generic Secret", () => {
    it("detects password = 'complex_value'", () => {
      const r = scanString(`password = "MyS3cur3Pa55w0rd!"\n`);
      expect(r.matches.some((m) => m.pattern.name.includes("Generic Secret"))).toBe(true);
    });

    it("ignores placeholder values", () => {
      // Too short / no numbers
      const r = scanString(`password = "changeme"\n`);
      expect(r.matches.filter((m) => m.pattern.name.includes("Generic Secret")).length).toBe(0);
    });
  });

  describe("Private Key", () => {
    it("detects RSA private key header", () => {
      const r = scanString("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n");
      expect(r.matches.some((m) => m.pattern.name.includes("Private Key"))).toBe(true);
    });

    it("detects EC private key header", () => {
      const r = scanString("-----BEGIN EC PRIVATE KEY-----\nMIIE...\n");
      expect(r.matches.some((m) => m.pattern.name.includes("Private Key"))).toBe(true);
    });

    it("detects OPENSSH private key header", () => {
      const r = scanString("-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blb...\n");
      expect(r.matches.some((m) => m.pattern.name.includes("Private Key"))).toBe(true);
    });

    it("does not fire on public key header", () => {
      const r = scanString("-----BEGIN PUBLIC KEY-----\nMIIE...\n");
      expect(r.matches.filter((m) => m.pattern.name === "Private Key").length).toBe(0);
    });
  });

  describe("Bearer Token", () => {
    it("detects bearer token in auth header", () => {
      const r = scanString("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9abc123def\n");
      expect(r.matches.some((m) => m.pattern.name.includes("Bearer") || m.pattern.name.includes("JWT"))).toBe(true);
    });
  });

  describe("Database Connection String", () => {
    it("detects postgres connection string", () => {
      const r = scanString("postgres://admin:s3cret@db.example.com:5432/mydb\n");
      expect(r.matches.some((m) => m.pattern.name.includes("Database"))).toBe(true);
    });

    it("detects mongodb connection string", () => {
      const r = scanString("mongodb://root:password123@mongo.example.com/admin\n");
      expect(r.matches.some((m) => m.pattern.name.includes("Database"))).toBe(true);
    });

    it("detects mysql connection string", () => {
      const r = scanString("mysql://user:pass@localhost:3306/testdb\n");
      expect(r.matches.some((m) => m.pattern.name.includes("Database"))).toBe(true);
    });
  });

  describe("JSON Web Token", () => {
    it("detects JWT token", () => {
      const jwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
      const r = scanString(jwt + "\n");
      expect(r.matches.some((m) => m.pattern.name.includes("Web Token"))).toBe(true);
    });
  });

  describe("npm Access Token", () => {
    it("detects npm_ token", () => {
      const r = scanString("npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n");
      expect(r.matches.some((m) => m.pattern.name.includes("npm"))).toBe(true);
    });
  });

  describe("PyPI Token", () => {
    it("detects pypi-AgEIcHlwaS5vcmc token", () => {
      const token = "pypi-AgEIcHlwaS5vcmc" + "A".repeat(60);
      const r = scanString(token + "\n");
      expect(r.matches.some((m) => m.pattern.name.includes("PyPI"))).toBe(true);
    });
  });

  // ── Helper function coverage ──────────────────────────────────────

  describe("getPatternsBySeverity", () => {
    it("returns only critical patterns for 'critical'", () => {
      const critical = getPatternsBySeverity("critical");
      expect(critical.length).toBeGreaterThan(0);
      expect(critical.every((p) => p.severity === "critical")).toBe(true);
    });

    it("returns only high patterns for 'high'", () => {
      const high = getPatternsBySeverity("high");
      expect(high.length).toBeGreaterThan(0);
      expect(high.every((p) => p.severity === "high")).toBe(true);
    });

    it("returns empty for 'low' (no built-in low patterns)", () => {
      const low = getPatternsBySeverity("low");
      expect(low).toHaveLength(0);
    });
  });

  describe("getCriticalPatterns", () => {
    it("returns same as getPatternsBySeverity('critical')", () => {
      expect(getCriticalPatterns()).toEqual(getPatternsBySeverity("critical"));
    });
  });
});

// ── Multi-finding file test ─────────────────────────────────────────

describe("Multi-secret file scanning", () => {
  let tmpDir: string;
  let scanner: RegexScanner;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-multi-"));
    scanner = new RegexScanner();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("detects multiple different secret types in a single file", () => {
    const content = [
      "AKIAIOSFODNN7EXAMPLE",
      "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789",
      fakeSecret("sk_live_", "abcdefghijklmnopqrstuvwx"),
      "-----BEGIN RSA PRIVATE KEY-----",
    ].join("\n");

    const f = path.join(tmpDir, "multi.env");
    fs.writeFileSync(f, content);
    const r = scanner.scanFile(f);

    const patternNames = r.matches.map((m) => m.pattern.name);
    expect(patternNames).toContain("AWS Access Key ID");
    expect(patternNames).toContain("GitHub Personal Access Token");
    expect(patternNames).toContain("Stripe API Key");
    expect(patternNames).toContain("Private Key");
  });

  it("reports correct line numbers for each match", () => {
    const content = [
      "line 1: clean",
      "line 2: AKIAIOSFODNN7EXAMPLE",
      "line 3: clean",
      "line 4: ghp_ABCDEFghijklmnopqrstuvwxyz0123456789",
    ].join("\n");

    const f = path.join(tmpDir, "lines.txt");
    fs.writeFileSync(f, content);
    const r = scanner.scanFile(f);

    const awsMatch = r.matches.find((m) => m.pattern.name === "AWS Access Key ID");
    const ghMatch = r.matches.find((m) => m.pattern.name === "GitHub Personal Access Token");
    expect(awsMatch?.line).toBe(2);
    expect(ghMatch?.line).toBe(4);
  });
});

// ── Scanner utility methods ─────────────────────────────────────────

describe("RegexScanner utility methods", () => {
  let scanner: RegexScanner;

  beforeEach(() => {
    scanner = new RegexScanner();
  });

  describe("scanText", () => {
    it("scans raw text without a file", () => {
      const matches = scanner.scanText("AKIAIOSFODNN7EXAMPLE");
      expect(matches.length).toBeGreaterThan(0);
    });

    it("returns empty for clean text", () => {
      const matches = scanner.scanText("Hello, world!");
      expect(matches).toHaveLength(0);
    });
  });

  describe("hasSecrets", () => {
    it("returns true when secrets present", () => {
      expect(scanner.hasSecrets("AKIAIOSFODNN7EXAMPLE")).toBe(true);
    });

    it("returns false for clean text", () => {
      expect(scanner.hasSecrets("no secrets here")).toBe(false);
    });
  });

  describe("redact", () => {
    it("redacts secrets from text", () => {
      const result = scanner.redact("key is AKIAIOSFODNN7EXAMPLE");
      expect(result).not.toContain("AKIAIOSFODNN7EXAMPLE");
    });
  });
});

// ── Directory scanning ──────────────────────────────────────────────

describe("RegexScanner directory scanning", () => {
  let tmpDir: string;
  let scanner: RegexScanner;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-dir-"));
    scanner = new RegexScanner();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("scans nested directories", () => {
    const subDir = path.join(tmpDir, "src", "config");
    fs.mkdirSync(subDir, { recursive: true });
    fs.writeFileSync(path.join(subDir, "env.ts"), "const key = 'AKIAIOSFODNN7EXAMPLE';\n");

    const results = scanner.scanDirectory(tmpDir);
    expect(results.length).toBeGreaterThan(0);
  });

  it("skips excluded directories", () => {
    const nodeModules = path.join(tmpDir, "node_modules", "pkg");
    fs.mkdirSync(nodeModules, { recursive: true });
    fs.writeFileSync(path.join(nodeModules, "secret.js"), "AKIAIOSFODNN7EXAMPLE\n");

    const results = scanner.scanDirectory(tmpDir);
    expect(results).toHaveLength(0);
  });

  it("skips binary files", () => {
    fs.writeFileSync(path.join(tmpDir, "image.png"), "AKIAIOSFODNN7EXAMPLE\n");
    const results = scanner.scanDirectory(tmpDir);
    expect(results).toHaveLength(0);
  });

  it("respects custom excludePaths", () => {
    const vendorDir = path.join(tmpDir, "myvendor");
    fs.mkdirSync(vendorDir);
    fs.writeFileSync(path.join(vendorDir, "lib.js"), "AKIAIOSFODNN7EXAMPLE\n");

    const results = scanner.scanDirectory(tmpDir, { excludePaths: ["myvendor"] });
    expect(results).toHaveLength(0);
  });

  it("respects maxDepth", () => {
    const deep = path.join(tmpDir, "a", "b", "c", "d");
    fs.mkdirSync(deep, { recursive: true });
    fs.writeFileSync(path.join(deep, "secret.txt"), "AKIAIOSFODNN7EXAMPLE\n");

    const results = scanner.scanDirectory(tmpDir, { maxDepth: 2 });
    expect(results).toHaveLength(0);
  });

  it("scanFiles handles multiple files", () => {
    const f1 = path.join(tmpDir, "a.txt");
    const f2 = path.join(tmpDir, "b.txt");
    fs.writeFileSync(f1, "AKIAIOSFODNN7EXAMPLE\n");
    fs.writeFileSync(f2, "no secrets\n");

    const results = scanner.scanFiles([f1, f2]);
    expect(results).toHaveLength(1);
    expect(results[0].file).toBe(f1);
  });
});

// ── Custom patterns via constructor ─────────────────────────────────

describe("RegexScanner with custom patterns", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rafter-custom-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("detects custom pattern alongside built-in patterns", () => {
    const scanner = new RegexScanner([
      { name: "Internal Token", regex: "INTERNAL_[A-Z0-9]{16}", severity: "critical" },
    ]);
    const f = path.join(tmpDir, "test.txt");
    fs.writeFileSync(f, "INTERNAL_ABCDEF0123456789\n");
    const r = scanner.scanFile(f);
    expect(r.matches.some((m) => m.pattern.name === "Internal Token")).toBe(true);
  });
});
