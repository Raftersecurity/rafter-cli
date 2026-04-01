import { describe, it, expect } from "vitest";
import { scanText, SECRET_PATTERNS } from "../src/secret-scanner";

describe("scanText", () => {
  it("detects AWS access keys", () => {
    const text = 'const key = "AKIAIOSFODNN7EXAMPLE";';
    const matches = scanText(text);
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].pattern.name).toBe("AWS Access Key");
    expect(matches[0].pattern.severity).toBe("critical");
  });

  it("detects GitHub tokens", () => {
    const text = 'TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij';
    const matches = scanText(text);
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].pattern.name).toBe("GitHub Token");
  });

  it("detects private keys", () => {
    const text = "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALR...";
    const matches = scanText(text);
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].pattern.name).toBe("Private Key");
  });

  it("detects Stripe secret keys", () => {
    // Build test token dynamically to avoid push protection
    const prefix = "sk_live_";
    const suffix = "0".repeat(24);
    const text = `stripe_key = "${prefix}${suffix}"`;
    const matches = scanText(text);
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].pattern.name).toBe("Stripe Secret Key");
  });

  it("detects NPM tokens", () => {
    const text = "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789";
    const matches = scanText(text);
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].pattern.name).toBe("NPM Token");
  });

  it("reports correct line and column", () => {
    const text = 'line one\nconst key = "AKIAIOSFODNN7EXAMPLE";\nline three';
    const matches = scanText(text);
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].line).toBe(1); // 0-indexed
  });

  it("skips lines after rafter-ignore comment", () => {
    const text = '// rafter-ignore\nconst key = "AKIAIOSFODNN7EXAMPLE";';
    const matches = scanText(text);
    expect(matches.length).toBe(0);
  });

  it("filters false positives for generic patterns", () => {
    const text = 'api_key = "YOUR_API_KEY_HERE"';
    const matches = scanText(text);
    const genericMatches = matches.filter((m) => m.pattern.name === "Generic API Key");
    expect(genericMatches.length).toBe(0);
  });

  it("filters placeholder values", () => {
    const text = 'secret = "changeme"';
    const matches = scanText(text);
    const genericMatches = matches.filter((m) => m.pattern.name === "Generic Secret");
    expect(genericMatches.length).toBe(0);
  });

  it("returns empty for clean files", () => {
    const text = "const x = 42;\nconsole.log('hello world');\n";
    const matches = scanText(text);
    expect(matches.length).toBe(0);
  });

  it("detects JWT tokens", () => {
    const text = 'const jwt = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    const matches = scanText(text);
    const jwtMatches = matches.filter((m) => m.pattern.name === "JWT Token");
    expect(jwtMatches.length).toBeGreaterThan(0);
  });
});

describe("SECRET_PATTERNS", () => {
  it("has expected number of patterns", () => {
    expect(SECRET_PATTERNS.length).toBeGreaterThanOrEqual(10);
  });

  it("all patterns have required fields", () => {
    for (const p of SECRET_PATTERNS) {
      expect(p.name).toBeTruthy();
      expect(p.regex).toBeTruthy();
      expect(["low", "medium", "high", "critical"]).toContain(p.severity);
    }
  });

  it("all regex patterns compile", () => {
    for (const p of SECRET_PATTERNS) {
      expect(() => new RegExp(p.regex, "g")).not.toThrow();
    }
  });
});
