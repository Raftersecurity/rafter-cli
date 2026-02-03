import { describe, it, expect } from "vitest";
import { PatternEngine, Pattern } from "../src/core/pattern-engine.js";

describe("PatternEngine", () => {
  const testPatterns: Pattern[] = [
    {
      name: "AWS Access Key",
      regex: "AKIA[0-9A-Z]{16}",
      severity: "critical",
      description: "AWS Access Key detected"
    },
    {
      name: "GitHub Token",
      regex: "ghp_[a-zA-Z0-9]{36}",
      severity: "critical",
      description: "GitHub token detected"
    },
    {
      name: "Generic API Key",
      regex: "(?i)api[_-]?key[\\s]*[:=][\\s]*['\"]?[0-9a-zA-Z\\-_]{16,}['\"]?",
      severity: "high",
      description: "Generic API key pattern"
    }
  ];

  it("should detect AWS keys", () => {
    const engine = new PatternEngine(testPatterns);
    const text = 'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";';

    const matches = engine.scan(text);

    expect(matches.length).toBe(1);
    expect(matches[0].pattern.name).toBe("AWS Access Key");
    expect(matches[0].match).toBe("AKIAIOSFODNN7EXAMPLE");
  });

  it("should detect GitHub tokens", () => {
    const engine = new PatternEngine(testPatterns);
    // GitHub token: ghp_ + 36 alphanumeric chars
    const text = 'const token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";';

    const matches = engine.scan(text);

    expect(matches.length).toBeGreaterThan(0);
    const githubMatch = matches.find(m => m.pattern.name === "GitHub Token");
    expect(githubMatch).toBeDefined();
  });

  it("should handle case-insensitive patterns", () => {
    const engine = new PatternEngine(testPatterns);
    const text = 'API_KEY="my-secret-key-123456"';

    const matches = engine.scan(text);

    expect(matches.length).toBeGreaterThan(0);
    const apiKeyMatch = matches.find(m => m.pattern.name === "Generic API Key");
    expect(apiKeyMatch).toBeDefined();
  });

  it("should redact secrets", () => {
    const engine = new PatternEngine(testPatterns);
    const text = 'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";';

    const matches = engine.scan(text);

    expect(matches[0].redacted).toBe("AKIA************MPLE");
  });

  it("should provide line/column info", () => {
    const engine = new PatternEngine(testPatterns);
    const text = `line 1
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
line 3`;

    const matches = engine.scanWithPosition(text);

    expect(matches.length).toBe(1);
    expect(matches[0].line).toBe(2);
    expect(matches[0].column).toBeGreaterThan(0);
  });

  it("should return empty array for clean text", () => {
    const engine = new PatternEngine(testPatterns);
    const text = "const safe = 'no secrets here';";

    const matches = engine.scan(text);

    expect(matches.length).toBe(0);
  });

  it("should detect multiple secrets in same text", () => {
    const engine = new PatternEngine(testPatterns);
    const text = `
      const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
      const GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
    `;

    const matches = engine.scan(text);

    // Should find at least AWS key and GitHub token
    expect(matches.length).toBeGreaterThanOrEqual(2);
    const awsMatch = matches.find(m => m.pattern.name === "AWS Access Key");
    const githubMatch = matches.find(m => m.pattern.name === "GitHub Token");
    expect(awsMatch).toBeDefined();
    expect(githubMatch).toBeDefined();
  });

  it("should filter by severity", () => {
    const engine = new PatternEngine(testPatterns);
    const critical = engine.getPatternsBySeverity("critical");

    expect(critical.length).toBe(2);
    expect(critical.every(p => p.severity === "critical")).toBe(true);
  });
});
