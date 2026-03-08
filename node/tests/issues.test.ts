import { describe, it, expect } from "vitest";
import crypto from "crypto";

// ── dedup logic (mirrored from src/commands/issues/dedup.ts) ─────────

const FINGERPRINT_PREFIX = "<!-- rafter-fingerprint:";
const FINGERPRINT_SUFFIX = " -->";

function fingerprint(file: string, ruleId: string): string {
  return crypto
    .createHash("sha256")
    .update(`${file}:${ruleId}`)
    .digest("hex")
    .slice(0, 12);
}

function embedFingerprint(body: string, fp: string): string {
  return `${body}\n\n${FINGERPRINT_PREFIX}${fp}${FINGERPRINT_SUFFIX}`;
}

function extractFingerprint(body: string): string | null {
  const idx = body.indexOf(FINGERPRINT_PREFIX);
  if (idx === -1) return null;
  const start = idx + FINGERPRINT_PREFIX.length;
  const end = body.indexOf(FINGERPRINT_SUFFIX, start);
  if (end === -1) return null;
  return body.slice(start, end);
}

type GHIssue = { number: number; title: string; body: string; labels: string[]; html_url: string; state: string };

function findDuplicates(existingIssues: GHIssue[], newFingerprints: string[]): Set<string> {
  const existingFps = new Set<string>();
  for (const issue of existingIssues) {
    const fp = extractFingerprint(issue.body);
    if (fp) existingFps.add(fp);
  }
  return new Set(newFingerprints.filter((fp) => existingFps.has(fp)));
}

describe("fingerprint", () => {
  it("produces deterministic 12-char hex hash", () => {
    const fp = fingerprint("src/config.ts", "AWS_KEY");
    expect(fp).toHaveLength(12);
    expect(fp).toMatch(/^[0-9a-f]{12}$/);
    expect(fingerprint("src/config.ts", "AWS_KEY")).toBe(fp);
  });

  it("differs for different files", () => {
    expect(fingerprint("a.ts", "rule1")).not.toBe(fingerprint("b.ts", "rule1"));
  });

  it("differs for different rules", () => {
    expect(fingerprint("a.ts", "rule1")).not.toBe(fingerprint("a.ts", "rule2"));
  });
});

describe("embedFingerprint / extractFingerprint", () => {
  it("round-trips fingerprint through body", () => {
    const fp = fingerprint("file.ts", "rule");
    const body = embedFingerprint("Some issue body", fp);
    expect(extractFingerprint(body)).toBe(fp);
  });

  it("returns null when no fingerprint embedded", () => {
    expect(extractFingerprint("plain body text")).toBeNull();
  });

  it("returns null for malformed fingerprint", () => {
    expect(extractFingerprint("<!-- rafter-fingerprint:abc")).toBeNull();
  });
});

describe("findDuplicates", () => {
  const makeIssue = (fp: string | null): GHIssue => ({
    number: 1,
    title: "test",
    body: fp ? embedFingerprint("body", fp) : "body without fingerprint",
    labels: [],
    html_url: "https://github.com/test/test/issues/1",
    state: "open",
  });

  it("finds duplicates when fingerprints match", () => {
    const fp = fingerprint("file.ts", "rule");
    const existing = [makeIssue(fp)];
    const dupes = findDuplicates(existing, [fp]);
    expect(dupes.has(fp)).toBe(true);
  });

  it("returns empty set when no matches", () => {
    const existing = [makeIssue(fingerprint("a.ts", "r1"))];
    const dupes = findDuplicates(existing, [fingerprint("b.ts", "r2")]);
    expect(dupes.size).toBe(0);
  });

  it("ignores issues without fingerprints", () => {
    const existing = [makeIssue(null)];
    const dupes = findDuplicates(existing, [fingerprint("file.ts", "rule")]);
    expect(dupes.size).toBe(0);
  });

  it("handles empty existing issues", () => {
    const dupes = findDuplicates([], [fingerprint("file.ts", "rule")]);
    expect(dupes.size).toBe(0);
  });
});

// ── issue-builder logic (mirrored from src/commands/issues/issue-builder.ts) ──

function severityLabel(level: string): string {
  const map: Record<string, string> = {
    error: "critical",
    critical: "critical",
    warning: "high",
    high: "high",
    note: "medium",
    medium: "medium",
    low: "low",
  };
  return map[level.toLowerCase()] || "medium";
}

function severityEmoji(level: string): string {
  const sev = severityLabel(level);
  const emojis: Record<string, string> = {
    critical: "\u{1F534}",
    high: "\u{1F7E0}",
    medium: "\u{1F7E1}",
    low: "\u{1F7E2}",
  };
  return emojis[sev] || "\u{1F7E1}";
}

interface IssueDraft {
  title: string;
  body: string;
  labels: string[];
  fingerprint: string;
}

interface BackendVulnerability {
  ruleId: string;
  level: string;
  message: string;
  file: string;
  line?: number;
}

function buildFromBackendVulnerability(vuln: BackendVulnerability): IssueDraft {
  const sev = severityLabel(vuln.level);
  const emoji = severityEmoji(vuln.level);
  const fp = fingerprint(vuln.file, vuln.ruleId);
  const title = `${emoji} [${sev.toUpperCase()}] ${vuln.ruleId}: ${vuln.message.length > 80 ? vuln.message.slice(0, 77) + "..." : vuln.message}`;
  let body = `## Security Finding\n\n`;
  body += `**Rule:** \`${vuln.ruleId}\`\n`;
  body += `**Severity:** ${sev}\n`;
  body += `**File:** \`${vuln.file}\``;
  if (vuln.line) body += ` (line ${vuln.line})`;
  body += `\n\n`;
  body += `### Description\n\n${vuln.message}\n\n`;
  body += `### Remediation\n\nReview and fix the finding in \`${vuln.file}\`.\n`;
  body += `\n---\n*Created by [Rafter CLI](https://rafter.so) — security for AI builders*\n`;
  const labels = ["security", `severity:${sev}`, `rule:${vuln.ruleId}`];
  return { title, body: embedFingerprint(body, fp), labels, fingerprint: fp };
}

type LocalMatch = { pattern: { name: string; severity: string; description?: string }; line?: number; column?: number; redacted?: string };

function buildFromLocalMatch(file: string, match: LocalMatch): IssueDraft {
  const sev = severityLabel(match.pattern.severity);
  const emoji = severityEmoji(match.pattern.severity);
  const fp = fingerprint(file, match.pattern.name);
  const basename = file.split("/").pop() || file;
  const title = `${emoji} [${sev.toUpperCase()}] Secret detected: ${match.pattern.name} in ${basename}`;
  let body = `## Secret Detection\n\n`;
  body += `**Pattern:** \`${match.pattern.name}\`\n`;
  body += `**Severity:** ${sev}\n`;
  body += `**File:** \`${file}\``;
  if (match.line) body += ` (line ${match.line})`;
  body += `\n`;
  if (match.redacted) body += `**Match:** \`${match.redacted}\`\n`;
  body += `\n`;
  if (match.pattern.description) body += `### Description\n\n${match.pattern.description}\n\n`;
  body += `### Remediation\n\n`;
  body += `1. Rotate the exposed credential immediately\n`;
  body += `2. Remove the secret from source code\n`;
  body += `3. Use environment variables or a secrets manager instead\n`;
  body += `\n---\n*Created by [Rafter CLI](https://rafter.so) — security for AI builders*\n`;
  const labels = ["security", "secret-detected", `severity:${sev}`];
  return { title, body: embedFingerprint(body, fp), labels, fingerprint: fp };
}

describe("severityLabel", () => {
  it("maps error to critical", () => expect(severityLabel("error")).toBe("critical"));
  it("maps warning to high", () => expect(severityLabel("warning")).toBe("high"));
  it("maps note to medium", () => expect(severityLabel("note")).toBe("medium"));
  it("maps low to low", () => expect(severityLabel("low")).toBe("low"));
  it("is case insensitive", () => expect(severityLabel("HIGH")).toBe("high"));
  it("defaults to medium for unknown", () => expect(severityLabel("unknown")).toBe("medium"));
});

describe("buildFromBackendVulnerability", () => {
  const vuln: BackendVulnerability = {
    ruleId: "sql-injection",
    level: "error",
    message: "SQL injection vulnerability detected",
    file: "src/db.ts",
    line: 42,
  };

  it("creates draft with correct title", () => {
    const draft = buildFromBackendVulnerability(vuln);
    expect(draft.title).toContain("[CRITICAL]");
    expect(draft.title).toContain("sql-injection");
  });

  it("includes file and line in body", () => {
    const draft = buildFromBackendVulnerability(vuln);
    expect(draft.body).toContain("`src/db.ts`");
    expect(draft.body).toContain("line 42");
  });

  it("sets security and severity labels", () => {
    const draft = buildFromBackendVulnerability(vuln);
    expect(draft.labels).toContain("security");
    expect(draft.labels).toContain("severity:critical");
    expect(draft.labels).toContain("rule:sql-injection");
  });

  it("embeds fingerprint in body", () => {
    const draft = buildFromBackendVulnerability(vuln);
    expect(extractFingerprint(draft.body)).toBe(draft.fingerprint);
  });

  it("omits line when not provided", () => {
    const noLine = { ...vuln, line: undefined };
    const draft = buildFromBackendVulnerability(noLine);
    expect(draft.body).not.toContain("line ");
  });
});

describe("buildFromLocalMatch", () => {
  const match: LocalMatch = {
    pattern: { name: "AWS Access Key", severity: "high", description: "AWS key found" },
    line: 10,
    redacted: "AKIA****XXXX",
  };

  it("creates draft with pattern name in title", () => {
    const draft = buildFromLocalMatch("src/config.ts", match);
    expect(draft.title).toContain("AWS Access Key");
    expect(draft.title).toContain("config.ts");
    expect(draft.title).toContain("[HIGH]");
  });

  it("includes redacted match in body", () => {
    const draft = buildFromLocalMatch("src/config.ts", match);
    expect(draft.body).toContain("AKIA****XXXX");
  });

  it("includes remediation steps", () => {
    const draft = buildFromLocalMatch("src/config.ts", match);
    expect(draft.body).toContain("Rotate the exposed credential");
    expect(draft.body).toContain("secrets manager");
  });

  it("sets secret-detected label", () => {
    const draft = buildFromLocalMatch("src/config.ts", match);
    expect(draft.labels).toContain("secret-detected");
  });

  it("handles match without description", () => {
    const noDesc = { ...match, pattern: { ...match.pattern, description: undefined } };
    const draft = buildFromLocalMatch("f.ts", noDesc);
    expect(draft.body).not.toContain("### Description");
  });

  it("handles match without redacted value", () => {
    const noRedact = { ...match, redacted: undefined };
    const draft = buildFromLocalMatch("f.ts", noRedact);
    expect(draft.body).not.toContain("**Match:**");
  });
});

// ── from-text parsing logic (mirrored from src/commands/issues/from-text.ts) ──

interface ParsedIssue {
  title: string;
  body: string;
  labels: string[];
}

function parseNaturalText(text: string): ParsedIssue {
  const lines = text.trim().split("\n");
  const labels: string[] = [];
  let title = "";
  let bodyStart = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line) {
      title = line.replace(/^#+\s*/, "").trim();
      bodyStart = i + 1;
      break;
    }
  }
  if (!title) title = "Security issue reported via Rafter CLI";
  if (title.length > 120) title = title.slice(0, 117) + "...";
  const bodyLines = lines.slice(bodyStart);
  let body = bodyLines.join("\n").trim();
  if (!body) body = text.trim();
  const textLower = text.toLowerCase();
  if (textLower.includes("critical") || textLower.includes("p0")) {
    labels.push("severity:critical");
  } else if (textLower.includes("high severity") || textLower.includes("high risk") || textLower.includes("p1")) {
    labels.push("severity:high");
  } else if (textLower.includes("medium") || textLower.includes("p2")) {
    labels.push("severity:medium");
  } else if (textLower.includes("low") || textLower.includes("p3")) {
    labels.push("severity:low");
  }
  const securityKeywords = [
    "security", "vulnerability", "cve", "cwe", "owasp", "secret",
    "credential", "token", "password", "injection", "xss", "csrf", "ssrf", "exploit",
  ];
  if (securityKeywords.some((kw) => textLower.includes(kw))) {
    labels.push("security");
  }
  const fileRefs = text.match(/(?:^|\s)([a-zA-Z0-9_./-]+\.[a-zA-Z]{1,10})(?::(\d+))?/gm);
  if (fileRefs && fileRefs.length > 0) {
    const files = fileRefs.map((f) => f.trim()).filter((f) => f.includes("/") || f.includes("."));
    if (files.length > 0) {
      body += `\n\n### Referenced Files\n\n`;
      for (const f of files.slice(0, 10)) {
        body += `- \`${f}\`\n`;
      }
    }
  }
  body += `\n\n---\n*Created by [Rafter CLI](https://rafter.so) — security for AI builders*\n`;
  return { title, body, labels: [...new Set(labels)] };
}

describe("parseNaturalText", () => {
  it("extracts first line as title", () => {
    const result = parseNaturalText("SQL injection in login form\nDetails here");
    expect(result.title).toBe("SQL injection in login form");
  });

  it("strips markdown headers from title", () => {
    const result = parseNaturalText("## Security Bug\nBody text");
    expect(result.title).toBe("Security Bug");
  });

  it("truncates long titles to 120 chars", () => {
    const longTitle = "A".repeat(150);
    const result = parseNaturalText(longTitle);
    expect(result.title.length).toBeLessThanOrEqual(120);
    expect(result.title.endsWith("...")).toBe(true);
  });

  it("uses default title when text is empty-ish", () => {
    const result = parseNaturalText("   \n   \n   ");
    expect(result.title).toBe("Security issue reported via Rafter CLI");
  });

  it("detects critical severity", () => {
    const result = parseNaturalText("Critical vulnerability in auth");
    expect(result.labels).toContain("severity:critical");
  });

  it("detects P0 as critical", () => {
    const result = parseNaturalText("P0 issue found");
    expect(result.labels).toContain("severity:critical");
  });

  it("detects high severity", () => {
    const result = parseNaturalText("High severity bug in parser");
    expect(result.labels).toContain("severity:high");
  });

  it("detects medium severity", () => {
    const result = parseNaturalText("Medium risk config issue");
    expect(result.labels).toContain("severity:medium");
  });

  it("detects low severity", () => {
    const result = parseNaturalText("Low priority cleanup");
    expect(result.labels).toContain("severity:low");
  });

  it("detects security keywords", () => {
    const result = parseNaturalText("XSS vulnerability in comments");
    expect(result.labels).toContain("security");
  });

  it("extracts file references", () => {
    const result = parseNaturalText("Bug in src/auth.ts:42");
    expect(result.body).toContain("src/auth.ts:42");
    expect(result.body).toContain("### Referenced Files");
  });

  it("adds Rafter footer", () => {
    const result = parseNaturalText("Some issue");
    expect(result.body).toContain("Rafter CLI");
  });

  it("deduplicates labels", () => {
    const result = parseNaturalText("Critical security vulnerability with credentials and tokens");
    const uniqueLabels = [...new Set(result.labels)];
    expect(result.labels).toEqual(uniqueLabels);
  });
});
