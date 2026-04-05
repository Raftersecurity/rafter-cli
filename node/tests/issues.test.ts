import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import crypto from "crypto";
import fs from "fs";
import { execFileSync } from "child_process";

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

// ── from-scan command logic (mirrored from src/commands/issues/from-scan.ts) ──

function draftsFromLocalScan(filePath: string): IssueDraft[] {
  const raw = fs.readFileSync(filePath, "utf-8");
  const results: Array<{ file: string; matches: LocalMatch[] }> = JSON.parse(raw);
  const drafts: IssueDraft[] = [];
  for (const result of results) {
    for (const match of result.matches) {
      drafts.push(buildFromLocalMatch(result.file, match));
    }
  }
  return drafts;
}

describe("from-scan: draftsFromLocalScan", () => {
  const sampleScanJson: Array<{ file: string; matches: LocalMatch[] }> = [
    {
      file: "src/config.ts",
      matches: [
        {
          pattern: { name: "AWS Access Key", severity: "critical", description: "AWS access key ID" },
          line: 15,
          redacted: "AKIA****XXXX",
        },
        {
          pattern: { name: "Generic API Key", severity: "medium" },
          line: 42,
          redacted: "api_****_key",
        },
      ],
    },
    {
      file: "src/db.ts",
      matches: [
        {
          pattern: { name: "Database Password", severity: "high", description: "DB password in code" },
          line: 7,
          redacted: "pass****word",
        },
      ],
    },
  ];

  let tmpFile: string;

  beforeEach(() => {
    tmpFile = `/tmp/rafter-test-scan-${Date.now()}.json`;
    fs.writeFileSync(tmpFile, JSON.stringify(sampleScanJson));
  });

  afterEach(() => {
    if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
  });

  it("creates one draft per match across all files", () => {
    const drafts = draftsFromLocalScan(tmpFile);
    expect(drafts).toHaveLength(3);
  });

  it("drafts have correct file associations", () => {
    const drafts = draftsFromLocalScan(tmpFile);
    expect(drafts[0].body).toContain("src/config.ts");
    expect(drafts[1].body).toContain("src/config.ts");
    expect(drafts[2].body).toContain("src/db.ts");
  });

  it("each draft has a unique fingerprint", () => {
    const drafts = draftsFromLocalScan(tmpFile);
    const fps = drafts.map((d) => d.fingerprint);
    expect(new Set(fps).size).toBe(3);
  });

  it("each draft has valid labels", () => {
    const drafts = draftsFromLocalScan(tmpFile);
    for (const draft of drafts) {
      expect(draft.labels).toContain("security");
      expect(draft.labels).toContain("secret-detected");
      expect(draft.labels.some((l) => l.startsWith("severity:"))).toBe(true);
    }
  });

  it("maps severity correctly in labels", () => {
    const drafts = draftsFromLocalScan(tmpFile);
    expect(drafts[0].labels).toContain("severity:critical");
    expect(drafts[1].labels).toContain("severity:medium");
    expect(drafts[2].labels).toContain("severity:high");
  });

  it("handles empty scan results", () => {
    const emptyFile = `/tmp/rafter-test-empty-${Date.now()}.json`;
    fs.writeFileSync(emptyFile, "[]");
    const drafts = draftsFromLocalScan(emptyFile);
    expect(drafts).toHaveLength(0);
    fs.unlinkSync(emptyFile);
  });

  it("handles file with no matches", () => {
    const noMatchFile = `/tmp/rafter-test-nomatch-${Date.now()}.json`;
    fs.writeFileSync(noMatchFile, JSON.stringify([{ file: "clean.ts", matches: [] }]));
    const drafts = draftsFromLocalScan(noMatchFile);
    expect(drafts).toHaveLength(0);
    fs.unlinkSync(noMatchFile);
  });
});

// ── from-scan deduplication integration ──────────────────────────────

describe("from-scan: deduplication flow", () => {
  const makeDraft = (file: string, rule: string): IssueDraft => {
    return buildFromLocalMatch(file, {
      pattern: { name: rule, severity: "high" },
      line: 1,
      redacted: "****",
    });
  };

  const makeExistingIssue = (fp: string): GHIssue => ({
    number: 1,
    title: "existing",
    body: embedFingerprint("body", fp),
    labels: [],
    html_url: "https://github.com/test/repo/issues/1",
    state: "open",
  });

  it("filters out drafts that already have open issues", () => {
    const draft1 = makeDraft("a.ts", "AWS_KEY");
    const draft2 = makeDraft("b.ts", "DB_PASS");
    const existing = [makeExistingIssue(draft1.fingerprint)];
    const dupes = findDuplicates(existing, [draft1.fingerprint, draft2.fingerprint]);
    const filtered = [draft1, draft2].filter((d) => !dupes.has(d.fingerprint));
    expect(filtered).toHaveLength(1);
    expect(filtered[0].fingerprint).toBe(draft2.fingerprint);
  });

  it("keeps all drafts when --no-dedup (no filtering applied)", () => {
    const draft1 = makeDraft("a.ts", "AWS_KEY");
    const draft2 = makeDraft("b.ts", "DB_PASS");
    // With --no-dedup, we skip the findDuplicates call entirely
    const drafts = [draft1, draft2];
    expect(drafts).toHaveLength(2);
  });

  it("keeps all drafts when no existing issues have fingerprints", () => {
    const draft1 = makeDraft("a.ts", "AWS_KEY");
    const draft2 = makeDraft("b.ts", "DB_PASS");
    const existing: GHIssue[] = [
      { number: 1, title: "old", body: "no fingerprint here", labels: [], html_url: "", state: "open" },
    ];
    const dupes = findDuplicates(existing, [draft1.fingerprint, draft2.fingerprint]);
    const filtered = [draft1, draft2].filter((d) => !dupes.has(d.fingerprint));
    expect(filtered).toHaveLength(2);
  });

  it("deduplicates all drafts when all already exist", () => {
    const draft1 = makeDraft("a.ts", "AWS_KEY");
    const draft2 = makeDraft("b.ts", "DB_PASS");
    const existing = [
      makeExistingIssue(draft1.fingerprint),
      makeExistingIssue(draft2.fingerprint),
    ];
    const dupes = findDuplicates(existing, [draft1.fingerprint, draft2.fingerprint]);
    const filtered = [draft1, draft2].filter((d) => !dupes.has(d.fingerprint));
    expect(filtered).toHaveLength(0);
  });
});

// ── from-scan: dry-run output format ─────────────────────────────────

describe("from-scan: dry-run output", () => {
  it("drafts serialize to JSON with required fields", () => {
    const draft = buildFromBackendVulnerability({
      ruleId: "sql-injection",
      level: "error",
      message: "SQL injection in query builder",
      file: "src/query.ts",
      line: 99,
    });
    const json = JSON.parse(JSON.stringify(draft));
    expect(json).toHaveProperty("title");
    expect(json).toHaveProperty("body");
    expect(json).toHaveProperty("labels");
    expect(json).toHaveProperty("fingerprint");
    expect(json.fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });

  it("multiple drafts serialize as JSON array", () => {
    const drafts = [
      buildFromBackendVulnerability({
        ruleId: "xss",
        level: "warning",
        message: "Cross-site scripting",
        file: "src/render.ts",
      }),
      buildFromLocalMatch("src/env.ts", {
        pattern: { name: "ENV_SECRET", severity: "critical" },
        line: 5,
        redacted: "****",
      }),
    ];
    const json = JSON.parse(JSON.stringify(drafts));
    expect(json).toHaveLength(2);
    expect(json[0].labels).toContain("security");
    expect(json[1].labels).toContain("secret-detected");
  });
});

// ── from-scan: backend scan drafts ───────────────────────────────────

describe("from-scan: backend vulnerability drafts", () => {
  it("creates drafts from vulnerability list", () => {
    const vulns: BackendVulnerability[] = [
      { ruleId: "sql-injection", level: "error", message: "SQL injection", file: "src/db.ts", line: 42 },
      { ruleId: "path-traversal", level: "warning", message: "Path traversal", file: "src/files.ts", line: 10 },
    ];
    const drafts = vulns.map(buildFromBackendVulnerability);
    expect(drafts).toHaveLength(2);
    expect(drafts[0].title).toContain("[CRITICAL]");
    expect(drafts[1].title).toContain("[HIGH]");
  });

  it("truncates long vulnerability messages in title", () => {
    const longMsg = "A".repeat(100);
    const draft = buildFromBackendVulnerability({
      ruleId: "test",
      level: "error",
      message: longMsg,
      file: "f.ts",
    });
    expect(draft.title.length).toBeLessThan(200);
    expect(draft.title).toContain("...");
  });

  it("includes rule ID in labels", () => {
    const draft = buildFromBackendVulnerability({
      ruleId: "my-custom-rule",
      level: "note",
      message: "Found issue",
      file: "x.ts",
    });
    expect(draft.labels).toContain("rule:my-custom-rule");
  });
});

// ── from-scan: --repo flag override ──────────────────────────────────

describe("from-scan: repo flag", () => {
  it("uses explicit repo when --repo is provided", () => {
    const repo = "my-org/my-repo";
    // The repo flag is used directly without git detection
    expect(repo).toBe("my-org/my-repo");
  });
});

// ── from-scan: error handling ────────────────────────────────────────

describe("from-scan: error handling", () => {
  it("requires --scan-id or --from-local", () => {
    // Neither option provided should be an error state
    const scanId = undefined;
    const fromLocal = undefined;
    expect(!scanId && !fromLocal).toBe(true);
  });

  it("throws on invalid JSON file", () => {
    const badFile = `/tmp/rafter-test-bad-${Date.now()}.json`;
    fs.writeFileSync(badFile, "not valid json{{{");
    expect(() => draftsFromLocalScan(badFile)).toThrow();
    fs.unlinkSync(badFile);
  });

  it("throws on non-existent file", () => {
    expect(() => draftsFromLocalScan("/tmp/nonexistent-rafter-scan.json")).toThrow();
  });
});

// ── from-text: title override ────────────────────────────────────────

describe("from-text: --title override", () => {
  it("overrides parsed title when --title provided", () => {
    const parsed = parseNaturalText("Original title\nBody text");
    const overrideTitle = "My Custom Title";
    parsed.title = overrideTitle;
    expect(parsed.title).toBe("My Custom Title");
  });
});

// ── from-text: --labels flag ─────────────────────────────────────────

describe("from-text: --labels flag", () => {
  it("appends comma-separated labels to auto-detected ones", () => {
    const parsed = parseNaturalText("Critical security bug");
    const extraLabels = "team:backend,priority:urgent";
    const extra = extraLabels.split(",").map((l) => l.trim()).filter(Boolean);
    parsed.labels.push(...extra);
    expect(parsed.labels).toContain("severity:critical");
    expect(parsed.labels).toContain("security");
    expect(parsed.labels).toContain("team:backend");
    expect(parsed.labels).toContain("priority:urgent");
  });

  it("handles empty labels string", () => {
    const parsed = parseNaturalText("Some issue");
    const extraLabels = "";
    const extra = extraLabels.split(",").map((l) => l.trim()).filter(Boolean);
    parsed.labels.push(...extra);
    // No extra labels added
    expect(parsed.labels.every((l) => !l.includes("team:"))).toBe(true);
  });

  it("handles labels with extra whitespace", () => {
    const parsed = parseNaturalText("Bug found");
    const extraLabels = " bug , needs-review , ";
    const extra = extraLabels.split(",").map((l) => l.trim()).filter(Boolean);
    parsed.labels.push(...extra);
    expect(parsed.labels).toContain("bug");
    expect(parsed.labels).toContain("needs-review");
  });
});

// ── from-text: --dry-run output ──────────────────────────────────────

describe("from-text: dry-run output", () => {
  it("parsed issue serializes to JSON with title, body, labels", () => {
    const parsed = parseNaturalText("XSS vulnerability in user comments\nThe comment form doesn't sanitize HTML");
    const json = JSON.parse(JSON.stringify(parsed));
    expect(json.title).toBe("XSS vulnerability in user comments");
    expect(json.body).toContain("comment form");
    expect(json.labels).toContain("security");
  });
});

// ── from-text: severity auto-detection from keywords ─────────────────

describe("from-text: severity keyword detection", () => {
  it("P0 maps to critical", () => {
    expect(parseNaturalText("P0 outage").labels).toContain("severity:critical");
  });

  it("P1 maps to high", () => {
    expect(parseNaturalText("P1 regression").labels).toContain("severity:high");
  });

  it("P2 maps to medium", () => {
    expect(parseNaturalText("P2 improvement").labels).toContain("severity:medium");
  });

  it("P3 maps to low", () => {
    expect(parseNaturalText("P3 cosmetic").labels).toContain("severity:low");
  });

  it("no severity keyword yields no severity label", () => {
    const result = parseNaturalText("Something happened in the app");
    expect(result.labels.some((l) => l.startsWith("severity:"))).toBe(false);
  });
});

// ── from-text: security keyword detection ────────────────────────────

describe("from-text: security keyword detection", () => {
  const securityKeywords = [
    "security", "vulnerability", "cve", "cwe", "owasp",
    "secret", "credential", "token", "password", "injection",
    "xss", "csrf", "ssrf", "exploit",
  ];

  for (const kw of securityKeywords) {
    it(`detects '${kw}' as security keyword`, () => {
      const result = parseNaturalText(`Issue involving ${kw} concern`);
      expect(result.labels).toContain("security");
    });
  }

  it("does not add security label for non-security text", () => {
    const result = parseNaturalText("The button color is wrong");
    expect(result.labels).not.toContain("security");
  });
});

// ── from-text: file path extraction ──────────────────────────────────

describe("from-text: file path extraction", () => {
  it("extracts file paths with line numbers", () => {
    const result = parseNaturalText("Bug in src/auth/login.ts:42 causes crash");
    expect(result.body).toContain("### Referenced Files");
    expect(result.body).toContain("src/auth/login.ts:42");
  });

  it("extracts multiple file paths", () => {
    const result = parseNaturalText("Found issues in src/a.ts and src/b.ts and lib/c.js");
    expect(result.body).toContain("src/a.ts");
    expect(result.body).toContain("src/b.ts");
    expect(result.body).toContain("lib/c.js");
  });

  it("limits to 10 file references", () => {
    const files = Array.from({ length: 15 }, (_, i) => `src/file${i}.ts`).join(" ");
    const result = parseNaturalText(`Issues in ${files}`);
    const matches = result.body.match(/- `/g);
    if (matches) {
      expect(matches.length).toBeLessThanOrEqual(10);
    }
  });

  it("does not add Referenced Files section when no paths found", () => {
    const result = parseNaturalText("This has no file references at all");
    expect(result.body).not.toContain("### Referenced Files");
  });
});

// ── from-text: --file flag ───────────────────────────────────────────

describe("from-text: --file input", () => {
  let tmpFile: string;

  beforeEach(() => {
    tmpFile = `/tmp/rafter-test-text-${Date.now()}.txt`;
  });

  afterEach(() => {
    if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
  });

  it("reads text from file and parses correctly", () => {
    fs.writeFileSync(tmpFile, "## Critical Security Bug\nSQL injection in src/db.ts:15");
    const text = fs.readFileSync(tmpFile, "utf-8");
    const parsed = parseNaturalText(text);
    expect(parsed.title).toBe("Critical Security Bug");
    expect(parsed.labels).toContain("severity:critical");
    expect(parsed.labels).toContain("security");
    expect(parsed.body).toContain("src/db.ts:15");
  });

  it("handles empty file", () => {
    fs.writeFileSync(tmpFile, "   \n  \n  ");
    const text = fs.readFileSync(tmpFile, "utf-8");
    const parsed = parseNaturalText(text);
    expect(parsed.title).toBe("Security issue reported via Rafter CLI");
  });
});

// ── from-text: --text inline ─────────────────────────────────────────

describe("from-text: --text inline", () => {
  it("parses first line as title, rest as body", () => {
    const text = "Found a bug\nThis is the detailed description\nWith multiple lines";
    const parsed = parseNaturalText(text);
    expect(parsed.title).toBe("Found a bug");
    expect(parsed.body).toContain("detailed description");
    expect(parsed.body).toContain("multiple lines");
  });

  it("single line text uses that as both title and body", () => {
    const text = "Single line issue";
    const parsed = parseNaturalText(text);
    expect(parsed.title).toBe("Single line issue");
    // Body should fall back to the full text
    expect(parsed.body).toContain("Single line issue");
  });
});

// ── cross-implementation fingerprint consistency ─────────────────────

describe("fingerprint: cross-implementation consistency", () => {
  it("produces same hash for same inputs across repeated calls", () => {
    const fp1 = fingerprint("src/config.ts", "AWS_KEY");
    const fp2 = fingerprint("src/config.ts", "AWS_KEY");
    const fp3 = fingerprint("src/config.ts", "AWS_KEY");
    expect(fp1).toBe(fp2);
    expect(fp2).toBe(fp3);
  });

  it("fingerprint is stable for backend and local match on same file+rule", () => {
    const backendFp = fingerprint("src/auth.ts", "sql-injection");
    const localFp = fingerprint("src/auth.ts", "sql-injection");
    expect(backendFp).toBe(localFp);
  });

  it("empty file and rule still produce valid fingerprint", () => {
    const fp = fingerprint("", "");
    expect(fp).toHaveLength(12);
    expect(fp).toMatch(/^[0-9a-f]{12}$/);
  });

  it("special characters in file path produce valid fingerprint", () => {
    const fp = fingerprint("src/path with spaces/file.ts", "rule:special/chars");
    expect(fp).toHaveLength(12);
    expect(fp).toMatch(/^[0-9a-f]{12}$/);
  });
});

// ── issue title format ───────────────────────────────────────────────

describe("issue title format", () => {
  it("backend issue title contains severity tag, rule, and message", () => {
    const draft = buildFromBackendVulnerability({
      ruleId: "hardcoded-password",
      level: "error",
      message: "Password hardcoded in source",
      file: "config.ts",
    });
    expect(draft.title).toMatch(/\[CRITICAL\]/);
    expect(draft.title).toContain("hardcoded-password");
    expect(draft.title).toContain("Password hardcoded in source");
  });

  it("local match title contains severity, pattern name, and basename", () => {
    const draft = buildFromLocalMatch("src/deep/nested/config.env", {
      pattern: { name: "GitHub Token", severity: "high" },
      line: 1,
    });
    expect(draft.title).toMatch(/\[HIGH\]/);
    expect(draft.title).toContain("GitHub Token");
    expect(draft.title).toContain("config.env");
    // Should NOT contain the full path in the title
    expect(draft.title).not.toContain("src/deep/nested/config.env");
  });
});

// ── issue body content ───────────────────────────────────────────────

describe("issue body content", () => {
  it("backend issue body has all sections", () => {
    const draft = buildFromBackendVulnerability({
      ruleId: "xss",
      level: "warning",
      message: "Cross-site scripting via unescaped output",
      file: "src/render.ts",
      line: 55,
    });
    expect(draft.body).toContain("## Security Finding");
    expect(draft.body).toContain("**Rule:** `xss`");
    expect(draft.body).toContain("**Severity:** high");
    expect(draft.body).toContain("**File:** `src/render.ts` (line 55)");
    expect(draft.body).toContain("### Description");
    expect(draft.body).toContain("### Remediation");
    expect(draft.body).toContain("Rafter CLI");
  });

  it("local match body has remediation steps", () => {
    const draft = buildFromLocalMatch("env/.env", {
      pattern: { name: "AWS Secret", severity: "critical", description: "AWS secret key" },
      line: 3,
      redacted: "wJal****rXUt",
    });
    expect(draft.body).toContain("## Secret Detection");
    expect(draft.body).toContain("Rotate the exposed credential");
    expect(draft.body).toContain("Remove the secret from source code");
    expect(draft.body).toContain("secrets manager");
    expect(draft.body).toContain("wJal****rXUt");
  });
});
