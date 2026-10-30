/**
 * Build structured GitHub issues from scan findings.
 *
 * Handles both:
 * - Backend scan vulnerabilities (SAST/policy findings)
 * - Local scan results (secret detection)
 */
import { fingerprint, embedFingerprint } from "./dedup.js";

export interface IssueDraft {
  title: string;
  body: string;
  labels: string[];
  fingerprint: string;
}

/**
 * Backend vulnerability from `GET /api/static/scan` (`rafter get <id> --format json`).
 *
 * The real API shape (`toRafterFindings()` on the backend) is
 * `rule_id`/`severity`/`title`/`description`/`file_path`/`line_start`/`line_end`
 * plus optional `cwe`/`confidence`. The `ruleId`/`level`/`message`/`file`/`line`
 * names below are the pre-rename shape; kept as a fallback for old cached
 * payloads and existing tests, never the primary source.
 */
export interface BackendVulnerability {
  rule_id?: string;
  severity?: string;
  title?: string;
  description?: string;
  file_path?: string | null;
  line_start?: number | null;
  line_end?: number | null;
  cwe?: string;
  confidence?: string;
  /** @deprecated pre-rename name — use `rule_id` */
  ruleId?: string;
  /** @deprecated pre-rename name — use `severity` */
  level?: string;
  /** @deprecated pre-rename name — use `title`/`description` */
  message?: string;
  /** @deprecated pre-rename name — use `file_path` */
  file?: string;
  /** @deprecated pre-rename name — use `line_start` */
  line?: number;
  result?: any;
}

/** Local scan result from `rafter scan local --format json` */
export interface LocalScanResult {
  file: string;
  matches: Array<{
    pattern: { name: string; severity: string; description?: string };
    line?: number;
    column?: number;
    redacted?: string;
  }>;
}

export function severityLabel(level: string): string {
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
    critical: "🔴",
    high: "🟠",
    medium: "🟡",
    low: "🟢",
  };
  return emojis[sev] || "🟡";
}

export function buildFromBackendVulnerability(
  vuln: BackendVulnerability
): IssueDraft {
  const ruleId = vuln.rule_id ?? vuln.ruleId ?? "unknown-rule";
  const level = vuln.severity ?? vuln.level ?? "note";
  const summary = vuln.title ?? vuln.message ?? "Security finding";
  const details = vuln.description ?? vuln.message ?? summary;
  const file = vuln.file_path ?? vuln.file ?? "unknown file";
  const line = vuln.line_start ?? vuln.line;

  const sev = severityLabel(level);
  const emoji = severityEmoji(level);
  const fp = fingerprint(file, ruleId);

  const title = `${emoji} [${sev.toUpperCase()}] ${ruleId}: ${truncate(summary, 80)}`;

  let body = `## Security Finding\n\n`;
  body += `**Rule:** \`${ruleId}\`\n`;
  body += `**Severity:** ${sev}\n`;
  body += `**File:** \`${file}\``;
  if (line) body += ` (line ${line})`;
  body += `\n\n`;
  body += `### Description\n\n${details}\n\n`;
  body += `### Remediation\n\nReview and fix the finding in \`${file}\`.\n`;
  body += `\n---\n*Created by [Rafter CLI](https://rafter.so) — security for AI builders*\n`;

  const labels = [
    "security",
    `severity:${sev}`,
    `rule:${ruleId}`,
  ];

  return {
    title,
    body: embedFingerprint(body, fp),
    labels,
    fingerprint: fp,
  };
}

export function buildFromLocalMatch(
  file: string,
  match: LocalScanResult["matches"][0]
): IssueDraft {
  const sev = severityLabel(match.pattern.severity);
  const emoji = severityEmoji(match.pattern.severity);
  const fp = fingerprint(file, match.pattern.name);

  const title = `${emoji} [${sev.toUpperCase()}] Secret detected: ${match.pattern.name} in ${basename(file)}`;

  let body = `## Secret Detection\n\n`;
  body += `**Pattern:** \`${match.pattern.name}\`\n`;
  body += `**Severity:** ${sev}\n`;
  body += `**File:** \`${file}\``;
  if (match.line) body += ` (line ${match.line})`;
  body += `\n`;
  if (match.redacted) {
    body += `**Match:** \`${match.redacted}\`\n`;
  }
  body += `\n`;
  if (match.pattern.description) {
    body += `### Description\n\n${match.pattern.description}\n\n`;
  }
  body += `### Remediation\n\n`;
  body += `1. Rotate the exposed credential immediately\n`;
  body += `2. Remove the secret from source code\n`;
  body += `3. Use environment variables or a secrets manager instead\n`;
  body += `\n---\n*Created by [Rafter CLI](https://rafter.so) — security for AI builders*\n`;

  const labels = [
    "security",
    "secret-detected",
    `severity:${sev}`,
  ];

  return {
    title,
    body: embedFingerprint(body, fp),
    labels,
    fingerprint: fp,
  };
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 3) + "...";
}

function basename(filepath: string): string {
  return filepath.split("/").pop() || filepath;
}
