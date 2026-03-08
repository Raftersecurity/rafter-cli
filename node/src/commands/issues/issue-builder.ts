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

/** Backend vulnerability from `rafter get <id> --format json` */
export interface BackendVulnerability {
  ruleId: string;
  level: string;
  message: string;
  file: string;
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
  const sev = severityLabel(vuln.level);
  const emoji = severityEmoji(vuln.level);
  const fp = fingerprint(vuln.file, vuln.ruleId);

  const title = `${emoji} [${sev.toUpperCase()}] ${vuln.ruleId}: ${truncate(vuln.message, 80)}`;

  let body = `## Security Finding\n\n`;
  body += `**Rule:** \`${vuln.ruleId}\`\n`;
  body += `**Severity:** ${sev}\n`;
  body += `**File:** \`${vuln.file}\``;
  if (vuln.line) body += ` (line ${vuln.line})`;
  body += `\n\n`;
  body += `### Description\n\n${vuln.message}\n\n`;
  body += `### Remediation\n\nReview and fix the finding in \`${vuln.file}\`.\n`;
  body += `\n---\n*Created by [Rafter CLI](https://rafter.so) — security for AI builders*\n`;

  const labels = [
    "security",
    `severity:${sev}`,
    `rule:${vuln.ruleId}`,
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
