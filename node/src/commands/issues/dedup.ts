/**
 * Deduplication logic for GitHub issues created from scan findings.
 *
 * Uses a fingerprint hash (file + pattern/ruleId) embedded in the issue body
 * to avoid creating duplicate issues for the same finding.
 */
import crypto from "crypto";
import { GitHubIssue } from "./github-client.js";

const FINGERPRINT_PREFIX = "<!-- rafter-fingerprint:";
const FINGERPRINT_SUFFIX = " -->";

export function fingerprint(file: string, ruleId: string): string {
  const hash = crypto
    .createHash("sha256")
    .update(`${file}:${ruleId}`)
    .digest("hex")
    .slice(0, 12);
  return hash;
}

export function embedFingerprint(body: string, fp: string): string {
  return `${body}\n\n${FINGERPRINT_PREFIX}${fp}${FINGERPRINT_SUFFIX}`;
}

export function extractFingerprint(body: string): string | null {
  const idx = body.indexOf(FINGERPRINT_PREFIX);
  if (idx === -1) return null;
  const start = idx + FINGERPRINT_PREFIX.length;
  const end = body.indexOf(FINGERPRINT_SUFFIX, start);
  if (end === -1) return null;
  return body.slice(start, end);
}

export function findDuplicates(
  existingIssues: GitHubIssue[],
  newFingerprints: string[]
): Set<string> {
  const existingFps = new Set<string>();
  for (const issue of existingIssues) {
    const fp = extractFingerprint(issue.body);
    if (fp) existingFps.add(fp);
  }
  return new Set(newFingerprints.filter((fp) => existingFps.has(fp)));
}
