/**
 * Secret scanning engine — inline pattern matching.
 *
 * Replicates the core rafter CLI secret-pattern logic so the extension works
 * without requiring the CLI to be installed.
 *
 * This module is VS Code-free so it can be unit tested without the vscode module.
 */

export interface SecretPattern {
  name: string;
  regex: string;
  severity: "low" | "medium" | "high" | "critical";
  description?: string;
}

/**
 * Default secret patterns — mirrors node/src/scanners/secret-patterns.ts
 */
export const SECRET_PATTERNS: SecretPattern[] = [
  { name: "AWS Access Key", regex: "AKIA[0-9A-Z]{16}", severity: "critical" },
  { name: "AWS Secret Key", regex: "(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\\s*[=:]\\s*['\"]?([A-Za-z0-9/+=]{40})", severity: "critical" },
  { name: "GitHub Token", regex: "gh[pousr]_[A-Za-z0-9_]{36,255}", severity: "critical" },
  { name: "GitHub Fine-Grained PAT", regex: "github_pat_[A-Za-z0-9_]{22,255}", severity: "critical" },
  { name: "Generic API Key", regex: "(?:api[_-]?key|apikey)\\s*[=:]\\s*['\"]?([A-Za-z0-9_\\-]{20,})", severity: "high" },
  { name: "Generic Secret", regex: "(?:secret|password|passwd|token)\\s*[=:]\\s*['\"]([^'\"\\s]{8,})['\"]", severity: "high" },
  { name: "Private Key", regex: "-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", severity: "critical" },
  { name: "Slack Token", regex: "xox[bporas]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}", severity: "critical" },
  { name: "Slack Webhook", regex: "https://hooks\\.slack\\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}", severity: "high" },
  { name: "Google API Key", regex: "AIza[0-9A-Za-z\\-_]{35}", severity: "high" },
  { name: "Stripe Secret Key", regex: "sk_live_[0-9a-zA-Z]{24,}", severity: "critical" },
  { name: "Stripe Publishable Key", regex: "pk_live_[0-9a-zA-Z]{24,}", severity: "medium" },
  { name: "Heroku API Key", regex: "(?:heroku.*[=:]\\s*)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", severity: "high" },
  { name: "JWT Token", regex: "eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}", severity: "medium" },
  { name: "NPM Token", regex: "npm_[A-Za-z0-9]{36}", severity: "critical" },
  { name: "PyPI Token", regex: "pypi-[A-Za-z0-9_-]{50,}", severity: "critical" },
];

const GENERIC_PATTERN_NAMES = new Set(["Generic API Key", "Generic Secret"]);
const VARIABLE_NAME_RE = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/;
const LOWERCASE_IDENT_RE = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/;
const QUOTED_VALUE_RE = /['"]([^'"]+)['"]/;

function isFalsePositive(pattern: SecretPattern, matched: string): boolean {
  if (!GENERIC_PATTERN_NAMES.has(pattern.name)) return false;
  const valueMatch = QUOTED_VALUE_RE.exec(matched);
  const value = valueMatch ? valueMatch[1] : matched.split(/[=:]\s*/)[1]?.replace(/['"]/g, "") || matched;
  if (VARIABLE_NAME_RE.test(value) || LOWERCASE_IDENT_RE.test(value)) return true;
  if (/^(true|false|null|none|undefined|placeholder|changeme|example|xxx+|your[_-])/i.test(value)) return true;
  return false;
}

export interface ScanMatch {
  pattern: SecretPattern;
  match: string;
  line: number;
  column: number;
}

export function scanText(text: string): ScanMatch[] {
  const matches: ScanMatch[] = [];
  const lines = text.split("\n");

  for (let lineNum = 0; lineNum < lines.length; lineNum++) {
    const line = lines[lineNum];

    // Skip rafter-ignore comments
    if (lineNum > 0 && /rafter-ignore/.test(lines[lineNum - 1])) continue;

    for (const pattern of SECRET_PATTERNS) {
      const regex = new RegExp(pattern.regex, "g");
      let match;
      while ((match = regex.exec(line)) !== null) {
        if (isFalsePositive(pattern, match[0])) continue;
        matches.push({
          pattern,
          match: match[0],
          line: lineNum,
          column: match.index,
        });
      }
    }
  }

  return matches;
}

export type ScanSeverity = "low" | "medium" | "high" | "critical";
