/**
 * Patterns the prompt-shield hook adds on top of DEFAULT_SECRET_PATTERNS.
 *
 * These are additive and intentionally NOT applied by the file scanner
 * (which has different false-positive tradeoffs). They target the kind of
 * credentials that show up in natural-language prompts — assignment forms,
 * URL credentials, and "password is X" phrasing.
 *
 * Each pattern declares which capture group holds the actual secret VALUE
 * (vs. the surrounding context like the keyword "password=" or URL prefix).
 * The value is what gets persisted to .env; the full match is what gets
 * redacted in audit logs.
 *
 * Min length 6 on the value bounds the obvious false-positive floor without
 * dropping common real passwords.
 */

export interface PromptShieldPattern {
  name: string;
  /** Stable env var basename — the persisted key derives from this. */
  envBaseName: string;
  regex: RegExp;
  /** Which capture group holds the secret value to persist. */
  valueGroup: number;
  severity: "low" | "medium" | "high" | "critical";
}

/**
 * Identifiers whose name (lowercased, underscores collapsed) contains one of
 * these substrings count as credentials for the inline-assignment pattern.
 */
export const CREDENTIAL_KEYWORD_RE = /(password|passwd|pwd|secret|apikey|access[\s_-]?key|authtoken|token|credential)/i;

export const PROMPT_SHIELD_PATTERNS: PromptShieldPattern[] = [
  {
    name: "Inline credential assignment",
    envBaseName: "RAFTER_SECRET",
    // Matches an identifier on the LHS of = or : whose name contains a
    // credential keyword (e.g. DB_PASSWORD, api_key, AUTH_TOKEN). We capture
    // the whole identifier so DB_PASSWORD lands in .env as DB_PASSWORD,
    // not just PASSWORD. The keyword check is done in JS (see
    // CREDENTIAL_KEYWORD_RE) to keep the regex simple.
    regex: /(?<![A-Za-z0-9])([A-Za-z][A-Za-z0-9_]{0,63})[ \t]*[:=][ \t]*["'`]?([^\s"'`,;]{6,256})["'`]?/g,
    valueGroup: 2,
    severity: "high",
  },
  {
    name: "Inline credential phrase",
    envBaseName: "RAFTER_SECRET",
    // Matches: "password is hunter2", "the api key is xyz", "use credential foo"
    regex: /(?<![A-Za-z0-9])(?:password|passwd|pwd|pass|credential|api[\s_-]?key|token|secret)\s+(?:is|=|:)\s+["'`]?([^\s"'`.,;]{6,256})["'`]?/gi,
    valueGroup: 1,
    severity: "high",
  },
  {
    name: "URL with credentials",
    envBaseName: "URL_PASSWORD",
    // Matches scheme://user:password@host — captures the password segment.
    regex: /\b[a-z][a-z0-9+\-.]{1,32}:\/\/[^\s:@/]+:([^\s@/'"`]{4,256})@[^\s'"`]+/gi,
    valueGroup: 1,
    severity: "critical",
  },
];

/**
 * Map a known DEFAULT_SECRET_PATTERNS pattern name to a stable env var basename.
 * Used when a built-in scanner pattern fires on a prompt — we want
 * "Stripe API Key" to land in .env as STRIPE_API_KEY, not RAFTER_SECRET_3.
 */
export const DEFAULT_PATTERN_ENV_NAMES: Record<string, string> = {
  "AWS Access Key ID": "AWS_ACCESS_KEY_ID",
  "AWS Secret Access Key": "AWS_SECRET_ACCESS_KEY",
  "GitHub Personal Access Token": "GITHUB_TOKEN",
  "GitHub OAuth Token": "GITHUB_OAUTH_TOKEN",
  "GitHub App Token": "GITHUB_APP_TOKEN",
  "GitHub Refresh Token": "GITHUB_REFRESH_TOKEN",
  "Google API Key": "GOOGLE_API_KEY",
  "Google OAuth": "GOOGLE_OAUTH_CLIENT_ID",
  "Slack Token": "SLACK_TOKEN",
  "Slack Webhook": "SLACK_WEBHOOK_URL",
  "Stripe API Key": "STRIPE_LIVE_KEY",
  "Stripe Restricted API Key": "STRIPE_RESTRICTED_KEY",
  "Twilio API Key": "TWILIO_API_KEY",
  "Generic API Key": "API_KEY",
  "Generic Secret": "SECRET",
  "Private Key": "PRIVATE_KEY",
  "Bearer Token": "BEARER_TOKEN",
  "Database Connection String": "DATABASE_URL",
  "JSON Web Token": "JWT",
  "npm Access Token": "NPM_TOKEN",
  "PyPI Token": "PYPI_TOKEN",
};
