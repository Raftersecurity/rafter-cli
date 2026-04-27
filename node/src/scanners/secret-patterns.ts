import { Pattern } from "../core/pattern-engine.js";

const REM_CLOUD =
  "Rotate the credential in the provider's console immediately. Reference via env var or a secret manager. Even after removing this from your working tree, git history still contains the secret — rotation is mandatory.";
const REM_API_KEY =
  "Revoke the key in the provider's dashboard, generate a new one, and reference via env var or secret manager. Git history retains the secret — rotation is mandatory.";
const REM_PRIVATE_KEY =
  "Generate a new keypair, deploy the new public key, and revoke the old one. Never commit private keys; use ssh-agent or a KMS for storage.";
const REM_DB =
  "Rotate database credentials immediately. Reference via env var (e.g. DATABASE_URL) or a secret manager. Audit access logs for unauthorized use.";
const REM_JWT =
  "If real, rotate the JWT signing key — every token signed with the old key is now untrusted. If example/test data, move to a fixture not committed to git.";
const REM_BEARER =
  "Revoke the token at the issuer; rotate. Reference via env var or short-lived credential exchange (OIDC).";
const REM_GENERIC =
  "Treat as a real credential: rotate at the issuer, move to env var or secret manager, and audit recent commits for related leaks.";
const REM_WEBHOOK =
  "Regenerate the webhook URL in the provider's admin panel. Treat webhook URLs as credentials and reference via env var.";

/**
 * Default secret detection patterns
 * Based on common secret formats and Gitleaks rules
 */
export const DEFAULT_SECRET_PATTERNS: Pattern[] = [
  // AWS
  {
    name: "AWS Access Key ID",
    regex: "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    severity: "critical",
    confidence: "high",
    description: "AWS Access Key ID detected",
    remediation: REM_CLOUD,
  },
  {
    name: "AWS Secret Access Key",
    regex: "(?i)aws(.{0,20})?['\"]?[0-9a-zA-Z/+]{40}['\"]?",
    severity: "critical",
    confidence: "medium",
    description: "AWS Secret Access Key detected",
    remediation: REM_CLOUD,
  },

  // GitHub
  {
    name: "GitHub Personal Access Token",
    regex: "ghp_[0-9a-zA-Z]{36}",
    severity: "critical",
    confidence: "high",
    description: "GitHub Personal Access Token detected",
    remediation: REM_API_KEY,
  },
  {
    name: "GitHub OAuth Token",
    regex: "gho_[0-9a-zA-Z]{36}",
    severity: "critical",
    confidence: "high",
    description: "GitHub OAuth Token detected",
    remediation: REM_API_KEY,
  },
  {
    name: "GitHub App Token",
    regex: "(ghu|ghs)_[0-9a-zA-Z]{36}",
    severity: "critical",
    confidence: "high",
    description: "GitHub App Token detected",
    remediation: REM_API_KEY,
  },
  {
    name: "GitHub Refresh Token",
    regex: "ghr_[0-9a-zA-Z]{76}",
    severity: "critical",
    confidence: "high",
    description: "GitHub Refresh Token detected",
    remediation: REM_API_KEY,
  },

  // Google
  {
    name: "Google API Key",
    regex: "AIza[0-9A-Za-z\\-_]{35}",
    severity: "critical",
    confidence: "high",
    description: "Google API Key detected",
    remediation: REM_API_KEY,
  },
  {
    name: "Google OAuth",
    regex: "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    severity: "critical",
    confidence: "high",
    description: "Google OAuth Client ID detected",
    remediation: REM_API_KEY,
  },

  // Slack
  {
    name: "Slack Token",
    regex: "xox[baprs]-([0-9a-zA-Z]{10,48})",
    severity: "critical",
    confidence: "high",
    description: "Slack Token detected",
    remediation: REM_API_KEY,
  },
  {
    name: "Slack Webhook",
    regex: "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    severity: "high",
    confidence: "high",
    description: "Slack Webhook URL detected",
    remediation: REM_WEBHOOK,
  },

  // Stripe
  {
    name: "Stripe API Key",
    regex: "(?i)sk_live_[0-9a-zA-Z]{24}",
    severity: "critical",
    confidence: "high",
    description: "Stripe Live API Key detected",
    remediation: REM_API_KEY,
  },
  {
    name: "Stripe Restricted API Key",
    regex: "(?i)rk_live_[0-9a-zA-Z]{24}",
    severity: "critical",
    confidence: "high",
    description: "Stripe Restricted API Key detected",
    remediation: REM_API_KEY,
  },

  // Twilio
  {
    name: "Twilio API Key",
    regex: "SK[0-9a-fA-F]{32}",
    severity: "critical",
    confidence: "high",
    description: "Twilio API Key detected",
    remediation: REM_API_KEY,
  },

  // Generic patterns
  {
    name: "Generic API Key",
    regex: "(?i)(?<![a-zA-Z0-9_])(api[_-]?key|apikey)[\\s]*[:=][\\s]*['\"](?=[0-9a-zA-Z\\-_]*[0-9])[0-9a-zA-Z\\-_]{16,256}['\"]",
    severity: "high",
    confidence: "medium",
    description: "Generic API key pattern detected",
    remediation: REM_GENERIC,
    minEntropy: 3.5,
  },
  {
    name: "Generic Secret",
    regex: "(?i)(?<![a-zA-Z0-9_])(secret|password|passwd|pwd)[\\s]*[:=][\\s]*['\"](?=[^\\s'\"]*[0-9])(?=[^\\s'\"]*[a-zA-Z])[0-9a-zA-Z\\-_!@#$%^&*()]{12,256}['\"]",
    severity: "high",
    confidence: "low",
    description: "Generic secret pattern detected",
    remediation: REM_GENERIC,
    minEntropy: 3.5,
  },
  {
    name: "Private Key",
    regex: "-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
    severity: "critical",
    confidence: "high",
    description: "Private key detected",
    remediation: REM_PRIVATE_KEY,
  },
  {
    name: "Bearer Token",
    regex: "(?i)bearer[\\s]+(?=[a-zA-Z0-9\\-_\\.=]*[0-9])(?=[a-zA-Z0-9\\-_\\.=]*[a-zA-Z])[a-zA-Z0-9\\-_\\.=]{20,512}",
    severity: "high",
    confidence: "low",
    description: "Bearer token detected",
    remediation: REM_BEARER,
    minEntropy: 3.5,
  },

  // Database connection strings
  {
    name: "Database Connection String",
    regex: "(?i)(postgres|mysql|mongodb)://[^\\s:@]+:[^\\s@]+@[^\\s]+",
    severity: "critical",
    confidence: "high",
    description: "Database connection string with credentials detected",
    remediation: REM_DB,
  },

  // JWT
  {
    name: "JSON Web Token",
    regex: "eyJ[A-Za-z0-9_-]{10,2048}\\.[A-Za-z0-9_-]{10,2048}\\.[A-Za-z0-9_-]{10,2048}",
    severity: "high",
    confidence: "medium",
    description: "JWT token detected",
    remediation: REM_JWT,
  },

  // npm token
  {
    name: "npm Access Token",
    regex: "npm_[A-Za-z0-9]{36}",
    severity: "critical",
    confidence: "high",
    description: "npm access token detected",
    remediation: REM_API_KEY,
  },

  // PyPI token
  {
    name: "PyPI Token",
    regex: "pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\\-_]{50,1024}",
    severity: "critical",
    confidence: "high",
    description: "PyPI API token detected",
    remediation: REM_API_KEY,
  }
];

/**
 * Get patterns by severity level
 */
export function getPatternsBySeverity(severity: "low" | "medium" | "high" | "critical"): Pattern[] {
  return DEFAULT_SECRET_PATTERNS.filter(p => p.severity === severity);
}

/**
 * Get all critical patterns
 */
export function getCriticalPatterns(): Pattern[] {
  return getPatternsBySeverity("critical");
}
