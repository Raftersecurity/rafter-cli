import { Pattern } from "../core/pattern-engine.js";

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
    description: "AWS Access Key ID detected"
  },
  {
    name: "AWS Secret Access Key",
    regex: "(?i)aws(.{0,20})?['\"][0-9a-zA-Z\\/+]{40}['\"]",
    severity: "critical",
    description: "AWS Secret Access Key detected"
  },

  // GitHub
  {
    name: "GitHub Personal Access Token",
    regex: "ghp_[0-9a-zA-Z]{36}",
    severity: "critical",
    description: "GitHub Personal Access Token detected"
  },
  {
    name: "GitHub OAuth Token",
    regex: "gho_[0-9a-zA-Z]{36}",
    severity: "critical",
    description: "GitHub OAuth Token detected"
  },
  {
    name: "GitHub App Token",
    regex: "(ghu|ghs)_[0-9a-zA-Z]{36}",
    severity: "critical",
    description: "GitHub App Token detected"
  },
  {
    name: "GitHub Refresh Token",
    regex: "ghr_[0-9a-zA-Z]{76}",
    severity: "critical",
    description: "GitHub Refresh Token detected"
  },

  // Google
  {
    name: "Google API Key",
    regex: "AIza[0-9A-Za-z\\-_]{35}",
    severity: "critical",
    description: "Google API Key detected"
  },
  {
    name: "Google OAuth",
    regex: "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    severity: "critical",
    description: "Google OAuth Client ID detected"
  },

  // Slack
  {
    name: "Slack Token",
    regex: "xox[baprs]-([0-9a-zA-Z]{10,48})",
    severity: "critical",
    description: "Slack Token detected"
  },
  {
    name: "Slack Webhook",
    regex: "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    severity: "high",
    description: "Slack Webhook URL detected"
  },

  // Stripe
  {
    name: "Stripe API Key",
    regex: "(?i)sk_live_[0-9a-zA-Z]{24}",
    severity: "critical",
    description: "Stripe Live API Key detected"
  },
  {
    name: "Stripe Restricted API Key",
    regex: "(?i)rk_live_[0-9a-zA-Z]{24}",
    severity: "critical",
    description: "Stripe Restricted API Key detected"
  },

  // Twilio
  {
    name: "Twilio API Key",
    regex: "SK[0-9a-fA-F]{32}",
    severity: "critical",
    description: "Twilio API Key detected"
  },

  // Generic patterns
  {
    name: "Generic API Key",
    regex: "(?i)(api[_-]?key|apikey)[\\s]*[:=][\\s]*['\"]?[0-9a-zA-Z\\-_]{16,}['\"]?",
    severity: "high",
    description: "Generic API key pattern detected"
  },
  {
    name: "Generic Secret",
    regex: "(?i)(secret|password|passwd|pwd)[\\s]*[:=][\\s]*['\"]?[0-9a-zA-Z\\-_!@#$%^&*()]{8,}['\"]?",
    severity: "high",
    description: "Generic secret pattern detected"
  },
  {
    name: "Private Key",
    regex: "-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
    severity: "critical",
    description: "Private key detected"
  },
  {
    name: "Bearer Token",
    regex: "(?i)bearer[\\s]+[a-zA-Z0-9\\-_\\.=]+",
    severity: "high",
    description: "Bearer token detected"
  },

  // Database connection strings
  {
    name: "Database Connection String",
    regex: "(?i)(postgres|mysql|mongodb)://[^\\s]+:[^\\s]+@[^\\s]+",
    severity: "critical",
    description: "Database connection string with credentials detected"
  },

  // JWT
  {
    name: "JSON Web Token",
    regex: "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}",
    severity: "high",
    description: "JWT token detected"
  },

  // npm token
  {
    name: "npm Access Token",
    regex: "npm_[A-Za-z0-9]{36}",
    severity: "critical",
    description: "npm access token detected"
  },

  // PyPI token
  {
    name: "PyPI Token",
    regex: "pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\\-_]{50,}",
    severity: "critical",
    description: "PyPI API token detected"
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
