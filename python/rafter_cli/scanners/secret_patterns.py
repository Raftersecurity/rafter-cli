"""Default secret detection patterns — verbatim port of Node.js patterns."""
from __future__ import annotations

from ..core.pattern_engine import Pattern

REM_CLOUD = (
    "Rotate the credential in the provider's console immediately. Reference via "
    "env var or a secret manager. Even after removing this from your working tree, "
    "git history still contains the secret — rotation is mandatory."
)
REM_API_KEY = (
    "Revoke the key in the provider's dashboard, generate a new one, and reference "
    "via env var or secret manager. Git history retains the secret — rotation is mandatory."
)
REM_PRIVATE_KEY = (
    "Generate a new keypair, deploy the new public key, and revoke the old one. "
    "Never commit private keys; use ssh-agent or a KMS for storage."
)
REM_DB = (
    "Rotate database credentials immediately. Reference via env var (e.g. DATABASE_URL) "
    "or a secret manager. Audit access logs for unauthorized use."
)
REM_JWT = (
    "If real, rotate the JWT signing key — every token signed with the old key is now "
    "untrusted. If example/test data, move to a fixture not committed to git."
)
REM_BEARER = (
    "Revoke the token at the issuer; rotate. Reference via env var or short-lived "
    "credential exchange (OIDC)."
)
REM_GENERIC = (
    "Treat as a real credential: rotate at the issuer, move to env var or secret manager, "
    "and audit recent commits for related leaks."
)
REM_WEBHOOK = (
    "Regenerate the webhook URL in the provider's admin panel. Treat webhook URLs as "
    "credentials and reference via env var."
)


DEFAULT_SECRET_PATTERNS: list[Pattern] = [
    # AWS
    Pattern(
        name="AWS Access Key ID",
        regex=r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        severity="critical",
        confidence="high",
        description="AWS Access Key ID detected",
        remediation=REM_CLOUD,
    ),
    Pattern(
        name="AWS Secret Access Key",
        regex=r"(?i)aws(.{0,20})?['\"]?[0-9a-zA-Z/+]{40}['\"]?",
        severity="critical",
        confidence="medium",
        description="AWS Secret Access Key detected",
        remediation=REM_CLOUD,
    ),
    # GitHub
    Pattern(
        name="GitHub Personal Access Token",
        regex=r"ghp_[0-9a-zA-Z]{36}",
        severity="critical",
        confidence="high",
        description="GitHub Personal Access Token detected",
        remediation=REM_API_KEY,
    ),
    Pattern(
        name="GitHub OAuth Token",
        regex=r"gho_[0-9a-zA-Z]{36}",
        severity="critical",
        confidence="high",
        description="GitHub OAuth Token detected",
        remediation=REM_API_KEY,
    ),
    Pattern(
        name="GitHub App Token",
        regex=r"(ghu|ghs)_[0-9a-zA-Z]{36}",
        severity="critical",
        confidence="high",
        description="GitHub App Token detected",
        remediation=REM_API_KEY,
    ),
    Pattern(
        name="GitHub Refresh Token",
        regex=r"ghr_[0-9a-zA-Z]{76}",
        severity="critical",
        confidence="high",
        description="GitHub Refresh Token detected",
        remediation=REM_API_KEY,
    ),
    # Google
    Pattern(
        name="Google API Key",
        regex=r"AIza[0-9A-Za-z\-_]{35}",
        severity="critical",
        confidence="high",
        description="Google API Key detected",
        remediation=REM_API_KEY,
    ),
    Pattern(
        name="Google OAuth",
        regex=r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        severity="critical",
        confidence="high",
        description="Google OAuth Client ID detected",
        remediation=REM_API_KEY,
    ),
    # Slack
    Pattern(
        name="Slack Token",
        regex=r"xox[baprs]-([0-9a-zA-Z]{10,48})",
        severity="critical",
        confidence="high",
        description="Slack Token detected",
        remediation=REM_API_KEY,
    ),
    Pattern(
        name="Slack Webhook",
        regex=r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
        severity="high",
        confidence="high",
        description="Slack Webhook URL detected",
        remediation=REM_WEBHOOK,
    ),
    # Stripe
    Pattern(
        name="Stripe API Key",
        regex=r"(?i)sk_live_[0-9a-zA-Z]{24}",
        severity="critical",
        confidence="high",
        description="Stripe Live API Key detected",
        remediation=REM_API_KEY,
    ),
    Pattern(
        name="Stripe Restricted API Key",
        regex=r"(?i)rk_live_[0-9a-zA-Z]{24}",
        severity="critical",
        confidence="high",
        description="Stripe Restricted API Key detected",
        remediation=REM_API_KEY,
    ),
    # Twilio
    Pattern(
        name="Twilio API Key",
        regex=r"SK[0-9a-fA-F]{32}",
        severity="critical",
        confidence="high",
        description="Twilio API Key detected",
        remediation=REM_API_KEY,
    ),
    # Generic
    Pattern(
        name="Generic API Key",
        regex=r"(?i)(?<![a-zA-Z0-9_])(api[_\-]?key|apikey)\s*[:=]\s*['\"](?=[0-9a-zA-Z\-_]*[0-9])[0-9a-zA-Z\-_]{16,256}['\"]",
        severity="high",
        confidence="medium",
        description="Generic API key pattern detected",
        remediation=REM_GENERIC,
        min_entropy=3.5,
    ),
    Pattern(
        name="Generic Secret",
        regex=r"(?i)(?<![a-zA-Z0-9_])(secret|password|passwd|pwd)\s*[:=]\s*['\"](?=[^\s'\"]*[0-9])(?=[^\s'\"]*[a-zA-Z])[0-9a-zA-Z\-_!@#$%^&*()]{12,256}['\"]",
        severity="high",
        confidence="low",
        description="Generic secret pattern detected",
        remediation=REM_GENERIC,
        min_entropy=3.5,
    ),
    Pattern(
        name="Private Key",
        regex=r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        severity="critical",
        confidence="high",
        description="Private key detected",
        remediation=REM_PRIVATE_KEY,
    ),
    Pattern(
        name="Bearer Token",
        regex=r"(?i)bearer\s+(?=[a-zA-Z0-9\-_\.=]*[0-9])(?=[a-zA-Z0-9\-_\.=]*[a-zA-Z])[a-zA-Z0-9\-_\.=]{20,512}",
        severity="high",
        confidence="low",
        description="Bearer token detected",
        remediation=REM_BEARER,
        min_entropy=3.5,
    ),
    # Database
    Pattern(
        name="Database Connection String",
        regex=r"(?i)(postgres|mysql|mongodb)://[^\s:@]+:[^\s@]+@[^\s]+",
        severity="critical",
        confidence="high",
        description="Database connection string with credentials detected",
        remediation=REM_DB,
    ),
    # JWT
    Pattern(
        name="JSON Web Token",
        regex=r"eyJ[A-Za-z0-9_-]{10,2048}\.[A-Za-z0-9_-]{10,2048}\.[A-Za-z0-9_-]{10,2048}",
        severity="high",
        confidence="medium",
        description="JWT token detected",
        remediation=REM_JWT,
    ),
    # npm
    Pattern(
        name="npm Access Token",
        regex=r"npm_[A-Za-z0-9]{36}",
        severity="critical",
        confidence="high",
        description="npm access token detected",
        remediation=REM_API_KEY,
    ),
    # PyPI
    Pattern(
        name="PyPI Token",
        regex=r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1024}",
        severity="critical",
        confidence="high",
        description="PyPI API token detected",
        remediation=REM_API_KEY,
    ),
]


def get_patterns_by_severity(severity: str) -> list[Pattern]:
    return [p for p in DEFAULT_SECRET_PATTERNS if p.severity == severity]


def get_critical_patterns() -> list[Pattern]:
    return get_patterns_by_severity("critical")
