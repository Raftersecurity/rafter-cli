"""Default secret detection patterns — verbatim port of Node.js patterns."""
from __future__ import annotations

from ..core.pattern_engine import Pattern

DEFAULT_SECRET_PATTERNS: list[Pattern] = [
    # AWS
    Pattern(
        name="AWS Access Key ID",
        regex=r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        severity="critical",
        description="AWS Access Key ID detected",
    ),
    Pattern(
        name="AWS Secret Access Key",
        regex=r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
        severity="critical",
        description="AWS Secret Access Key detected",
    ),
    # GitHub
    Pattern(
        name="GitHub Personal Access Token",
        regex=r"ghp_[0-9a-zA-Z]{36}",
        severity="critical",
        description="GitHub Personal Access Token detected",
    ),
    Pattern(
        name="GitHub OAuth Token",
        regex=r"gho_[0-9a-zA-Z]{36}",
        severity="critical",
        description="GitHub OAuth Token detected",
    ),
    Pattern(
        name="GitHub App Token",
        regex=r"(ghu|ghs)_[0-9a-zA-Z]{36}",
        severity="critical",
        description="GitHub App Token detected",
    ),
    Pattern(
        name="GitHub Refresh Token",
        regex=r"ghr_[0-9a-zA-Z]{76}",
        severity="critical",
        description="GitHub Refresh Token detected",
    ),
    # Google
    Pattern(
        name="Google API Key",
        regex=r"AIza[0-9A-Za-z\-_]{35}",
        severity="critical",
        description="Google API Key detected",
    ),
    Pattern(
        name="Google OAuth",
        regex=r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        severity="critical",
        description="Google OAuth Client ID detected",
    ),
    # Slack
    Pattern(
        name="Slack Token",
        regex=r"xox[baprs]-([0-9a-zA-Z]{10,48})",
        severity="critical",
        description="Slack Token detected",
    ),
    Pattern(
        name="Slack Webhook",
        regex=r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
        severity="high",
        description="Slack Webhook URL detected",
    ),
    # Stripe
    Pattern(
        name="Stripe API Key",
        regex=r"(?i)sk_live_[0-9a-zA-Z]{24}",
        severity="critical",
        description="Stripe Live API Key detected",
    ),
    Pattern(
        name="Stripe Restricted API Key",
        regex=r"(?i)rk_live_[0-9a-zA-Z]{24}",
        severity="critical",
        description="Stripe Restricted API Key detected",
    ),
    # Twilio
    Pattern(
        name="Twilio API Key",
        regex=r"SK[0-9a-fA-F]{32}",
        severity="critical",
        description="Twilio API Key detected",
    ),
    # Generic
    Pattern(
        name="Generic API Key",
        regex=r"(?i)(api[_\-]?key|apikey)\s*[:=]\s*['\"]?[0-9a-zA-Z\-_]{16,256}['\"]?",
        severity="high",
        description="Generic API key pattern detected",
    ),
    Pattern(
        name="Generic Secret",
        regex=r"(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"]?[0-9a-zA-Z\-_!@#$%^&*()]{8,256}['\"]?",
        severity="high",
        description="Generic secret pattern detected",
    ),
    Pattern(
        name="Private Key",
        regex=r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        severity="critical",
        description="Private key detected",
    ),
    Pattern(
        name="Bearer Token",
        regex=r"(?i)bearer\s+[a-zA-Z0-9\-_\.=]+",
        severity="high",
        description="Bearer token detected",
    ),
    # Database
    Pattern(
        name="Database Connection String",
        regex=r"(?i)(postgres|mysql|mongodb)://[^\s]+:[^\s]+@[^\s]+",
        severity="critical",
        description="Database connection string with credentials detected",
    ),
    # JWT
    Pattern(
        name="JSON Web Token",
        regex=r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        severity="high",
        description="JWT token detected",
    ),
    # npm
    Pattern(
        name="npm Access Token",
        regex=r"npm_[A-Za-z0-9]{36}",
        severity="critical",
        description="npm access token detected",
    ),
    # PyPI
    Pattern(
        name="PyPI Token",
        regex=r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}",
        severity="critical",
        description="PyPI API token detected",
    ),
]


def get_patterns_by_severity(severity: str) -> list[Pattern]:
    return [p for p in DEFAULT_SECRET_PATTERNS if p.severity == severity]


def get_critical_patterns() -> list[Pattern]:
    return get_patterns_by_severity("critical")
