"""Patterns the prompt-shield hook adds on top of DEFAULT_SECRET_PATTERNS.

These are additive and intentionally NOT applied by the file scanner
(different false-positive tradeoffs). They target the kind of credentials
that show up in natural-language prompts — assignment forms, URL credentials,
and "password is X" phrasing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PromptShieldPattern:
    name: str
    env_base_name: str
    regex: re.Pattern[str]
    value_group: int
    severity: str  # "low" | "medium" | "high" | "critical"


# Identifiers whose name (lowercased) contains one of these substrings count
# as credentials for the inline-assignment pattern.
CREDENTIAL_KEYWORD_RE = re.compile(
    r"(password|passwd|pwd|secret|apikey|access[\s_-]?key|authtoken|token|credential)",
    re.IGNORECASE,
)

PROMPT_SHIELD_PATTERNS: list[PromptShieldPattern] = [
    PromptShieldPattern(
        name="Inline credential assignment",
        env_base_name="RAFTER_SECRET",
        # LHS identifier on the left of = or :, gated on credential keyword in JS.
        regex=re.compile(
            r"(?<![A-Za-z0-9])([A-Za-z][A-Za-z0-9_]{0,63})[ \t]*[:=][ \t]*[\"'`]?([^\s\"'`,;]{6,256})[\"'`]?"
        ),
        value_group=2,
        severity="high",
    ),
    PromptShieldPattern(
        name="Inline credential phrase",
        env_base_name="RAFTER_SECRET",
        regex=re.compile(
            r"(?<![A-Za-z0-9])(?:password|passwd|pwd|pass|credential|api[\s_-]?key|token|secret)\s+(?:is|=|:)\s+[\"'`]?([^\s\"'`.,;]{6,256})[\"'`]?",
            re.IGNORECASE,
        ),
        value_group=1,
        severity="high",
    ),
    PromptShieldPattern(
        name="URL with credentials",
        env_base_name="URL_PASSWORD",
        regex=re.compile(
            r"\b[a-z][a-z0-9+\-.]{1,32}://[^\s:@/]+:([^\s@/'\"`]{4,256})@[^\s'\"`]+",
            re.IGNORECASE,
        ),
        value_group=1,
        severity="critical",
    ),
]


DEFAULT_PATTERN_ENV_NAMES: dict[str, str] = {
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
}
