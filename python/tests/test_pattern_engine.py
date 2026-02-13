"""Tests for pattern engine and all 21 secret patterns."""
from rafter_cli.core.pattern_engine import PatternEngine
from rafter_cli.scanners.secret_patterns import DEFAULT_SECRET_PATTERNS


def _engine():
    return PatternEngine(DEFAULT_SECRET_PATTERNS)


# -- AWS ------------------------------------------------------------------

def test_aws_access_key_id():
    matches = _engine().scan("AKIAIOSFODNN7EXAMPLE")
    assert any(m.pattern.name == "AWS Access Key ID" for m in matches)


def test_aws_secret_access_key():
    matches = _engine().scan("aws_secret='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'")
    assert any(m.pattern.name == "AWS Secret Access Key" for m in matches)


# -- GitHub ---------------------------------------------------------------

def test_github_pat():
    matches = _engine().scan("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
    assert any(m.pattern.name == "GitHub Personal Access Token" for m in matches)


def test_github_oauth():
    matches = _engine().scan("gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
    assert any(m.pattern.name == "GitHub OAuth Token" for m in matches)


def test_github_app_token():
    matches = _engine().scan("ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
    assert any(m.pattern.name == "GitHub App Token" for m in matches)


def test_github_refresh_token():
    token = "ghr_" + "A" * 76
    matches = _engine().scan(token)
    assert any(m.pattern.name == "GitHub Refresh Token" for m in matches)


# -- Google ---------------------------------------------------------------

def test_google_api_key():
    matches = _engine().scan("AIzaSyA-1234567890abcdefghijklmnopqrstuv")
    assert any(m.pattern.name == "Google API Key" for m in matches)


def test_google_oauth():
    matches = _engine().scan("123456789-abcdefghijklmnopqrstuvwxyz123456.apps.googleusercontent.com")
    assert any(m.pattern.name == "Google OAuth" for m in matches)


# -- Slack ----------------------------------------------------------------

def test_slack_token():
    matches = _engine().scan("xoxb-1234567890-abcdefghij")
    assert any(m.pattern.name == "Slack Token" for m in matches)


def test_slack_webhook():
    matches = _engine().scan("https://hooks.slack" + ".com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx")
    assert any(m.pattern.name == "Slack Webhook" for m in matches)


# -- Stripe ---------------------------------------------------------------

def test_stripe_api_key():
    matches = _engine().scan("sk_" + "live_abcdefghijklmnopqrstuvwx")
    assert any(m.pattern.name == "Stripe API Key" for m in matches)


def test_stripe_restricted_key():
    matches = _engine().scan("rk_" + "live_abcdefghijklmnopqrstuvwx")
    assert any(m.pattern.name == "Stripe Restricted API Key" for m in matches)


# -- Twilio ---------------------------------------------------------------

def test_twilio_api_key():
    matches = _engine().scan("SK" + "a1" * 16)
    assert any(m.pattern.name == "Twilio API Key" for m in matches)


# -- Generic --------------------------------------------------------------

def test_generic_api_key():
    matches = _engine().scan("api_key=abcdefghijklmnopqrstuv")
    assert any(m.pattern.name == "Generic API Key" for m in matches)


def test_generic_secret():
    matches = _engine().scan("password=MyS3cretP@ss!")
    assert any(m.pattern.name == "Generic Secret" for m in matches)


def test_private_key():
    matches = _engine().scan("-----BEGIN RSA PRIVATE KEY-----")
    assert any(m.pattern.name == "Private Key" for m in matches)


def test_bearer_token():
    matches = _engine().scan("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9")
    assert any(m.pattern.name == "Bearer Token" for m in matches)


# -- Database -------------------------------------------------------------

def test_database_connection_string():
    matches = _engine().scan("postgres://user:password@host:5432/db")
    assert any(m.pattern.name == "Database Connection String" for m in matches)


# -- JWT ------------------------------------------------------------------

def test_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    matches = _engine().scan(jwt)
    assert any(m.pattern.name == "JSON Web Token" for m in matches)


# -- npm ------------------------------------------------------------------

def test_npm_token():
    matches = _engine().scan("npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
    assert any(m.pattern.name == "npm Access Token" for m in matches)


# -- PyPI -----------------------------------------------------------------

def test_pypi_token():
    token = "pypi-AgEIcHlwaS5vcmc" + "A" * 50
    matches = _engine().scan(token)
    assert any(m.pattern.name == "PyPI Token" for m in matches)


# -- Engine features ------------------------------------------------------

def test_no_false_positive_on_clean_text():
    matches = _engine().scan("This is a normal sentence with no secrets.")
    assert len(matches) == 0


def test_redact():
    engine = _engine()
    text = engine.redact_text("My key is ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
    assert "ghp_" in text
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" not in text


def test_scan_with_position():
    matches = _engine().scan_with_position("line1\nghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\nline3")
    found = [m for m in matches if m.pattern.name == "GitHub Personal Access Token"]
    assert len(found) == 1
    assert found[0].line == 2


def test_all_21_patterns_present():
    assert len(DEFAULT_SECRET_PATTERNS) == 21
