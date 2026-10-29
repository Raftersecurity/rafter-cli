"""Tests for pattern engine and all 21 secret patterns."""
import pytest

from rafter_cli.core.pattern_engine import PatternEngine
from rafter_cli.scanners.secret_patterns import DEFAULT_SECRET_PATTERNS

# A fake AWS key ID, assembled at runtime so the file holds no key-shaped literal.
FAKE_AWS_KEY_ID = "AKIA" + "IOSFODNN7ABCDEFG"
FAKE_AWS_KEY_ID_2 = "AKIA" + "QWERTYUIOPASDFGH"
FAKE_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYABCDEFGHIJ"


def _engine():
    return PatternEngine(DEFAULT_SECRET_PATTERNS)


# -- AWS ------------------------------------------------------------------

def test_aws_access_key_id():
    matches = _engine().scan(FAKE_AWS_KEY_ID)
    assert any(m.pattern.name == "AWS Access Key ID" for m in matches)


# #230: betterleaks skips the canonical AWS-docs example access key (it
# ends in EXAMPLE); the built-in regex engine disagreed and flagged it. Copy
# betterleaks' exemption so a Write containing the AWS docs sample isn't denied.
def test_aws_access_key_id_ignores_docs_example():
    matches = _engine().scan("AKIAIOSFODNN7EXAMPLE")
    assert not any(m.pattern.name == "AWS Access Key ID" for m in matches)


def test_aws_access_key_id_detects_plausible_non_example_key():
    matches = _engine().scan(FAKE_AWS_KEY_ID_2)
    assert any(m.pattern.name == "AWS Access Key ID" for m in matches)


def test_aws_secret_access_key():
    matches = _engine().scan(f"aws_secret='{FAKE_AWS_SECRET}'")
    assert any(m.pattern.name == "AWS Secret Access Key" for m in matches)


# #230: betterleaks skips the canonical AWS-docs example secret access
# key (it ends in EXAMPLEKEY); the built-in regex engine disagreed and
# flagged it. Copy betterleaks' exemption so a Write containing the AWS docs
# sample isn't denied.
def test_aws_secret_access_key_ignores_docs_example():
    matches = _engine().scan("aws_secret='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'")
    assert not any(m.pattern.name == "AWS Secret Access Key" for m in matches)


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


# -- Generic ---------------------------------------------------------------

@pytest.mark.parametrize("text", [
    'api_key="a1b2c3d4e5f6g7h8i9j0"',
    'api_key = "a1b2c3d4e5f6g7h8"',  # standalone api_key, quoted value (rc-0as)
    'api_key = "aB3xY9kL2mN5pQ8r"',  # real key, mixed case (rc-1qd)
])
def test_generic_api_key_matches(text):
    matches = _engine().scan(text)
    assert any(m.pattern.name == "Generic API Key" for m in matches)


@pytest.mark.parametrize("text", [
    "password='MyS3cretP@ss!'",
    'password = "Sup3rS3cr3t!"',  # standalone password, quoted value (rc-0as)
    'password = "P@ssw0rd!XyZ"',  # real secret with special chars (rc-1qd)
])
def test_generic_secret_matches(text):
    matches = _engine().scan(text)
    assert any(m.pattern.name == "Generic Secret" for m in matches)


# -- False positive guards ---------------------------------------------------
# rc-0as: compound variable names and unquoted values.
# rc-uos: env-var names / identifiers as the value.
# rc-1qd: variable names containing digits.

@pytest.mark.parametrize("text", [
    'anthropic_api_key = "sk-ant-something"',  # rc-0as compound var name
    "api_key = some_variable_name",            # rc-0as unquoted value
    "api_key = 'ANTHROPIC_API_KEY'",           # rc-uos env var name as value
    "api_key: 'GOOGLE_PLACES_API_KEY'",        # rc-uos colon form
    'api_key = "abcdefghijklmnopqrstuv"',      # rc-uos all letters, no entropy
    "api_key = 'OPENAI_API_KEY_V2'",           # rc-1qd env var name with digit
    "api_key = 'my_app_api_key_v2'",           # rc-1qd lowercase identifier
])
def test_generic_api_key_no_false_positive(text):
    matches = _engine().scan(text)
    assert not any(m.pattern.name == "Generic API Key" for m in matches)


@pytest.mark.parametrize("text", [
    "settings.user_password = get_password()",  # rc-0as compound var name
    'app_secret = "not-a-real-secret"',         # rc-0as compound var name
    "password = 'DATABASE_PASSWORD'",           # rc-uos env var name as value
    "secret = 'my_app_secret_key'",             # rc-uos identifier as value
    "password = 'DATABASE_PASSWORD_1'",         # rc-1qd env var name with digit
    "secret = 'app_secret_token_1'",            # rc-1qd lowercase identifier
])
def test_generic_secret_no_false_positive(text):
    matches = _engine().scan(text)
    assert not any(m.pattern.name == "Generic Secret" for m in matches)


def test_no_false_positive_redact_preserves_var_names():
    """redact_text should not redact variable name values."""
    engine = _engine()
    text = "api_key = 'OPENAI_API_KEY_V2'"
    assert engine.redact_text(text) == text


def test_has_matches_excludes_var_names():
    """has_matches should return False for variable name values."""
    engine = _engine()
    assert not engine.has_matches("api_key = 'OPENAI_API_KEY_V2'")


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


def test_all_patterns_present():
    # Floor assertion, not an exact count: the pattern list only grows, so a
    # hardcoded `== N` goes stale every time a pattern is added (sable-6d6 —
    # was 21, broke when the HashiCorp Vault token brought it to 22).
    assert len(DEFAULT_SECRET_PATTERNS) >= 22
    names = [p.name for p in DEFAULT_SECRET_PATTERNS]
    assert len(names) == len(set(names)), "pattern names must be unique"


# -- Env-assignment redaction (ob-y5ep) --------------------------------------
# A value whose NAME looks secret-bearing must be masked even when the value
# matches no known secret pattern (e.g. a bespoke RAFTER_API_KEY).

def test_env_redaction_masks_rafter_api_key_value():
    out = _engine().redact_text("RAFTER_API_KEY=sk-deadbeefdeadbeef rafter scan .")
    assert "sk-deadbeefdeadbeef" not in out
    assert "RAFTER_API_KEY=" in out
    assert "rafter scan ." in out


def test_env_redaction_masks_common_secret_named_vars():
    for name in ("API_KEY", "GITHUB_TOKEN", "DB_PASSWORD", "AWS_SECRET", "AUTH", "PASSWD"):
        out = _engine().redact_text(f"{name}=supersecretvalue123 next")
        assert "supersecretvalue123" not in out, name


def test_env_redaction_preserves_benign_assignments():
    engine = _engine()
    assert engine.redact_text("FOO=bar") == "FOO=bar"
    assert engine.redact_text("NODE_ENV=production") == "NODE_ENV=production"
    assert engine.redact_text("PATH=/usr/bin rafter scan .") == "PATH=/usr/bin rafter scan ."


def test_env_redaction_only_touches_secret_assignment_in_mixed_command():
    out = _engine().redact_text("FOO=bar SECRET_TOKEN=abcdef1234567890 rafter")
    assert "FOO=bar" in out
    assert "abcdef1234567890" not in out


# sable-fqrr: `agent exec` shell-quotes a token containing special characters,
# so the logged command has a quote right before NAME=. The (^|\s) anchor did
# not tolerate it and the value reached the audit log unredacted. The anchor
# must also accept a leading quote.
def test_env_redaction_handles_leading_shell_quote():
    out = _engine().redact_text("env 'SECRET_TOKEN=supersecretvalue123' cmd")
    assert "supersecretvalue123" not in out
    dq = _engine().redact_text('env "API_KEY=supersecretvalue123" cmd')
    assert "supersecretvalue123" not in dq


def test_does_not_compile_regexes_per_line(monkeypatch):
    # Compiling every pattern for every line made the regex engine 45x slower
    # than betterleaks on a large repo.
    from rafter_cli.core.pattern_engine import Pattern
    engine = PatternEngine([
        Pattern(name="AWS Access Key ID", regex="AKIA[A-Z0-9]{16}", severity="critical"),
        Pattern(name="Generic", regex="(?i)secret", severity="low"),
    ])
    calls = []
    original = PatternEngine._compile
    monkeypatch.setattr(PatternEngine, "_compile", staticmethod(lambda r: calls.append(r) or original(r)))
    text = "\n".join("x" if i % 50 else "AKIAIOSFODNN7EXAMPLE" for i in range(200))
    assert [m.line for m in engine.scan_with_position(text)] == [1, 51, 101, 151]
    assert calls == []
