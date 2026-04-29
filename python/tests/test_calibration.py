"""Calibration harness for prompt-shield (rc-6fg) — Python mirror.

Mirrors `node/tests/calibration.test.ts`. Loads the shared corpora and runs
its own per-pattern matrix against `detect_secrets`. The two implementations
should produce identical detection counts on the same inputs; calibration
catches drift.

Three independent assertion blocks:
  1. Negative corpus  — `shared-docs/calibration/negative.txt`. Each line
     must produce zero detections; current FP count is `KNOWN_FP_FLOOR`,
     which fails on regression. Lower it as patterns improve.
  2. Positive corpus  — `shared-docs/calibration/positive.yaml`. Each case
     lists expected secret values; recall must clear `RECALL_FLOOR`.
  3. Per-pattern matrix (defined here, not in YAML — provider tokens would
     trip rafter's own pretool hook + GitHub push protection). For each of
     the 24 patterns: at least one positive case fires, at least one
     near-miss case does not.

Run with:
    pytest tests/test_calibration.py -v
or  pytest -m calibration -v
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from rafter_cli.core.config_schema import get_default_config
from rafter_cli.core.prompt_shield import detect_secrets, replace_secrets_with_refs

pytestmark = pytest.mark.calibration

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "shared-docs" / "calibration"

# Tunable floors. Mirror node/tests/calibration.test.ts; drift = bug in one impl.
# 6 known FPs all in Inline credential assignment with non-secret RHS values
# (X-Api-Key, ordered_set, aws-default, public, opaque, argon2id) — fix
# tracked in rc-wk5. Floors are pinned just below today's actuals so the
# suite gates against drift; today is recall=1.00, precision=0.917.
KNOWN_FP_FLOOR = 6
RECALL_FLOOR = 0.97
PRECISION_FLOOR = 0.90  # target 0.95 (rc-6fg)


@pytest.fixture(autouse=True)
def _use_default_config():
    with patch(
        "rafter_cli.core.config_manager.ConfigManager.load",
        return_value=get_default_config(),
    ), patch(
        "rafter_cli.core.config_manager.ConfigManager.load_with_policy",
        return_value=get_default_config(),
    ):
        yield


# ──────────── Token construction (split to dodge file scanners) ────────────
AKIA = "AKI" + "A"
ASIA = "ASI" + "A"
AROA = "ARO" + "A"
AGPA = "AGP" + "A"
AIDA = "AID" + "A"
A3T = "A3" + "T"
SK_LIVE = "sk_" + "live_"
RK_LIVE = "rk_" + "live_"
GHP = "ghp" + "_"
GHO = "gho" + "_"
GHU = "ghu" + "_"
GHR = "ghr" + "_"
SLACK_BOT = "xox" + "b-"
SLACK_USER = "xox" + "p-"
SLACK_APP = "xox" + "a-"
SLACK_REFRESH = "xox" + "r-"
GHS = "ghs" + "_"
NPM_PREFIX = "npm" + "_"
PYPI_PREFIX = "pypi-AgEI" + "cHlwaS5vcmc"
AIZA = "AI" + "za"
AWS_KEYWORD = "aw" + "s"
AWS_DOCS_KEY = AKIA + "IOSFODNN7EXAMPLE"
AWS_SECRET_TAIL = "wJalrXUtnFEMI/K7MDE" + "NG/bPxRfiCYEXAMPLEKEY"
PG_SCHEME = "post" + "gres"
MYSQL_SCHEME = "my" + "sql"
MONGO_SCHEME = "mong" + "odb"
PRIV_KEY_HEADER = "-----BEGI" + "N RSA PRIVATE KEY-----"
APIKEY_KW = "api" + "_key"
SECRET_KW = "sec" + "ret"
BEARER_KW = "Bear" + "er"

ALNUM36 = "abcdefghijklmnopqrstuvwxyz0123456789"
ALNUM24 = "abcdefghijklmnopqrstuvwx"
ALNUM32 = "abcdefghijklmnopqrstuvwxyz012345"
ALNUM35 = "abcdefghijklmnopqrstuvwxyz012345678"
ALNUM50 = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN"
ALNUM76 = (ALNUM50 + "OPQRSTUVWXabcdefghijklmnop")[:76]
HEX32 = "0123456789abcdef0123456789abcdef"

JWT_HEADER = "eyJ" + "hbGciOiJIUzI1NiJ9"
JWT_PAYLOAD = "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
JWT_SIG = "abcdefghijklmnopqrstuvwxyz012345ABCDEFGHIJ"

# Sanity-check token lengths.
for _name, _val, _expected in (
    ("ALNUM76", ALNUM76, 76),
    ("ALNUM50", ALNUM50, 50),
    ("ALNUM35", ALNUM35, 35),
    ("ALNUM36", ALNUM36, 36),
    ("ALNUM32", ALNUM32, 32),
    ("ALNUM24", ALNUM24, 24),
    ("HEX32", HEX32, 32),
    ("AWS_SECRET_TAIL", AWS_SECRET_TAIL, 40),
):
    assert len(_val) == _expected, f"{_name} length mismatch: {len(_val)}, expected {_expected}"


# ─────────────────────── Per-pattern hit/miss matrix ───────────────────────
# Each entry: (pattern_name, hits=[(prompt, expected_value), ...], misses=[prompt, ...])
MATRIX: list[tuple[str, list[tuple[str, str]], list[str]]] = [
    (
        "AWS Access Key ID",
        # Regex accepts 9 prefixes; cover one per alternation arm so a
        # refactor that drops any prefix surfaces immediately.
        [
            (f"use {AWS_DOCS_KEY} for the test", AWS_DOCS_KEY),
            (f"STS issued {ASIA}IOSFODNN7EXAMPLE for staging", f"{ASIA}IOSFODNN7EXAMPLE"),
            (f"assumed role {AROA}IOSFODNN7EXAMPLE today", f"{AROA}IOSFODNN7EXAMPLE"),
            (f"group key {AGPA}IOSFODNN7EXAMPLE active", f"{AGPA}IOSFODNN7EXAMPLE"),
            (f"IAM user {AIDA}IOSFODNN7EXAMPLE created", f"{AIDA}IOSFODNN7EXAMPLE"),
            (f"legacy {A3T}XIOSFODNN7EXAMPLE found", f"{A3T}XIOSFODNN7EXAMPLE"),
        ],
        [f"the {AKIA} prefix is part of AWS keys", f"{AKIA}SHORT123"],
    ),
    (
        "AWS Secret Access Key",
        [(
            f"{AWS_KEYWORD}_secret = {AWS_SECRET_TAIL} now",
            f"{AWS_KEYWORD}_secret = {AWS_SECRET_TAIL}",
        )],
        [f"{AWS_KEYWORD} is a cloud provider"],
    ),
    (
        "GitHub Personal Access Token",
        [(f"auth with {GHP}{ALNUM36} now", f"{GHP}{ALNUM36}")],
        [f"{GHP}tooshort", "gh prefix is for github"],
    ),
    (
        "GitHub OAuth Token",
        [(f"oauth: {GHO}{ALNUM36} returned", f"{GHO}{ALNUM36}")],
        [f"{GHO}short"],
    ),
    (
        "GitHub App Token",
        # Regex `(ghu|ghs)_…`; both prefixes must hit.
        [
            (f"app: {GHU}{ALNUM36} ok", f"{GHU}{ALNUM36}"),
            (f"server-to-server: {GHS}{ALNUM36} ok", f"{GHS}{ALNUM36}"),
        ],
        [f"{GHU}toosmall"],
    ),
    (
        "GitHub Refresh Token",
        [(f"refresh: {GHR}{ALNUM76} ok", f"{GHR}{ALNUM76}")],
        [f"{GHR}{ALNUM36}"],
    ),
    (
        "Google API Key",
        [(f"google api: {AIZA}{ALNUM35} now", f"{AIZA}{ALNUM35}")],
        [f"{AIZA}short"],
    ),
    (
        "Google OAuth",
        [(
            f"client id 1234567890-{ALNUM32}.apps.googleusercontent.com is ours",
            f"1234567890-{ALNUM32}.apps.googleusercontent.com",
        )],
        ["apps.googleusercontent.com is the host"],
    ),
    (
        "Slack Token",
        # Regex `xox[baprs]-…`; cover bot/user/app/refresh so a refactor
        # that narrows the bracket alternation surfaces immediately.
        [
            (f"slack: {SLACK_BOT}{ALNUM24} success", f"{SLACK_BOT}{ALNUM24}"),
            (f"user token {SLACK_USER}{ALNUM24} ok", f"{SLACK_USER}{ALNUM24}"),
            (f"app token {SLACK_APP}{ALNUM24} ok", f"{SLACK_APP}{ALNUM24}"),
            (f"refresh {SLACK_REFRESH}{ALNUM24} stored", f"{SLACK_REFRESH}{ALNUM24}"),
        ],
        [f"{SLACK_BOT}short"],
    ),
    (
        "Slack Webhook",
        [(
            f"webhook https://hooks.slack.com/services/T01234567/B01234567/{ALNUM24} ok",
            f"https://hooks.slack.com/services/T01234567/B01234567/{ALNUM24}",
        )],
        ["hooks.slack.com is the slack webhook host"],
    ),
    (
        "Stripe API Key",
        [(f"stripe: {SK_LIVE}{ALNUM24} ok", f"{SK_LIVE}{ALNUM24}")],
        [f"{SK_LIVE}short"],
    ),
    (
        "Stripe Restricted API Key",
        [(f"stripe restricted: {RK_LIVE}{ALNUM24} ok", f"{RK_LIVE}{ALNUM24}")],
        [f"{RK_LIVE}short"],
    ),
    (
        "Twilio API Key",
        [(f"twilio: SK{HEX32} ok", f"SK{HEX32}")],
        ["SK is a Twilio prefix", "SKshort"],
    ),
    (
        "Generic API Key",
        [(
            f'config {APIKEY_KW}="abcd1234efgh5678" loaded',
            f'{APIKEY_KW}="abcd1234efgh5678"',
        )],
        [
            f"the {APIKEY_KW} is short",
            f'{APIKEY_KW}="abc"',
            f'{APIKEY_KW}="abcdefghijklmnop"',
        ],
    ),
    (
        "Generic Secret",
        [(
            f'cfg {SECRET_KW}="abcd1234efghIJKL" loaded',
            f'{SECRET_KW}="abcd1234efghIJKL"',
        )],
        [f"{SECRET_KW} = unquoted_value", f'{SECRET_KW}="short1"'],
    ),
    (
        "Private Key",
        [(f"paste:\n{PRIV_KEY_HEADER}\nMIIEowIBA", PRIV_KEY_HEADER)],
        ["BEGIN PRIVATE block", "the private key file is rotated weekly"],
    ),
    (
        "Bearer Token",
        [(
            f"Authorization: {BEARER_KW} {ALNUM32}aaaa1234",
            f"{BEARER_KW} {ALNUM32}aaaa1234",
        )],
        [f"the {BEARER_KW.lower()} token is missing", f"{BEARER_KW} short"],
    ),
    (
        "Database Connection String",
        [(
            f"connect to {PG_SCHEME}://user:correctsecret@host:5432/db now",
            f"{PG_SCHEME}://user:correctsecret@host:5432/db",
        )],
        [
            f"the {PG_SCHEME} database is on host primary",
            f"{PG_SCHEME}://host:5432/db",
        ],
    ),
    (
        "JSON Web Token",
        [(
            f"the jwt is {JWT_HEADER}.{JWT_PAYLOAD}.{JWT_SIG} signed",
            f"{JWT_HEADER}.{JWT_PAYLOAD}.{JWT_SIG}",
        )],
        ["eyJ is the json header prefix"],
    ),
    (
        "npm Access Token",
        [(f"npm publish with {NPM_PREFIX}{ALNUM36} success", f"{NPM_PREFIX}{ALNUM36}")],
        [f"{NPM_PREFIX}short"],
    ),
    (
        "PyPI Token",
        [(f"pypi: {PYPI_PREFIX}{ALNUM50} ok", f"{PYPI_PREFIX}{ALNUM50}")],
        [f"{PYPI_PREFIX}short"],
    ),
    (
        "Inline credential assignment",
        [("DB_PASSWORD=hunter2andmore set", "hunter2andmore")],
        ["secret_id=12345", "DB_NAME=production"],
    ),
    (
        "Inline credential phrase",
        [("the password is hunter2andmore now", "hunter2andmore")],
        [
            "the password to victory is patience",
            "set api_key environment variable",
        ],
    ),
    (
        "URL with credentials",
        [(
            "fetch https://api-user:correctsecret@api.example.com/v1/me ok",
            "correctsecret",
        )],
        ["https://api.example.com/v1/me", "git@github.com:org/repo.git"],
    ),
]


# ───────────────────────────── Loaders ─────────────────────────────────────
def _load_negatives() -> list[str]:
    text = (FIXTURES / "negative.txt").read_text(encoding="utf-8")
    return [
        line.rstrip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _load_positives() -> list[dict]:
    text = (FIXTURES / "positive.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(text)["cases"]


def _describe(detected) -> str:
    if not detected:
        return "<none>"
    return ", ".join(f"{d.pattern_name}:{d.value!r}" for d in detected)


# ───────────────────────────── Tests ───────────────────────────────────────
class TestNegativeCorpus:
    def test_fp_count_at_or_below_floor(self, capsys):
        negatives = _load_negatives()
        fps = []
        for prompt in negatives:
            detected = detect_secrets(prompt)
            if detected:
                fps.append((prompt, detected))
        if len(fps) > KNOWN_FP_FLOOR:
            for prompt, hits in fps:
                print(f"  {prompt!r} -> {_describe(hits)}")
        assert len(fps) <= KNOWN_FP_FLOOR, (
            f"FP count {len(fps)} exceeds floor {KNOWN_FP_FLOOR}"
        )


class TestPositiveCorpus:
    def test_recall_at_or_above_floor(self, capsys):
        positives = _load_positives()
        total_expected = 0
        found = 0
        missed = []
        for case in positives:
            detected = detect_secrets(case["prompt"])
            detected_values = {d.value for d in detected}
            detected_pairs = {(d.pattern_name, d.value) for d in detected}
            for exp in case["expects"]:
                total_expected += 1
                value_ok = exp["value"] in detected_values
                pattern_ok = "pattern" not in exp or (exp["pattern"], exp["value"]) in detected_pairs
                if value_ok and pattern_ok:
                    found += 1
                else:
                    missed.append(
                        f"[{case['id']}] expected "
                        f"{exp.get('pattern','*')}:{exp['value']!r} | "
                        f"detected: {_describe(detected)}"
                    )
        recall = found / total_expected if total_expected else 1.0
        if missed:
            for m in missed:
                print(f"  {m}")
        assert recall >= RECALL_FLOOR, (
            f"Recall {recall:.3f} below floor {RECALL_FLOOR} ({found}/{total_expected})"
        )


class TestCombinedPrecision:
    def test_precision_at_or_above_floor(self):
        positives = _load_positives()
        negatives = _load_negatives()
        tp, fp = 0, 0
        for case in positives:
            detected = detect_secrets(case["prompt"])
            expected_values = {e["value"] for e in case["expects"]}
            for d in detected:
                if d.value in expected_values:
                    tp += 1
                else:
                    fp += 1
        for prompt in negatives:
            fp += len(detect_secrets(prompt))
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        assert precision >= PRECISION_FLOOR, (
            f"Precision {precision:.3f} below floor {PRECISION_FLOOR} (tp={tp}, fp={fp})"
        )


@pytest.mark.parametrize(
    "pattern_name,prompt,expected",
    [
        (name, prompt, value)
        for name, hits, _ in MATRIX
        for prompt, value in hits
    ],
    ids=[
        f"{name}-hit-{i}"
        for name, hits, _ in MATRIX
        for i, _ in enumerate(hits)
    ],
)
def test_matrix_hit(pattern_name, prompt, expected):
    detected = detect_secrets(prompt)
    matches = [d for d in detected if d.pattern_name == pattern_name and d.value == expected]
    assert matches, (
        f"[{pattern_name}] expected hit on {expected!r}, got {_describe(detected)}"
    )


@pytest.mark.parametrize(
    "pattern_name,prompt",
    [
        (name, prompt)
        for name, _, misses in MATRIX
        for prompt in misses
    ],
    ids=[
        f"{name}-miss-{i}"
        for name, _, misses in MATRIX
        for i, _ in enumerate(misses)
    ],
)
def test_matrix_miss(pattern_name, prompt):
    detected = detect_secrets(prompt)
    fired = [d for d in detected if d.pattern_name == pattern_name]
    assert not fired, (
        f"[{pattern_name}] unexpected hit on {prompt!r}: {_describe(detected)}"
    )


# rc-apd #1: round-trip envelope path. detect_secrets() is exercised by the
# corpus + matrix above, but env_base_name derivation, longest-first
# substring-safe replacement, and the placeholder filter feed the actual
# hook envelope. A regex change that left detection intact while breaking
# these auxiliary paths would pass every other assertion in this file.
class TestRoundTripEnvelope:
    def test_envbase_from_assignment_lhs(self):
        detected = detect_secrets("Connect with DB_PASSWORD=hunter2andmore please")
        assert len(detected) == 1
        assert detected[0].value == "hunter2andmore"
        assert detected[0].env_base_name == "DB_PASSWORD"

    def test_replace_with_env_ref(self):
        prompt = "Connect with DB_PASSWORD=hunter2andmore please"
        detected = detect_secrets(prompt)
        value_to_name = {d.value: d.env_base_name for d in detected}
        rewritten = replace_secrets_with_refs(prompt, detected, value_to_name)
        assert rewritten == "Connect with DB_PASSWORD=$DB_PASSWORD please"

    def test_longest_first_replacement_no_substring_shadowing(self):
        prompt = (
            "DB_PASSWORD=hunter2andmore_extended and "
            "AUTH_TOKEN=hunter2andmore here"
        )
        detected = detect_secrets(prompt)
        value_to_name = {d.value: d.env_base_name for d in detected}
        rewritten = replace_secrets_with_refs(prompt, detected, value_to_name)
        assert "DB_PASSWORD=$DB_PASSWORD" in rewritten
        assert "AUTH_TOKEN=$AUTH_TOKEN" in rewritten
        # Shorter value's env-ref must NOT appear inside the longer match.
        assert "$AUTH_TOKEN_extended" not in rewritten

    def test_url_credentials_envbase_is_url_password(self):
        detected = detect_secrets(
            "connect to redis://admin:hunter2andmore@cache.internal:6379/0"
        )
        urls = [d for d in detected if d.pattern_name == "URL with credentials"]
        assert urls
        assert urls[0].env_base_name == "URL_PASSWORD"
