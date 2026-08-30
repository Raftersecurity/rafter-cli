from __future__ import annotations

from pathlib import Path

import pytest

from rafter_cli.core.surface.serialize import canonical_json
from rafter_cli.core.surface.yaml_safe import (
    YamlAdapterError,
    load_yaml_string_only,
    parse_scalar,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

DIVERGENCE_EXPECTED = {
    "a": "yes",
    "b": "no",
    "c": "on",
    "d": "0o17",
    "e": "017",
    "f": "0x1F",
    "g": "1_000",
    "h": "27017:27017",
    "i": "27017:27017",
    "j": "3.0",
    "k": "08",
}


def assert_yaml_error(source: str, reason: str, detail: str) -> None:
    with pytest.raises(YamlAdapterError) as caught:
        load_yaml_string_only(source)
    assert caught.value.reason == reason
    assert caught.value.detail == detail


def test_divergence_fixture_matches_hand_written_bytes() -> None:
    source = (REPO_ROOT / "fixtures" / "surface" / "yaml-divergence.yml").read_text()

    assert canonical_json(load_yaml_string_only(source)) == canonical_json(
        DIVERGENCE_EXPECTED
    )


def test_duplicate_mapping_key_is_typed_parse_error() -> None:
    assert_yaml_error(
        "value: one\nvalue: two\n", "parse_error", "YAML could not be parsed"
    )


def test_empty_nodes_and_documents_normalize_to_empty_strings() -> None:
    assert canonical_json(load_yaml_string_only("mapping:\nsequence:\n  -\n")) == (
        canonical_json({"mapping": "", "sequence": [""]})
    )
    assert load_yaml_string_only("") == ""
    assert load_yaml_string_only("---\n") == ""


def test_merge_key_remains_literal() -> None:
    source = "\n".join(
        [
            "base: &base",
            "  enabled: yes",
            "derived:",
            "  <<: *base",
            "  port: 017",
            "",
        ]
    )

    assert canonical_json(load_yaml_string_only(source)) == canonical_json(
        {
            "base": {"enabled": "yes"},
            "derived": {"<<": {"enabled": "yes"}, "port": "017"},
        }
    )


def test_ordinary_anchors_and_aliases_resolve_without_coercion() -> None:
    source = "\n".join(
        [
            "base: &base",
            "  enabled: yes",
            "  port: 017",
            "copy: *base",
            "",
        ]
    )
    expected = {
        "base": {"enabled": "yes", "port": "017"},
        "copy": {"enabled": "yes", "port": "017"},
    }

    assert canonical_json(load_yaml_string_only(source)) == canonical_json(expected)


def test_additional_divergent_scalar_forms_remain_strings() -> None:
    source = "\n".join(
        [
            "sexagesimal: 12:34:56",
            "scientific: 1e3",
            "timestamp: 2025-01-02",
            "huge: 9007199254740993",
            "infinity: .inf",
            "null_word: null",
            "null_tilde: ~",
            "",
        ]
    )

    assert canonical_json(load_yaml_string_only(source)) == canonical_json(
        {
            "sexagesimal": "12:34:56",
            "scientific": "1e3",
            "timestamp": "2025-01-02",
            "huge": "9007199254740993",
            "infinity": ".inf",
            "null_word": "null",
            "null_tilde": "~",
        }
    )


def test_tags_unsafe_keys_cycles_and_tabs_are_unsupported() -> None:
    assert_yaml_error(
        "value: !!int 17\n", "unsupported_syntax", "YAML uses an unsupported tag"
    )
    assert_yaml_error(
        "[a, b]: value\n",
        "unsupported_syntax",
        "YAML mapping keys must be scalar strings",
    )
    assert_yaml_error(
        '\"\": value\n',
        "unsupported_syntax",
        "Empty YAML mapping keys are unsupported",
    )
    assert_yaml_error(
        "value: &value\n  self: *value\n",
        "unsupported_syntax",
        "Cyclic YAML aliases are unsupported",
    )
    assert_yaml_error(
        "value: plain\ttext\n",
        "unsupported_syntax",
        "YAML containing tab characters is unsupported",
    )
    assert_yaml_error(
        "block: |\n\t\nend: value\n",
        "unsupported_syntax",
        "YAML containing tab characters is unsupported",
    )
    assert_yaml_error(
        "- block: |\n    content\n  value: plain\ttext\n",
        "unsupported_syntax",
        "YAML containing tab characters is unsupported",
    )
    assert_yaml_error(
        "key: &key value\n*key: other\n",
        "parse_error",
        "YAML could not be parsed",
    )


def test_flow_mappings_and_unicode_input_keys_are_accepted() -> None:
    assert load_yaml_string_only("{a: b, c: [d, e]}\n") == {
        "a": "b",
        "c": ["d", "e"],
    }
    assert load_yaml_string_only("a:\n  - {b: c}\n") == {"a": [{"b": "c"}]}
    assert load_yaml_string_only("café: value\n") == {"café": "value"}
    assert load_yaml_string_only("key: &key value\n? *key\n: other\n") == {
        "key": "value",
        "value": "other",
    }


def test_tabs_inside_quoted_strings_comments_and_block_scalars_are_allowed() -> None:
    source = "\n".join(
        [
            'double: "left\tright"',
            "single: 'left\tright'",
            "comment: value # left\tright",
            "block: |",
            "  left\tright",
            "explicit: |2",
            "    first",
            "  left\tright",
            "sequence:",
            "  - |",
            "    left\tright",
            "nested:",
            "  -   - |",
            "        left\tright",
            "",
        ]
    )

    assert canonical_json(load_yaml_string_only(source)) == canonical_json(
        {
            "double": "left\tright",
            "single": "left\tright",
            "comment": "value",
            "block": "left\tright\n",
            "explicit": "  first\nleft\tright\n",
            "sequence": ["left\tright\n"],
            "nested": [["left\tright\n"]],
        }
    )


def test_structures_beyond_shared_nesting_budget_are_rejected() -> None:
    source = f'value: {"[" * 65}leaf{"]" * 65}\n'

    assert_yaml_error(source, "parse_error", "YAML could not be parsed")


def test_prototype_shaped_keys_remain_inert_data() -> None:
    loaded = load_yaml_string_only(
        "__proto__:\n  polluted: yes\nconstructor: safe\n"
    )

    assert canonical_json(loaded) == canonical_json(
        {"__proto__": {"polluted": "yes"}, "constructor": "safe"}
    )


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("~", None),
        ("null", None),
        ("Null", None),
        ("NULL", None),
        ("true", True),
        ("True", True),
        ("TRUE", True),
        ("false", False),
        ("False", False),
        ("FALSE", False),
        ("0", 0),
        ("+0", 0),
        ("-0", 0),
        ("+17", 17),
        ("-17", -17),
        ("9007199254740991", 9007199254740991),
    ],
)
def test_parse_scalar_shared_lists(source: str, expected: object) -> None:
    assert parse_scalar(source) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "yes",
        "no",
        "on",
        "off",
        "017",
        "08",
        "0o17",
        "0x1F",
        "1_000",
        "3.0",
        "1e3",
        "12:34:56",
        "2025-01-02",
        "9007199254740992",
        "-9007199254740992",
        "9" * 4_301,
    ],
)
def test_parse_scalar_preserves_ambiguous_forms(value: str) -> None:
    assert parse_scalar(value) == value
