from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from rafter_cli.core.surface.differ import DiffCoverage, diff_properties
from rafter_cli.core.surface.kind_specs import KEY_COMPONENTS, KIND_SPECS
from rafter_cli.core.surface.model import AxisSpec, Evidence, KindSpec, Property, Unanalyzed
from rafter_cli.core.surface.serialize import (
    canonical_json,
    kind_specs_to_wire,
    sort_unanalyzed,
    transition_to_wire,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def prop(
    kind: str,
    key: str,
    levels: dict[str, str | None],
    *,
    subject: str | None = None,
    attrs: dict[str, str | int | bool | None] | None = None,
    file: str | None = None,
    pairing_scope: str | None = None,
) -> Property:
    return Property(
        kind=kind,
        key=key,
        subject=subject or key,
        levels=levels,
        label=key,
        attrs=attrs or {},
        evidence=Evidence(file or ("policy.json" if kind.startswith("iam.") else "compose.yml"), 5),
        pairing_scope=pairing_scope,
    )


def iam_levels(**overrides: str | None) -> dict[str, str | None]:
    return {
        "action": "literal",
        "resource": "prefix-wildcard",
        "principal": "absent-or-literal",
        "condition": "absent",
        **overrides,
    }


def expected_transition(case_id: str) -> dict[str, object]:
    fixture = REPO_ROOT / "fixtures" / "surface" / "cases" / case_id / "expected.json"
    transition = json.loads(fixture.read_text(encoding="utf-8"))["transitions"][0]
    transition.pop("label")
    return transition


def assert_case(case_id: str, base: list[Property], head: list[Property]) -> None:
    transitions = diff_properties(base, head)
    assert len(transitions) == 1
    assert transition_to_wire(transitions[0]) == expected_transition(case_id)


def test_compose_port_appears() -> None:
    assert_case(
        "compose-port-appears",
        [],
        [
            prop(
                "container.port",
                "container.port:compose:compose.yml|redis|6379/tcp",
                {"binding": "host-published"},
                subject="service redis",
                attrs={
                    "service": "redis",
                    "bind": "0.0.0.0",
                    "container_port": 6379,
                    "protocol": "tcp",
                },
            )
        ],
    )


def test_compose_port_narrowed_to_loopback() -> None:
    key = "container.port:compose:compose.yml|redis|6379/tcp"
    assert_case(
        "compose-port-narrowed",
        [prop("container.port", key, {"binding": "host-published"}, subject="service redis")],
        [
            prop(
                "container.port",
                key,
                {"binding": "loopback-published"},
                subject="service redis",
                attrs={
                    "service": "redis",
                    "bind": "127.0.0.1",
                    "container_port": 6379,
                    "protocol": "tcp",
                },
            )
        ],
    )


def test_compose_service_rename_is_paired_unchanged() -> None:
    assert_case(
        "compose-service-renamed",
        [
            prop(
                "container.port",
                "container.port:compose:compose.yml|redis|6379/tcp",
                {"binding": "host-published"},
                subject="service redis",
                pairing_scope="compose.yml",
            )
        ],
        [
            prop(
                "container.port",
                "container.port:compose:compose.yml|cache|6379/tcp",
                {"binding": "host-published"},
                subject="service cache",
                pairing_scope="compose.yml",
                attrs={
                    "service": "cache",
                    "bind": "0.0.0.0",
                    "container_port": 6379,
                    "protocol": "tcp",
                },
            )
        ],
    )


def test_iam_resource_widened_with_sid() -> None:
    key = "iam.allow:iam-json:policy.json|sid=AppBucketAccess"
    assert_case(
        "iam-resource-widened-sid",
        [prop("iam.allow", key, iam_levels(), subject="statement AppBucketAccess")],
        [
            prop(
                "iam.allow",
                key,
                iam_levels(resource="global-wildcard"),
                subject="statement AppBucketAccess",
                attrs={"effect": "Allow", "action": "s3:GetObject", "resource": "*"},
            )
        ],
    )


def test_iam_resource_widened_without_sid() -> None:
    key = (
        "iam.allow:iam-json:policy.json|"
        "act=f084bba5e84ede8168b6c5b1ac07f2eea93c5e78290171b83d8f3f2709d10ba1|prin=none"
    )
    assert_case(
        "iam-resource-widened-no-sid",
        [prop("iam.allow", key, iam_levels(), subject="statement 1")],
        [
            prop(
                "iam.allow",
                key,
                iam_levels(resource="global-wildcard"),
                subject="statement 1",
                attrs={"effect": "Allow", "action": "s3:GetObject", "resource": "*"},
            )
        ],
    )


def test_iam_mixed_axis_change_is_incomparable() -> None:
    base_key = (
        "iam.allow:iam-json:policy.json|"
        "act=1e63caf99cd654591e8916273241630a7117703bb5f6129bf7108ccef9e9ef52|prin=none"
    )
    head_key = (
        "iam.allow:iam-json:policy.json|"
        "act=f084bba5e84ede8168b6c5b1ac07f2eea93c5e78290171b83d8f3f2709d10ba1|prin=none"
    )
    assert_case(
        "iam-incomparable",
        [
            prop(
                "iam.allow",
                base_key,
                iam_levels(action="service-wildcard"),
                subject="statement 1",
                pairing_scope="policy.json",
            )
        ],
        [
            prop(
                "iam.allow",
                head_key,
                iam_levels(resource="global-wildcard"),
                subject="statement 1",
                pairing_scope="policy.json",
                attrs={"effect": "Allow", "action": "s3:GetObject", "resource": "*"},
            )
        ],
    )


def test_iam_deny_removal_inverts_danger() -> None:
    assert_case(
        "iam-deny-removed",
        [
            prop(
                "iam.deny",
                "iam.deny:iam-json:policy.json|sid=BlockAllS3",
                iam_levels(action="global-wildcard", resource="global-wildcard"),
                subject="statement BlockAllS3",
                attrs={"effect": "Deny", "action": "*", "resource": "*"},
            )
        ],
        [],
    )


def test_iam_condition_removal_increases_danger() -> None:
    key = "iam.allow:iam-json:policy.json|sid=OfficeOnly"
    assert_case(
        "iam-condition-removed",
        [prop("iam.allow", key, iam_levels(condition="present"), subject="statement OfficeOnly")],
        [
            prop(
                "iam.allow",
                key,
                iam_levels(),
                subject="statement OfficeOnly",
                attrs={
                    "effect": "Allow",
                    "action": "s3:GetObject",
                    "resource": "arn:aws:s3:::app-bucket/*",
                },
            )
        ],
    )


def test_unchanged_exact_key_emits_nothing() -> None:
    unchanged = prop("container.port", "same", {"binding": "host-published"})
    assert diff_properties([unchanged], [unchanged]) == []


def test_duplicate_keys_abort_file_instead_of_merging() -> None:
    coverage = DiffCoverage()
    duplicate = prop("container.port", "duplicate", {"binding": "host-published"})
    assert diff_properties([duplicate, duplicate], [], coverage=coverage) == []
    assert coverage.unanalyzed == [
        Unanalyzed(
            file="compose.yml",
            side="base",
            reason="parse_error",
            detail="duplicate property key 'duplicate'",
            changed=False,
        )
    ]


def test_absent_rank_above_makes_removal_dangerous() -> None:
    source = KIND_SPECS[0]
    spec = replace(
        source,
        axes=(replace(source.axes[0], absent_rank="above"),),
        severity_when_absent="high",
        allow_residual_pairing=False,
    )
    transition = diff_properties(
        [prop("container.port", "protected", {"binding": "host-published"})],
        [],
        specs=[spec],
    )[0]
    assert transition.change == "removed"
    assert transition.danger == "increased"
    assert transition.severity == "high"
    assert transition.axes[0].order == "greater"


def test_null_severity_level_is_non_reportable() -> None:
    transition = diff_properties(
        [], [prop("container.port", "internal", {"binding": "not-published"})]
    )[0]
    assert transition.danger == "increased"
    assert transition.severity is None


def test_unknown_lattice_axis_forces_unknown() -> None:
    transition = diff_properties(
        [prop("iam.allow", "unknown", iam_levels(condition="present"))],
        [prop("iam.allow", "unknown", iam_levels(condition=None))],
    )[0]
    assert transition.danger == "unknown"
    assert transition.severity is None


def test_residual_pairing_requires_exactly_one_per_side() -> None:
    one_base = prop(
        "container.port", "a", {"binding": "host-published"}, pairing_scope="scope"
    )
    one_head = prop(
        "container.port", "b", {"binding": "host-published"}, pairing_scope="scope"
    )
    assert len(diff_properties([one_base], [one_head])) == 1
    transitions = diff_properties(
        [one_base, replace(one_base, key="c")],
        [one_head, replace(one_head, key="d")],
    )
    assert len(transitions) == 4
    assert all(not transition.paired for transition in transitions)
    assert {transition.change for transition in transitions} == {"added", "removed"}


def test_coverage_blocked_addition_becomes_unknown() -> None:
    coverage = DiffCoverage(
        unanalyzed=[
            Unanalyzed(
                file="broken.yml",
                side="base",
                reason="parse_error",
                detail="invalid YAML",
                changed=True,
            )
        ]
    )
    transition = diff_properties(
        [],
        [prop("container.port", "added", {"binding": "host-published"})],
        coverage=coverage,
    )[0]
    assert transition.change == "added"
    assert transition.danger == "unknown"
    assert transition.severity is None


def test_transition_sort_uses_utf8_bytes() -> None:
    transitions = diff_properties(
        [],
        [
            prop("container.port", "é", {"binding": "host-published"}),
            prop("container.port", "z", {"binding": "host-published"}),
        ],
    )
    assert [transition.key for transition in transitions] == ["z", "é"]


def test_key_components_are_disjoint_from_axes() -> None:
    for spec in KIND_SPECS:
        axes = {axis.name for axis in spec.axes}
        assert not (set(KEY_COMPONENTS[spec.kind]) & axes)


def test_kind_specs_match_shared_canonical_dump() -> None:
    expected = json.loads(
        (REPO_ROOT / "fixtures" / "surface" / "kind-specs.json").read_text(encoding="utf-8")
    )
    assert canonical_json(kind_specs_to_wire(KIND_SPECS)) == canonical_json(expected)


def test_expected_fixtures_are_internally_consistent() -> None:
    severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    cases_root = REPO_ROOT / "fixtures" / "surface" / "cases"
    for fixture in cases_root.glob("*/expected.json"):
        expected = json.loads(fixture.read_text(encoding="utf-8"))
        transitions = expected["transitions"]
        assert expected["schema_version"] == 1
        assert expected["summary"]["reportable"] == sum(
            transition["severity"] is not None for transition in transitions
        )
        for danger in ("increased", "decreased", "incomparable", "unchanged", "unknown"):
            assert expected["summary"][danger] == sum(
                transition["danger"] == danger for transition in transitions
            )
        for change in ("added", "removed", "modified"):
            assert expected["summary"][change] == sum(
                transition["change"] == change for transition in transitions
            )
        severities = sorted(
            (transition["severity"] for transition in transitions if transition["severity"]),
            key=severity_rank.__getitem__,
            reverse=True,
        )
        assert expected["summary"]["highest_severity"] == (severities[0] if severities else None)
        assert expected["coverage"]["degraded"] == bool(expected["coverage"]["unanalyzed"])
        assert expected["coverage"]["inconclusive"] == any(
            item["changed"] for item in expected["coverage"]["unanalyzed"]
        )
        for transition in transitions:
            spec = next(spec for spec in KIND_SPECS if spec.kind == transition["kind"])
            assert [axis["axis"] for axis in transition["axes"]] == [axis.name for axis in spec.axes]
            assert all(key.isascii() for key in transition["attrs"])
            assert all(not isinstance(value, float) for value in transition["attrs"].values())


def test_serializer_owns_python_from_and_to_wire_names() -> None:
    transition = diff_properties(
        [], [prop("container.port", "added", {"binding": "host-published"})]
    )[0]
    assert hasattr(transition, "from_level")
    assert not hasattr(transition, "from")
    assert hasattr(transition.axes[0], "from_rank")
    assert not hasattr(transition.axes[0], "from")
    wire = transition_to_wire(transition)
    assert wire["from"] is None
    assert wire["to"] == "host-published"
    assert wire["axes"][0]["from"] is None
    assert wire["axes"][0]["to"] == "host-published"


def test_canonical_json_normalizes_and_rejects_invalid_numbers_and_keys() -> None:
    assert canonical_json({"z": "e\u0301", "a": "\ud800", "n": 9007199254740991}) == (
        '{"a":"�","n":9007199254740991,"z":"é"}'
    )
    with pytest.raises(TypeError, match="no floats"):
        canonical_json({"value": 1.5})
    with pytest.raises(TypeError, match="safe integers"):
        canonical_json({"value": 9007199254740992})
    with pytest.raises(TypeError, match="non-ASCII object key"):
        canonical_json({"é": 1})


def test_unanalyzed_sort_uses_utf8_bytes() -> None:
    def item(file: str) -> Unanalyzed:
        return Unanalyzed(file, "base", "parse_error", "bad", False)

    assert [entry.file for entry in sort_unanalyzed([item("é.yml"), item("z.yml")])] == [
        "z.yml",
        "é.yml",
    ]
