from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from rafter_cli.core.surface.differ import DiffCoverage, diff_properties
from rafter_cli.core.surface.kind_specs import KEY_COMPONENTS, KIND_SPECS
from rafter_cli.core.surface.model import Evidence, Property, Unanalyzed
from rafter_cli.core.surface.paths import parent_scope
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
    label: str | None = None,
    attrs: dict[str, str | int | bool | None] | None = None,
    file: str | None = None,
    line: int = 5,
    discriminator: str | None = None,
    pairing_scope: str | None = None,
) -> Property:
    return Property(
        kind=kind,
        key=key,
        discriminator=key if discriminator is None else discriminator,
        subject=subject or key,
        levels=levels,
        label=label or key,
        attrs=attrs or {},
        evidence=Evidence(
            file or ("policy.json" if kind.startswith("iam.") else "compose.yml"), line
        ),
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
    return json.loads(fixture.read_text(encoding="utf-8"))["transitions"][0]


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
                label="redis port 6379 published on 0.0.0.0",
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
                label="redis port 6379 published on 127.0.0.1",
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
                label="cache port 6379 published on 0.0.0.0",
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
                label="Allow s3:GetObject on *",
                attrs={"effect": "Allow", "action": "s3:GetObject", "resource": "*"},
            )
        ],
    )


def test_iam_resource_widened_without_sid() -> None:
    key = "iam.allow:iam-json:policy.json|nosid"
    assert_case(
        "iam-resource-widened-no-sid",
        [prop("iam.allow", key, iam_levels(), subject="unnamed statement")],
        [
            prop(
                "iam.allow",
                key,
                iam_levels(resource="global-wildcard"),
                subject="unnamed statement",
                label="Allow s3:GetObject on *",
                attrs={"effect": "Allow", "action": "s3:GetObject", "resource": "*"},
            )
        ],
    )


def test_iam_mixed_axis_change_is_incomparable() -> None:
    key = "iam.allow:iam-json:policy.json|nosid"
    assert_case(
        "iam-incomparable",
        [
            prop(
                "iam.allow",
                key,
                iam_levels(action="service-wildcard"),
                subject="unnamed statement",
                discriminator="",
            )
        ],
        [
            prop(
                "iam.allow",
                key,
                iam_levels(resource="global-wildcard"),
                subject="unnamed statement",
                label="Allow s3:GetObject on *",
                discriminator="",
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
                label="Deny * on *",
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
                label="Allow s3:GetObject on arn:aws:s3:::app-bucket/*",
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


def test_repeated_key_bucket_cancels_equal_vectors_before_classifying_residue() -> None:
    key = "iam.allow:iam-json:policy.json|nosid"
    assert_case(
        "iam-two-nosid-statements-changed",
        [
            prop(
                "iam.allow",
                key,
                iam_levels(resource="literal"),
                subject="unnamed statement",
                discriminator="",
                line=5,
            ),
            prop(
                "iam.allow",
                key,
                iam_levels(),
                subject="unnamed statement",
                discriminator="",
                line=10,
            ),
        ],
        [
            prop(
                "iam.allow",
                key,
                iam_levels(resource="literal"),
                subject="unnamed statement",
                discriminator="",
                line=5,
            ),
            prop(
                "iam.allow",
                key,
                iam_levels(resource="global-wildcard"),
                subject="unnamed statement",
                label="Allow s3:GetObject on *",
                discriminator="",
                line=10,
                attrs={"effect": "Allow", "action": "s3:GetObject", "resource": "*"},
            ),
        ],
    )


def test_unique_discriminators_match_across_file_relocation_without_noops() -> None:
    def relocated(file: str, service: str, port: int) -> Property:
        return prop(
            "container.port",
            f"container.port:compose:{file}|{service}|{port}/tcp",
            {"binding": "host-published"},
            subject=f"service {service}",
            discriminator=f"{service}|{port}/tcp",
            pairing_scope="infra",
            file=file,
        )

    specs_without_phase_2 = tuple(
        replace(spec, allow_residual_pairing=False)
        if spec.kind == "container.port"
        else spec
        for spec in KIND_SPECS
    )
    assert (
        diff_properties(
            [
                relocated("infra/docker-compose.yml", "redis", 6379),
                relocated("infra/docker-compose.yml", "web", 8080),
            ],
            [
                relocated("infra/compose.prod.yml", "redis", 6379),
                relocated("infra/compose.prod.yml", "web", 8080),
            ],
            specs_without_phase_2,
        )
        == []
    )


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


def test_key_component_provenance_is_disjoint_from_axis_provenance() -> None:
    for spec in KIND_SPECS:
        key_fields = {
            field
            for component in KEY_COMPONENTS[spec.kind]
            for field in component["derived_from"]
        }
        axis_fields = {field for axis in spec.axes for field in axis.derived_from}
        assert not (key_fields & axis_fields)


def test_discriminator_elides_locative_key_components() -> None:
    key = "container.port:compose:infra/docker-compose.yml|redis|6379/tcp"
    observed = prop(
        "container.port",
        key,
        {"binding": "host-published"},
        discriminator="redis|6379/tcp",
    )
    key_body = key.split(":compose:", maxsplit=1)[1]
    assert [
        component["component"]
        for component in KEY_COMPONENTS[observed.kind]
        if component["locative"]
    ] == ["path"]
    assert observed.discriminator == "|".join(key_body.split("|")[1:])


def test_serializer_emits_complete_transition_key_set_in_schema_order() -> None:
    transition = diff_properties(
        [],
        [
            prop(
                "container.port",
                "added",
                {"binding": "host-published"},
                label="published port",
            )
        ],
    )[0]
    assert list(transition_to_wire(transition)) == [
        "kind",
        "key",
        "subject",
        "label",
        "change",
        "danger",
        "severity",
        "axes",
        "from",
        "to",
        "confidence",
        "base_evidence",
        "head_evidence",
        "attrs",
        "paired",
    ]


def test_kind_specs_match_shared_canonical_dump() -> None:
    expected = json.loads(
        (REPO_ROOT / "fixtures" / "surface" / "kind-specs.json").read_text(encoding="utf-8")
    )
    assert canonical_json(kind_specs_to_wire(KIND_SPECS)) == canonical_json(expected)


def test_expected_fixtures_are_internally_consistent() -> None:
    severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    cases_root = REPO_ROOT / "fixtures" / "surface" / "cases"
    fixtures = list(cases_root.glob("*/expected.json"))
    assert len(fixtures) == 10
    for fixture in fixtures:
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
            assert list(transition) == [
                "kind",
                "key",
                "subject",
                "label",
                "change",
                "danger",
                "severity",
                "axes",
                "from",
                "to",
                "confidence",
                "base_evidence",
                "head_evidence",
                "attrs",
                "paired",
            ]
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


def test_cancellation_survivor_is_independent_of_input_order() -> None:
    """IAM ``Statement[]`` order carries no meaning, so reordering a document must
    not change which property survives cancellation. Ordering cancellation by input
    position instead of by content makes the surviving label and evidence depend on
    emission order — reorder-variance the W7 M1 mutation would fail on.
    """
    key = "iam.allow:iam-json:policy.json|nosid"

    def bucket(subject: str, line: int) -> Property:
        return prop(
            "iam.allow",
            key,
            iam_levels(),
            subject=subject,
            label=f"Allow s3:GetObject on {subject}",
            discriminator="",
            file="policy.json",
            line=line,
            attrs={"effect": "Allow", "action": "s3:GetObject", "resource": subject},
        )

    alpha = bucket("bucket-alpha", 5)
    beta = bucket("bucket-beta", 12)
    head = [bucket("bucket-alpha", 5)]

    forward = [transition_to_wire(t) for t in diff_properties([alpha, beta], head)]
    reversed_ = [transition_to_wire(t) for t in diff_properties([beta, alpha], head)]

    assert canonical_json(forward) == canonical_json(reversed_)
    assert len(forward) == 1
    assert forward[0]["change"] == "removed"
    assert forward[0]["subject"] == "bucket-beta"


def test_unanalyzed_reasons_tuple_matches_literal() -> None:
    """Python cannot derive a Literal from a tuple, so the runtime tuple and the
    type are necessarily written twice. Guard the drift: the docs-sync test walks
    the tuple, so a reason present only in the Literal would go undocumented.
    """
    from typing import get_args

    from rafter_cli.core.surface.model import UNANALYZED_REASONS, UnanalyzedReason

    assert set(UNANALYZED_REASONS) == set(get_args(UnanalyzedReason))


# --- A2 F2: severity is a function of arrival rank, never of movement ---------


def test_narrowest_added_allow_is_severity_null() -> None:
    """Before the fix every IAM axis moved from absent (rank -1) to present, each
    contributed its old ``severity_at_top``, and ``principal``'s was ``critical`` —
    so the narrowest expressible statement gated CI at ``critical``."""
    transition = diff_properties(
        [],
        [
            prop(
                "iam.allow",
                "iam.allow:iam-json:policy.json|sid=NarrowRead",
                {
                    "action": "literal",
                    "resource": "literal",
                    "principal": "absent-or-literal",
                    "condition": "present",
                },
                subject="statement NarrowRead",
                label="Allow s3:GetObject on arn:aws:s3:::app-bucket/report.csv",
            )
        ],
    )[0]
    assert transition.change == "added"
    assert transition.danger == "increased"
    assert transition.severity is None


def test_added_allow_without_condition_is_medium() -> None:
    """The accepted false positive: a single ``medium`` contributor. Visible under
    the default ``--min-severity low``, never gating under ``--fail-on high``."""
    transition = diff_properties(
        [],
        [
            prop(
                "iam.allow",
                "iam.allow:iam-json:policy.json|sid=NoCondition",
                {
                    "action": "literal",
                    "resource": "literal",
                    "principal": "absent-or-literal",
                    "condition": "absent",
                },
            )
        ],
    )[0]
    assert (transition.danger, transition.severity) == ("increased", "medium")


def test_two_strong_axes_promote_to_critical() -> None:
    transition = diff_properties(
        [],
        [
            prop(
                "iam.allow",
                "iam.allow:iam-json:policy.json|sid=Admin",
                {
                    "action": "global-wildcard",
                    "resource": "global-wildcard",
                    "principal": "absent-or-literal",
                    "condition": "absent",
                },
            )
        ],
    )[0]
    assert (transition.danger, transition.severity) == ("increased", "critical")


def test_every_axis_has_one_severity_per_rank() -> None:
    for spec in KIND_SPECS:
        for axis in spec.axes:
            assert len(axis.severity_by_rank) == len(axis.ranks)
    shared = json.loads(
        (REPO_ROOT / "fixtures" / "surface" / "kind-specs.json").read_text(encoding="utf-8")
    )
    for spec_wire in shared:
        for axis_wire in spec_wire["axes"]:
            assert len(axis_wire["severityByRank"]) == len(axis_wire["ranks"])


# --- A2 F8b: the final sort is a total order ---------------------------------


def test_same_key_transitions_order_by_content_not_emission() -> None:
    """Under ``key_may_repeat``, two transitions can share severity, kind and key;
    the v1 three-component sort left that tie to a stable sort, so the order was a
    function of emission order — i.e. of ``Statement[]`` position."""
    key = "iam.allow:iam-json:policy.json|nosid"

    def statement(resource: str, line: int) -> Property:
        return prop(
            "iam.allow",
            key,
            iam_levels(resource="global-wildcard"),
            subject="unnamed statement",
            label=f"Allow s3:GetObject on {resource}",
            discriminator="",
            line=line,
            attrs={"effect": "Allow", "action": "s3:GetObject", "resource": resource},
        )

    alpha = statement("*", 5)
    beta = statement("**", 12)
    forward = diff_properties([], [alpha, beta])
    reversed_ = diff_properties([], [beta, alpha])

    assert len(forward) == 2
    assert [transition.key for transition in forward] == [key, key]
    assert [transition.severity for transition in forward] == ["high", "high"]
    assert canonical_json([transition_to_wire(t) for t in forward]) == canonical_json(
        [transition_to_wire(t) for t in reversed_]
    )
    assert [transition.attrs["resource"] for transition in forward] == ["*", "**"]


def test_content_identical_transitions_fall_back_to_evidence() -> None:
    key = "iam.allow:iam-json:policy.json|nosid"

    def twin(line: int) -> Property:
        return prop(
            "iam.allow",
            key,
            iam_levels(resource="global-wildcard"),
            subject="unnamed statement",
            label="Allow s3:GetObject on *",
            discriminator="",
            line=line,
        )

    forward = diff_properties([], [twin(5), twin(12)])
    reversed_ = diff_properties([], [twin(12), twin(5)])
    assert [t.head_evidence.line for t in forward if t.head_evidence] == [5, 12]
    assert canonical_json([transition_to_wire(t) for t in forward]) == canonical_json(
        [transition_to_wire(t) for t in reversed_]
    )


# --- A2 F5: a paired transition takes the head-side key ----------------------


def test_paired_transition_takes_the_head_key() -> None:
    """The keys here are chosen so the deleted min-of-two rule would pick the base
    key: all ten committed fixtures pass under either rule."""
    transition = diff_properties(
        [
            prop(
                "container.port",
                "container.port:compose:a/compose.yml|cache|6379/tcp",
                {"binding": "host-published"},
                subject="service cache",
                pairing_scope="a",
            )
        ],
        [
            prop(
                "container.port",
                "container.port:compose:a/compose.yml|redis|6379/tcp",
                {"binding": "host-published"},
                subject="service redis",
                pairing_scope="a",
            )
        ],
    )[0]
    assert transition.key == "container.port:compose:a/compose.yml|redis|6379/tcp"
    assert transition.subject == "service redis"
    assert transition.paired is True
    assert transition.danger == "unchanged"


# --- A2 F10: the repo root is spelled "" ------------------------------------


def test_parent_scope_spells_the_repo_root_empty() -> None:
    """The empty string is a valid scope and is not ``None``, so callers gating on
    a scope must test ``is not None``, never truthiness."""
    assert parent_scope("compose.yml") == ""
    assert parent_scope("a/compose.yml") == "a"
    assert parent_scope("a/b/compose.yml") == "a/b"
