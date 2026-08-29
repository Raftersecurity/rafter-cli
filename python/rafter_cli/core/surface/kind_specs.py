from __future__ import annotations

from .model import AxisSpec, KindSpec

IAM_AXES = (
    AxisSpec(
        name="action",
        ranks=("literal", "service-wildcard", "global-wildcard"),
        absent_rank="below",
        severity_at_top="high",
    ),
    AxisSpec(
        name="resource",
        ranks=("literal", "prefix-wildcard", "global-wildcard"),
        absent_rank="below",
        severity_at_top="high",
    ),
    AxisSpec(
        name="principal",
        ranks=("absent-or-literal", "wildcard"),
        absent_rank="below",
        severity_at_top="critical",
    ),
    AxisSpec(
        name="condition",
        ranks=("present", "absent"),
        absent_rank="below",
        severity_at_top="medium",
    ),
)

KIND_SPECS = (
    KindSpec(
        kind="container.port",
        comparator="ordinal",
        axes=(
            AxisSpec(
                name="binding",
                ranks=("not-published", "loopback-published", "host-published"),
                absent_rank="below",
                severity_at_top="high",
            ),
        ),
        severity_by_level=(None, "low", "high"),
        invert_danger=False,
        allow_residual_pairing=True,
        display="published ports",
    ),
    KindSpec(
        kind="iam.allow",
        comparator="lattice",
        axes=IAM_AXES,
        severity_when_incomparable="medium",
        invert_danger=False,
        allow_residual_pairing=True,
        display="IAM allows",
    ),
    KindSpec(
        kind="iam.deny",
        comparator="lattice",
        axes=IAM_AXES,
        severity_when_incomparable="medium",
        invert_danger=True,
        allow_residual_pairing=True,
        display="IAM denies",
    ),
    KindSpec(
        kind="pkg.lifecycle_script",
        comparator="ordinal",
        axes=(
            AxisSpec(
                name="fetch",
                ranks=("local", "fetches-remote", "pipes-remote-to-interpreter"),
                absent_rank="below",
                severity_at_top="critical",
            ),
        ),
        severity_by_level=(None, "medium", "critical"),
        invert_danger=False,
        allow_residual_pairing=False,
        display="lifecycle scripts",
    ),
)

KIND_SPEC_BY_KIND = {spec.kind: spec for spec in KIND_SPECS}

KEY_COMPONENTS = {
    "container.port": ("path", "service", "container_port", "protocol"),
    "iam.allow": ("path", "effect", "sid", "action_hash", "principal_hash"),
    "iam.deny": ("path", "effect", "sid", "action_hash", "principal_hash"),
    "pkg.lifecycle_script": ("path", "script_name"),
}
