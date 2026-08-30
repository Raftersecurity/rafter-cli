from __future__ import annotations

from .model import AxisSpec, KindSpec

IAM_AXES = (
    AxisSpec(
        name="action",
        derived_from=("Action",),
        ranks=("literal", "service-wildcard", "global-wildcard"),
        absent_rank="below",
        severity_by_rank=(None, "medium", "high"),
    ),
    AxisSpec(
        name="resource",
        derived_from=("Resource",),
        ranks=("literal", "prefix-wildcard", "global-wildcard"),
        absent_rank="below",
        severity_by_rank=(None, "medium", "high"),
    ),
    AxisSpec(
        name="principal",
        derived_from=("Principal",),
        ranks=("absent-or-literal", "wildcard"),
        absent_rank="below",
        severity_by_rank=(None, "critical"),
    ),
    AxisSpec(
        name="condition",
        derived_from=("Condition",),
        ranks=("present", "absent"),
        absent_rank="below",
        severity_by_rank=(None, "medium"),
    ),
)

KIND_SPECS = (
    KindSpec(
        kind="container.port",
        comparator="ordinal",
        axes=(
            AxisSpec(
                name="binding",
                derived_from=(
                    "ports[].host_ip",
                    "ports[].published",
                    "ports[].mode",
                    "expose",
                ),
                ranks=("not-published", "loopback-published", "host-published"),
                absent_rank="below",
                severity_by_rank=(None, "low", "high"),
            ),
        ),
        invert_danger=False,
        allow_residual_pairing=True,
        key_may_repeat=False,
        display="published ports",
    ),
    KindSpec(
        kind="iam.allow",
        comparator="lattice",
        axes=IAM_AXES,
        severity_when_incomparable="medium",
        invert_danger=False,
        allow_residual_pairing=True,
        key_may_repeat=True,
        display="IAM allows",
    ),
    KindSpec(
        kind="iam.deny",
        comparator="lattice",
        axes=IAM_AXES,
        severity_when_incomparable="medium",
        invert_danger=True,
        allow_residual_pairing=True,
        key_may_repeat=True,
        display="IAM denies",
    ),
    KindSpec(
        kind="pkg.lifecycle_script",
        comparator="ordinal",
        axes=(
            AxisSpec(
                name="fetch",
                derived_from=("scripts.<name>.body",),
                ranks=("local", "fetches-remote", "pipes-remote-to-interpreter"),
                absent_rank="below",
                severity_by_rank=(None, "medium", "critical"),
            ),
        ),
        invert_danger=False,
        allow_residual_pairing=False,
        key_may_repeat=False,
        display="lifecycle scripts",
    ),
)

KIND_SPEC_BY_KIND = {spec.kind: spec for spec in KIND_SPECS}

KEY_COMPONENTS = {
    "container.port": (
        {"component": "path", "derived_from": ("file-path",), "locative": True},
        {"component": "service", "derived_from": ("service-name",), "locative": False},
        {
            "component": "container_port",
            "derived_from": ("ports[].target",),
            "locative": False,
        },
        {
            "component": "protocol",
            "derived_from": ("ports[].protocol",),
            "locative": False,
        },
    ),
    "iam.allow": (
        {"component": "path", "derived_from": ("file-path",), "locative": True},
        {"component": "effect", "derived_from": ("Effect",), "locative": False},
        {"component": "sid", "derived_from": ("Sid",), "locative": False},
    ),
    "iam.deny": (
        {"component": "path", "derived_from": ("file-path",), "locative": True},
        {"component": "effect", "derived_from": ("Effect",), "locative": False},
        {"component": "sid", "derived_from": ("Sid",), "locative": False},
    ),
    "pkg.lifecycle_script": (
        {"component": "path", "derived_from": ("file-path",), "locative": True},
        {
            "component": "script_name",
            "derived_from": ("scripts.<name>",),
            "locative": False,
        },
    ),
}
