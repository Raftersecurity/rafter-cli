from __future__ import annotations

from typing import Literal, Optional, Sequence

from .model import (
    AxisOrder,
    AxisSpec,
    AxisTransition,
    Danger,
    KindSpec,
    Property,
    SurfaceSeverity,
)

ComparatorOrder = Literal["equal", "greater", "less", "incomparable", "unknown"]

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _rank_of(axis: AxisSpec, value: Optional[str], present: bool) -> Optional[int]:
    if not present:
        return -1 if axis.absent_rank == "below" else len(axis.ranks)
    if value is None:
        return None
    try:
        return axis.ranks.index(value)  # type: ignore[union-attr]
    except ValueError:
        return None


def _compare_axis(
    axis: AxisSpec,
    base: Optional[Property],
    head: Optional[Property],
) -> AxisTransition:
    from_rank = base.levels.get(axis.name) if base is not None else None
    to_rank = head.levels.get(axis.name) if head is not None else None
    base_rank = _rank_of(axis, from_rank, base is not None)
    head_rank = _rank_of(axis, to_rank, head is not None)
    order: AxisOrder
    if base_rank is None or head_rank is None:
        order = "unknown"
    elif head_rank == base_rank:
        order = "equal"
    elif head_rank > base_rank:
        order = "greater"
    else:
        order = "less"
    return AxisTransition(axis.name, from_rank, to_rank, order)


def _aggregate(axes: Sequence[AxisTransition]) -> ComparatorOrder:
    if any(axis.order == "unknown" for axis in axes):
        return "unknown"
    greater = any(axis.order == "greater" for axis in axes)
    less = any(axis.order == "less" for axis in axes)
    if greater and less:
        return "incomparable"
    if greater:
        return "greater"
    if less:
        return "less"
    return "equal"


def ordinal_compare(
    spec: KindSpec,
    base: Optional[Property],
    head: Optional[Property],
) -> tuple[ComparatorOrder, list[AxisTransition]]:
    if len(spec.axes) != 1:
        raise ValueError(f"ordinal kind {spec.kind} must have one axis")
    axes = [_compare_axis(spec.axes[0], base, head)]
    return axes[0].order, axes


def lattice_compare(
    spec: KindSpec,
    base: Optional[Property],
    head: Optional[Property],
) -> tuple[ComparatorOrder, list[AxisTransition]]:
    axes = [_compare_axis(axis, base, head) for axis in spec.axes]
    return _aggregate(axes), axes


def flip_order(order: ComparatorOrder) -> ComparatorOrder:
    if order == "greater":
        return "less"
    if order == "less":
        return "greater"
    return order


def danger_for(order: ComparatorOrder) -> Danger:
    return {
        "equal": "unchanged",
        "greater": "increased",
        "less": "decreased",
        "incomparable": "incomparable",
        "unknown": "unknown",
    }[order]  # type: ignore[return-value]


def _maximum_severity(values: Sequence[SurfaceSeverity]) -> SurfaceSeverity:
    best: SurfaceSeverity = None
    for value in values:
        if value is not None and (best is None or SEVERITY_RANK[value] > SEVERITY_RANK[best]):
            best = value
    return best


def _axis_severity(
    spec: KindSpec,
    axis: Optional[AxisSpec],
    transition: AxisTransition,
    endpoint: Optional[Property],
) -> SurfaceSeverity:
    """Severity contributed by one increasing axis: the severity of the rank the
    axis ARRIVED at on the endpoint side. ``endpoint is None`` means the whole
    property is absent on the dangerous side, which is only reachable — with an
    increasing axis — when ``absent_rank == "above"``."""
    if axis is None:
        return None
    if endpoint is None:
        return spec.severity_when_absent if axis.absent_rank == "above" else None
    level = transition.from_rank if spec.invert_danger else transition.to_rank
    if level is None:
        return None
    try:
        rank = axis.ranks.index(level)
    except ValueError:
        return None
    return axis.severity_by_rank[rank]


def severity_for(
    spec: KindSpec,
    base: Optional[Property],
    head: Optional[Property],
    danger: Danger,
    axes: Sequence[AxisTransition],
) -> SurfaceSeverity:
    """Severity is a function of the rank an axis arrived at, never of the fact
    that it moved (A2 F2). The ``ordinal`` path is a one-axis special case of the
    ``lattice`` path: with one axis the two-strong-axis promotion can never fire.
    """
    if danger == "incomparable":
        return spec.severity_when_incomparable
    if danger != "increased":
        return None

    endpoint = base if spec.invert_danger else head
    increasing_order: AxisOrder = "less" if spec.invert_danger else "greater"
    axes_by_name = {axis.name: axis for axis in spec.axes}
    contributions = [
        _axis_severity(spec, axes_by_name.get(transition.axis), transition, endpoint)
        for transition in axes
        if transition.order == increasing_order
    ]
    if sum(1 for value in contributions if value in ("high", "critical")) >= 2:
        return "critical"
    return _maximum_severity(contributions)
