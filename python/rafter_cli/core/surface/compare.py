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


def severity_for(
    spec: KindSpec,
    base: Optional[Property],
    head: Optional[Property],
    danger: Danger,
    axes: Sequence[AxisTransition],
) -> SurfaceSeverity:
    if danger == "incomparable":
        return spec.severity_when_incomparable
    if danger != "increased":
        return None

    if spec.comparator == "ordinal":
        axis = spec.axes[0]
        arrival = base if spec.invert_danger else head
        if arrival is None:
            return spec.severity_when_absent if axis.absent_rank == "above" else None
        level = arrival.levels.get(axis.name)
        if level is None:
            return None
        try:
            rank = axis.ranks.index(level)  # type: ignore[union-attr]
        except ValueError:
            return None
        if spec.severity_by_level is None:
            return None
        return spec.severity_by_level[rank]

    increasing_order: AxisOrder = "less" if spec.invert_danger else "greater"
    increasing_axes = [axis for axis in axes if axis.order == increasing_order]
    axes_by_name = {axis.name: axis for axis in spec.axes}
    severity = _maximum_severity(
        [axes_by_name[transition.axis].severity_at_top for transition in increasing_axes]
    )
    top_count = sum(
        1
        for transition in increasing_axes
        if (transition.from_rank if spec.invert_danger else transition.to_rank)
        == axes_by_name[transition.axis].ranks[-1]
    )
    return "critical" if top_count >= 2 else severity
