from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import Callable, Mapping, Optional, Sequence

from .compare import danger_for, flip_order, lattice_compare, ordinal_compare, severity_for
from .kind_specs import KIND_SPECS
from .model import KindSpec, Property, SurfaceSeverity, Transition, Unanalyzed

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class DiffCoverage:
    unanalyzed: list[Unanalyzed] = field(default_factory=list)
    blocks_absence_proof: Optional[Callable[[Transition], bool]] = None


def _utf8(value: str) -> bytes:
    return value.encode("utf-8")


def _index_buckets(
    properties: Sequence[Property],
    side: str,
    specs: Mapping[str, KindSpec],
    coverage: DiffCoverage,
) -> dict[str, list[Property]]:
    groups: dict[str, list[Property]] = {}
    for prop in properties:
        groups.setdefault(prop.key, []).append(prop)
    indexed: dict[str, list[Property]] = {}
    for key, group in groups.items():
        try:
            spec = specs[group[0].kind]
        except KeyError as error:
            raise ValueError(f"missing kind spec for {group[0].kind}") from error
        if len(group) == 1 or spec.key_may_repeat:
            indexed[key] = group
            continue
        for file in sorted({prop.evidence.file for prop in group}, key=_utf8):
            coverage.unanalyzed.append(
                Unanalyzed(
                    file=file,
                    side=side,  # type: ignore[arg-type]
                    reason="parse_error",
                    detail=f"duplicate property key '{key}'",
                    changed=False,
                )
            )
    return indexed


def _level_vector(prop: Property, spec: KindSpec) -> str:
    return json.dumps(
        [prop.levels.get(axis.name) for axis in spec.axes],
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _cancel_equal_vectors(
    base: Sequence[Property],
    head: Sequence[Property],
    spec: KindSpec,
) -> tuple[list[Property], list[Property]]:
    def sorted_by_vector(properties: Sequence[Property]) -> list[Property]:
        indexed = enumerate(properties)
        return [
            prop
            for _, prop in sorted(
                indexed,
                key=lambda item: (_utf8(_level_vector(item[1], spec)), item[0]),
            )
        ]

    sorted_base = sorted_by_vector(base)
    sorted_head = sorted_by_vector(head)
    left_base: list[Property] = []
    left_head: list[Property] = []
    base_index = 0
    head_index = 0
    while base_index < len(sorted_base) and head_index < len(sorted_head):
        base_vector = _utf8(_level_vector(sorted_base[base_index], spec))
        head_vector = _utf8(_level_vector(sorted_head[head_index], spec))
        if base_vector == head_vector:
            base_index += 1
            head_index += 1
        elif base_vector < head_vector:
            left_base.append(sorted_base[base_index])
            base_index += 1
        else:
            left_head.append(sorted_head[head_index])
            head_index += 1
    left_base.extend(sorted_base[base_index:])
    left_head.extend(sorted_head[head_index:])
    return left_base, left_head


def _classify(
    base: Optional[Property],
    head: Optional[Property],
    specs: Mapping[str, KindSpec],
    paired: bool = False,
    emit_unchanged: Optional[bool] = None,
) -> list[Transition]:
    endpoint = head if head is not None else base
    if endpoint is None:
        return []
    if base is not None and head is not None and base.kind != head.kind:
        raise ValueError(f"cannot compare {base.kind} with {head.kind}")
    try:
        spec = specs[endpoint.kind]
    except KeyError as error:
        raise ValueError(f"missing kind spec for {endpoint.kind}") from error
    if spec.comparator == "ordinal":
        order, axes = ordinal_compare(spec, base, head)
    else:
        order, axes = lattice_compare(spec, base, head)
    semantic_order = flip_order(order) if spec.invert_danger else order
    danger = danger_for(semantic_order)
    should_emit_unchanged = paired if emit_unchanged is None else emit_unchanged
    if danger == "unchanged" and not should_emit_unchanged:
        return []
    change = "added" if base is None else "removed" if head is None else "modified"
    key = endpoint.key
    if paired and base is not None and head is not None:
        key = min((base.key, head.key), key=_utf8)
    severity = severity_for(spec, base, head, danger, axes)
    return [
        Transition(
            kind=endpoint.kind,
            key=key,
            subject=endpoint.subject,
            label=endpoint.label,
            change=change,  # type: ignore[arg-type]
            danger=danger,
            severity=severity,
            axes=axes,
            from_level=axes[0].from_rank if len(axes) == 1 else None,
            to_level=axes[0].to_rank if len(axes) == 1 else None,
            confidence=endpoint.confidence,
            base_evidence=base.evidence if base is not None else None,
            head_evidence=head.evidence if head is not None else None,
            attrs=endpoint.attrs,
            paired=paired,
        )
    ]


def _relocation_pairs(
    base: Sequence[Property],
    head: Sequence[Property],
) -> tuple[list[tuple[Property, Property]], list[Property], list[Property]]:
    def relocation_key(prop: Property) -> Optional[str]:
        if prop.pairing_scope is None or prop.discriminator == "":
            return None
        return f"{prop.kind}\0{prop.pairing_scope}\0{prop.discriminator}"

    base_groups: dict[str, list[Property]] = {}
    head_groups: dict[str, list[Property]] = {}
    for prop in base:
        key = relocation_key(prop)
        if key is not None:
            base_groups.setdefault(key, []).append(prop)
    for prop in head:
        key = relocation_key(prop)
        if key is not None:
            head_groups.setdefault(key, []).append(prop)

    pairs: list[tuple[Property, Property]] = []
    used_base: set[int] = set()
    used_head: set[int] = set()
    for key in sorted(base_groups.keys() & head_groups.keys(), key=_utf8):
        base_group = base_groups[key]
        head_group = head_groups[key]
        if len(base_group) == 1 and len(head_group) == 1:
            pairs.append((base_group[0], head_group[0]))
            used_base.add(id(base_group[0]))
            used_head.add(id(head_group[0]))
    return (
        pairs,
        [prop for prop in base if id(prop) not in used_base],
        [prop for prop in head if id(prop) not in used_head],
    )


def _residual_pairs(
    base: Sequence[Property],
    head: Sequence[Property],
    specs: Mapping[str, KindSpec],
) -> tuple[list[tuple[Property, Property]], list[Property], list[Property]]:
    def scope_key(prop: Property) -> Optional[str]:
        spec = specs.get(prop.kind)
        if spec is None or not spec.allow_residual_pairing or prop.pairing_scope is None:
            return None
        return f"{prop.kind}\0{prop.pairing_scope}"

    base_groups: dict[str, list[Property]] = {}
    head_groups: dict[str, list[Property]] = {}
    for prop in base:
        scope = scope_key(prop)
        if scope is not None:
            base_groups.setdefault(scope, []).append(prop)
    for prop in head:
        scope = scope_key(prop)
        if scope is not None:
            head_groups.setdefault(scope, []).append(prop)

    pairs: list[tuple[Property, Property]] = []
    used_base: set[int] = set()
    used_head: set[int] = set()
    for scope in sorted(base_groups.keys() & head_groups.keys(), key=_utf8):
        base_group = base_groups[scope]
        head_group = head_groups[scope]
        if len(base_group) == 1 and len(head_group) == 1:
            pairs.append((base_group[0], head_group[0]))
            used_base.add(id(base_group[0]))
            used_head.add(id(head_group[0]))
    return (
        pairs,
        [prop for prop in base if id(prop) not in used_base],
        [prop for prop in head if id(prop) not in used_head],
    )


def _default_blocks_absence_proof(
    transition: Transition,
    unanalyzed: Sequence[Unanalyzed],
) -> bool:
    if transition.change == "added":
        return any(item.side == "base" for item in unanalyzed)
    if transition.change == "removed":
        return any(item.side == "head" for item in unanalyzed)
    return False


def diff_properties(
    base_properties: Sequence[Property],
    head_properties: Sequence[Property],
    specs: Sequence[KindSpec] = KIND_SPECS,
    coverage: Optional[DiffCoverage] = None,
) -> list[Transition]:
    active_coverage = coverage if coverage is not None else DiffCoverage()
    by_kind = {spec.kind: spec for spec in specs}
    base = _index_buckets(base_properties, "base", by_kind, active_coverage)
    head = _index_buckets(head_properties, "head", by_kind, active_coverage)
    output: list[Transition] = []
    unmatched_base: list[Property] = []
    unmatched_head: list[Property] = []

    for key in sorted(base.keys() & head.keys(), key=_utf8):
        base_group = base[key]
        head_group = head[key]
        try:
            spec = by_kind[base_group[0].kind]
        except KeyError as error:
            raise ValueError(f"missing kind spec for {base_group[0].kind}") from error
        if len(base_group) == 1 and len(head_group) == 1:
            output.extend(_classify(base_group[0], head_group[0], by_kind))
            continue
        left_base, left_head = _cancel_equal_vectors(base_group, head_group, spec)
        if len(left_base) == 1 and len(left_head) == 1:
            output.extend(_classify(left_base[0], left_head[0], by_kind))
        else:
            unmatched_base.extend(left_base)
            unmatched_head.extend(left_head)
    for key, group in base.items():
        if key not in head:
            unmatched_base.extend(group)
    for key, group in head.items():
        if key not in base:
            unmatched_head.extend(group)

    relocation_pairs, left_base, left_head = _relocation_pairs(
        unmatched_base, unmatched_head
    )
    for base_prop, head_prop in relocation_pairs:
        output.extend(
            _classify(base_prop, head_prop, by_kind, paired=True, emit_unchanged=False)
        )
    pairs, left_base, left_head = _residual_pairs(left_base, left_head, by_kind)
    for base_prop, head_prop in pairs:
        output.extend(_classify(base_prop, head_prop, by_kind, paired=True))
    for prop in left_base:
        output.extend(_classify(prop, None, by_kind))
    for prop in left_head:
        output.extend(_classify(None, prop, by_kind))

    for index, transition in enumerate(output):
        blocked = (
            active_coverage.blocks_absence_proof(transition)
            if active_coverage.blocks_absence_proof is not None
            else _default_blocks_absence_proof(transition, active_coverage.unanalyzed)
        )
        if blocked:
            output[index] = replace(transition, danger="unknown", severity=None)

    def sort_key(transition: Transition) -> tuple[int, bytes, bytes]:
        severity_rank = -1 if transition.severity is None else SEVERITY_RANK[transition.severity]
        return (-severity_rank, _utf8(transition.kind), _utf8(transition.key))

    return sorted(output, key=sort_key)
