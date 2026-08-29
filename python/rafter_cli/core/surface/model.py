from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Mapping, Optional, Sequence

SurfaceSeverity = Optional[Literal["low", "medium", "high", "critical"]]
Confidence = Literal["certain"]
Change = Literal["added", "removed", "modified"]
Danger = Literal["increased", "decreased", "unchanged", "incomparable", "unknown"]
AxisOrder = Literal["equal", "greater", "less", "unknown"]
UnanalyzedReason = Literal[
    "parse_error",
    "unsupported_syntax",
    "too_large",
    "too_many_candidates",
    "binary",
    "symlink",
    "timeout",
]
AttrValue = Optional[str | int | bool]


@dataclass(frozen=True, slots=True)
class Evidence:
    file: str
    line: Optional[int]


@dataclass(frozen=True, slots=True)
class Property:
    kind: str
    key: str
    subject: str
    levels: Mapping[str, Optional[str]]
    label: str
    attrs: Mapping[str, AttrValue]
    evidence: Evidence
    confidence: Confidence = "certain"
    pairing_scope: Optional[str] = None


@dataclass(frozen=True, slots=True)
class AxisSpec:
    name: str
    ranks: Sequence[str]
    absent_rank: Literal["below", "above"]
    severity_at_top: SurfaceSeverity


@dataclass(frozen=True, slots=True)
class KindSpec:
    kind: str
    comparator: Literal["ordinal", "lattice"]
    axes: Sequence[AxisSpec]
    display: str
    invert_danger: bool = False
    allow_residual_pairing: bool = False
    severity_by_level: Optional[Sequence[SurfaceSeverity]] = None
    severity_when_absent: SurfaceSeverity = None
    severity_when_incomparable: SurfaceSeverity = None


@dataclass(frozen=True, slots=True)
class AxisTransition:
    axis: str
    from_rank: Optional[str]
    to_rank: Optional[str]
    order: AxisOrder


@dataclass(frozen=True, slots=True)
class Transition:
    kind: str
    key: str
    subject: str
    change: Change
    danger: Danger
    severity: SurfaceSeverity
    axes: Sequence[AxisTransition]
    from_level: Optional[str]
    to_level: Optional[str]
    confidence: Confidence
    base_evidence: Optional[Evidence]
    head_evidence: Optional[Evidence]
    attrs: Mapping[str, AttrValue]
    paired: bool


@dataclass(frozen=True, slots=True)
class Unanalyzed:
    file: str
    side: Literal["base", "head"]
    reason: UnanalyzedReason
    detail: str
    changed: bool


@dataclass(frozen=True, slots=True)
class ExtractResult:
    properties: list[Property] = field(default_factory=list)
    unanalyzed: list[Unanalyzed] = field(default_factory=list)
