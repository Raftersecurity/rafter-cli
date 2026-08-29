from __future__ import annotations

import json
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any

from .model import KindSpec, Transition, Unanalyzed

MAX_SAFE_INTEGER = 2**53 - 1


def _normalize_string(value: str) -> str:
    repaired: list[str] = []
    index = 0
    while index < len(value):
        codepoint = ord(value[index])
        if 0xD800 <= codepoint <= 0xDBFF:
            if index + 1 < len(value) and 0xDC00 <= ord(value[index + 1]) <= 0xDFFF:
                high = codepoint - 0xD800
                low = ord(value[index + 1]) - 0xDC00
                repaired.append(chr(0x10000 + (high << 10) + low))
                index += 2
                continue
            repaired.append("\ufffd")
        elif 0xDC00 <= codepoint <= 0xDFFF:
            repaired.append("\ufffd")
        else:
            repaired.append(value[index])
        index += 1
    return unicodedata.normalize("NFC", "".join(repaired))


def _canonicalize(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return _normalize_string(value)
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise TypeError("canonical JSON accepts only safe integers")
        return value
    if isinstance(value, float):
        raise TypeError("canonical JSON accepts no floats")
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for key in sorted(value):
            if not isinstance(key, str):
                raise TypeError("canonical JSON object keys must be strings")
            if not key or any(ord(character) > 0x7F for character in key):
                raise TypeError(f"non-ASCII object key: {key}")
            output[key] = _canonicalize(value[key])
        return output
    if isinstance(value, Sequence):
        return [_canonicalize(item) for item in value]
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    return json.dumps(
        _canonicalize(value),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def sort_unanalyzed(items: Sequence[Unanalyzed]) -> list[Unanalyzed]:
    return sorted(items, key=lambda item: (item.file.encode("utf-8"), item.side))


def transition_to_wire(transition: Transition) -> dict[str, Any]:
    return {
        "kind": transition.kind,
        "key": transition.key,
        "subject": transition.subject,
        "change": transition.change,
        "danger": transition.danger,
        "severity": transition.severity,
        "axes": [
            {
                "axis": axis.axis,
                "from": axis.from_rank,
                "to": axis.to_rank,
                "order": axis.order,
            }
            for axis in transition.axes
        ],
        "from": transition.from_level,
        "to": transition.to_level,
        "confidence": transition.confidence,
        "base_evidence": (
            None
            if transition.base_evidence is None
            else {"file": transition.base_evidence.file, "line": transition.base_evidence.line}
        ),
        "head_evidence": (
            None
            if transition.head_evidence is None
            else {"file": transition.head_evidence.file, "line": transition.head_evidence.line}
        ),
        "attrs": dict(transition.attrs),
        "paired": transition.paired,
    }


def kind_spec_to_wire(spec: KindSpec) -> dict[str, Any]:
    output: dict[str, Any] = {
        "kind": spec.kind,
        "comparator": spec.comparator,
        "axes": [
            {
                "name": axis.name,
                "ranks": list(axis.ranks),
                "absentRank": axis.absent_rank,
                "severityAtTop": axis.severity_at_top,
            }
            for axis in spec.axes
        ],
        "invertDanger": spec.invert_danger,
        "allowResidualPairing": spec.allow_residual_pairing,
        "display": spec.display,
    }
    if spec.severity_by_level is not None:
        output["severityByLevel"] = list(spec.severity_by_level)
    if spec.severity_when_absent is not None:
        output["severityWhenAbsent"] = spec.severity_when_absent
    if spec.severity_when_incomparable is not None:
        output["severityWhenIncomparable"] = spec.severity_when_incomparable
    return output


def kind_specs_to_wire(specs: Sequence[KindSpec]) -> list[dict[str, Any]]:
    return [kind_spec_to_wire(spec) for spec in specs]
