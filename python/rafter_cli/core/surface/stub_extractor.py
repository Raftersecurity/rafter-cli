"""TEMPORARY — W4 scaffolding.

The CLI shell, renderers, and exit codes (W4) ship before the real extractors
(W6 ``container.port``, W7 ``iam.allow``/``iam.deny``, W8
``pkg.lifecycle_script``). This extractor reads ``*.surface-stub.json`` files
that state their properties directly, so the whole pipeline — tree reads,
differ, coverage, exit codes — can be exercised end to end without waiting on
Wave 2.

To retire it: delete this file and drop it from ``EXTRACTORS`` in
``registry.py``. Nothing else references it.

Mirrors ``node/src/core/surface/stub-extractor.ts``.
"""
from __future__ import annotations

import json
from typing import Any, Mapping

from .kind_specs import KIND_SPEC_BY_KIND
from .model import Evidence, ExtractResult, Property, Unanalyzed

STUB_SUFFIX = ".surface-stub.json"


def _to_property(file: str, raw: Any) -> Property:
    if not isinstance(raw, dict):
        raise ValueError("property entry is not an object")
    kind = raw["kind"]
    if kind not in KIND_SPEC_BY_KIND:
        raise ValueError(f"unknown kind {kind!r}")
    return Property(
        kind=kind,
        key=raw["key"],
        discriminator=raw.get("discriminator", ""),
        subject=raw["subject"],
        levels=dict(raw["levels"]),
        label=raw["label"],
        attrs=dict(raw.get("attrs", {})),
        evidence=Evidence(file=file, line=raw.get("line")),
        confidence="certain",
        pairing_scope=raw.get("pairingScope"),
    )


class StubExtractor:
    id = "stub"
    version = 1
    kinds = ("container.port", "iam.allow", "iam.deny", "pkg.lifecycle_script")

    @staticmethod
    def candidate(path: str, size_bytes: int = 0) -> bool:
        return path.endswith(STUB_SUFFIX)

    @staticmethod
    def extract(files: Mapping[str, str]) -> ExtractResult:
        result = ExtractResult()
        for file in sorted(files):
            try:
                document = json.loads(files[file])
            except ValueError:
                # The caller overwrites `side` and `changed`; both are its business.
                result.unanalyzed.append(
                    Unanalyzed(
                        file=file,
                        side="base",
                        reason="parse_error",
                        detail="stub document is not valid JSON",
                        changed=False,
                    )
                )
                continue
            if not isinstance(document, dict):
                result.unanalyzed.append(
                    Unanalyzed(
                        file=file,
                        side="base",
                        reason="parse_error",
                        detail="stub document is not an object",
                        changed=False,
                    )
                )
                continue
            for entry in document.get("unanalyzed", []):
                if not isinstance(entry, dict):
                    continue
                result.unanalyzed.append(
                    Unanalyzed(
                        file=file,
                        side="base",
                        reason=entry.get("reason", "parse_error"),
                        detail=entry.get("detail", ""),
                        changed=False,
                    )
                )
            for entry in document.get("properties", []):
                result.properties.append(_to_property(file, entry))
        return result


stub_extractor = StubExtractor()
