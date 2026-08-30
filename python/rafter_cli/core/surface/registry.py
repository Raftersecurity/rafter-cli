"""The extractor registry. Mirrors ``node/src/core/surface/registry.ts``.

W6/W7/W8 each append their extractor here and remove the stub; nothing else in
the CLI knows which extractors exist.
"""
from __future__ import annotations

from typing import Mapping, Protocol, Sequence

from .model import ExtractResult
from .stub_extractor import stub_extractor


class Extractor(Protocol):
    id: str
    version: int
    kinds: Sequence[str]

    def candidate(self, path: str, size_bytes: int) -> bool: ...

    def extract(self, files: Mapping[str, str]) -> ExtractResult: ...


EXTRACTORS: tuple[Extractor, ...] = (stub_extractor,)
