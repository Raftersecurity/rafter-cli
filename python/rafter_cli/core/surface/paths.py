"""Repo-relative path helpers shared by every extractor, so that W6 and W8 cannot
each reinvent them with different spellings for the repo root (A2 F10)."""

from __future__ import annotations


def parent_scope(path: str) -> str:
    """POSIX dirname of a repo-relative path, with the repo root spelled ``""``.

    Never ``"."``, never ``"/"``, never a trailing slash. The empty string is a
    valid scope and is NOT ``None``: callers gating on a scope must test
    ``is not None``, never truthiness.
    """
    index = path.rfind("/")
    return "" if index <= 0 else path[:index]
