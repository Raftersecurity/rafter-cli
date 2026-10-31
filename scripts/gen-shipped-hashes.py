#!/usr/bin/env python3
"""Regenerate the shipped-hashes table from the published npm and PyPI packages.

`rafter agent init` overwrites a file it installed only when it can prove the
file still holds rafter's own content. One proof is the install manifest
(<root>/.rafter/installed.json); the other is this table: the sha256 of every
bundled resource in every published release, so installs made before the
manifest existed can still be told apart from files the user edited.

The table is derived data. Do not edit it by hand; run this script after each
release is published (see PUBLISHING.md) and commit the result.

    python3 scripts/gen-shipped-hashes.py            # rewrite both copies
    python3 scripts/gen-shipped-hashes.py --check    # exit 1 if stale

Writes byte-identical copies to node/resources/shipped-hashes.json and
python/rafter_cli/resources/shipped-hashes.json. Standard library only.

Keys are resource paths relative to resources/ (e.g. "skills/rafter/SKILL.md").
A key with a "#<variant>" suffix holds hashes of a TRANSFORMED resource, for
artifacts init writes after changing the bytes:

    agents/rafter.md#cursor   .cursor/agents/rafter.md, the sub-agent with its
                              `tools:` frontmatter line stripped. Both the Node
                              and the (pre-fix) Python strip are hashed, since
                              they differed by one blank line.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

NPM_PACKAGE = "@rafter-security/cli"
PYPI_PACKAGE = "rafter-cli"
MIN_VERSION = (0, 8, 0)

REPO = Path(__file__).resolve().parent.parent
OUTPUTS = [
    REPO / "node" / "resources" / "shipped-hashes.json",
    REPO / "python" / "rafter_cli" / "resources" / "shipped-hashes.json",
]


def _version_tuple(v: str) -> tuple[int, ...] | None:
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", v)
    return tuple(int(x) for x in m.groups()) if m else None


def _get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as resp:
        return resp.read()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strip_tools_node(content: str) -> str:
    """Node's stripToolsFromFrontmatter: drop `tools:` lines, rejoin."""
    if not content.startswith("---\n"):
        return content
    end = content.find("\n---", 4)
    if end == -1:
        return content
    fm, body = content[4:end], content[end:]
    cleaned = "\n".join(line for line in fm.split("\n") if not re.match(r"^tools:\s", line))
    return f"---\n{cleaned}{body}"


def strip_tools_python_legacy(content: str) -> str:
    """Python's strip through 0.11.x, which left a blank line when `tools:` was last."""
    if not content.startswith("---\n"):
        return content
    end = content.find("\n---", 4)
    if end == -1:
        return content
    fm, body = content[4:end], content[end:]
    cleaned = re.sub(r"^tools:\s.*$\n?", "", fm, flags=re.MULTILINE)
    return f"---\n{cleaned}{body}"


def _derived(rel: str, data: bytes) -> dict[str, set[str]]:
    if rel != "agents/rafter.md":
        return {}
    text = data.decode("utf-8")
    return {
        "agents/rafter.md#cursor": {
            _sha(strip_tools_node(text).encode("utf-8")),
            _sha(strip_tools_python_legacy(text).encode("utf-8")),
        }
    }


def _add(table: dict[str, set[str]], rel: str, data: bytes) -> None:
    if rel.endswith("__init__.py") or "__pycache__" in rel:
        return
    table.setdefault(rel, set()).add(_sha(data))
    for key, shas in _derived(rel, data).items():
        table.setdefault(key, set()).update(shas)


def npm_releases() -> list[tuple[str, str]]:
    meta = json.loads(_get(f"https://registry.npmjs.org/{NPM_PACKAGE.replace('/', '%2F')}"))
    out = []
    for v, info in meta.get("versions", {}).items():
        t = _version_tuple(v)
        if t and t >= MIN_VERSION:
            out.append((v, info["dist"]["tarball"]))
    return sorted(out, key=lambda x: _version_tuple(x[0]))


def pypi_releases() -> list[tuple[str, str]]:
    meta = json.loads(_get(f"https://pypi.org/pypi/{PYPI_PACKAGE}/json"))
    out = []
    for v, files in meta.get("releases", {}).items():
        t = _version_tuple(v)
        if not t or t < MIN_VERSION:
            continue
        wheels = [f["url"] for f in files if f["filename"].endswith(".whl") and not f.get("yanked")]
        if wheels:
            out.append((v, wheels[0]))
    return sorted(out, key=lambda x: _version_tuple(x[0]))


def hash_npm(url: str, table: dict[str, set[str]]) -> None:
    prefix = "package/resources/"
    with tarfile.open(fileobj=io.BytesIO(_get(url)), mode="r:gz") as tar:
        for member in tar.getmembers():
            if member.isfile() and member.name.startswith(prefix):
                f = tar.extractfile(member)
                if f is not None:
                    _add(table, member.name[len(prefix):], f.read())


def hash_pypi(url: str, table: dict[str, set[str]]) -> None:
    prefix = "rafter_cli/resources/"
    with zipfile.ZipFile(io.BytesIO(_get(url))) as whl:
        for name in whl.namelist():
            if name.startswith(prefix) and not name.endswith("/"):
                _add(table, name[len(prefix):], whl.read(name))


def build() -> str:
    table: dict[str, set[str]] = {}
    releases: list[str] = []
    for v, url in npm_releases():
        print(f"npm  {v}", file=sys.stderr)
        hash_npm(url, table)
        releases.append(f"npm:{v}")
    for v, url in pypi_releases():
        print(f"pypi {v}", file=sys.stderr)
        hash_pypi(url, table)
        releases.append(f"pypi:{v}")
    doc = {
        "schema": 1,
        "generatedBy": "scripts/gen-shipped-hashes.py",
        "releases": releases,
        "files": {k: sorted(v) for k, v in sorted(table.items())},
    }
    return json.dumps(doc, indent=1) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="exit 1 if a committed copy differs from the registries")
    args = ap.parse_args()
    text = build()
    if args.check:
        stale = [p for p in OUTPUTS if not p.exists() or p.read_text(encoding="utf-8") != text]
        for p in stale:
            print(f"STALE: {p.relative_to(REPO)} (run scripts/gen-shipped-hashes.py)", file=sys.stderr)
        return 1 if stale else 0
    for p in OUTPUTS:
        p.write_bytes(text.encode("utf-8"))
        print(f"wrote {p.relative_to(REPO)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
