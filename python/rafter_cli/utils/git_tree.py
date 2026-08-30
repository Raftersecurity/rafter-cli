"""Hardened Git plumbing for reading attack-surface candidates from two trees."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal, Protocol, Sequence

from rafter_cli.core.surface.model import Unanalyzed, UnanalyzedReason

EMPTY_TREE_OID = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
MAX_FILE_BYTES = 1024 * 1024
MAX_CANDIDATES = 2000
BINARY_SNIFF_BYTES = 8 * 1024
EXTRACTION_TIMEOUT_SECONDS = 20.0
MAX_BATCH_BYTES = 32 * 1024 * 1024

OID_RE = re.compile(r"^[0-9a-f]{40}$")


class GitRunner(Protocol):
    def __call__(
        self,
        args: list[str],
        *,
        cwd: Path,
        input_data: bytes | None = None,
        timeout: float | None = None,
    ) -> bytes: ...


@dataclass(frozen=True, slots=True)
class TreeEntry:
    """One committed-tree or working-tree path."""

    path: str
    raw_path: str
    mode: str
    type: Literal["blob", "commit"]
    oid: str
    size_bytes: int


@dataclass(slots=True)
class CandidateReadResult:
    files: dict[str, str] = field(default_factory=dict)
    unanalyzed: list[Unanalyzed] = field(default_factory=list)


class InvalidRefError(ValueError):
    code = "invalid_ref"
    exit_code = 2

    def __init__(self, ref: str) -> None:
        super().__init__(f"Invalid git ref: {ref!r}")


class RefResolutionError(RuntimeError):
    code = "base_unresolved"
    exit_code = 3

    def __init__(self, ref: str) -> None:
        super().__init__(f"Could not resolve git ref to a commit: {ref!r}")


def _default_git_runner(
    args: list[str],
    *,
    cwd: Path,
    input_data: bytes | None = None,
    timeout: float | None = None,
) -> bytes:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        input=input_data,
        check=True,
        capture_output=True,
        shell=False,
        timeout=timeout,
    ).stdout


def validate_ref(ref: str) -> None:
    if not ref or ref.startswith("-") or "\0" in ref:
        raise InvalidRefError(ref)


def _assert_oid(oid: str) -> None:
    if not OID_RE.fullmatch(oid):
        raise ValueError(f"Expected a resolved 40-hex git object ID, got {oid!r}")


def _decode_path(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")


def _normalize_path(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def _split_nul(output: bytes) -> list[bytes]:
    if output and not output.endswith(b"\0"):
        raise ValueError("Malformed git output: missing NUL terminator")
    return output.split(b"\0")[:-1] if output else []


class BaseTreeReader:
    def __init__(
        self,
        repo_path: Path | str,
        *,
        runner: GitRunner | None = None,
        max_file_bytes: int = MAX_FILE_BYTES,
        max_candidates: int = MAX_CANDIDATES,
        timeout_seconds: float = EXTRACTION_TIMEOUT_SECONDS,
        max_batch_bytes: int = MAX_BATCH_BYTES,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.repo_path = Path(repo_path)
        self._runner = runner or _default_git_runner
        self.max_file_bytes = max_file_bytes
        self.max_candidates = max_candidates
        self.timeout_seconds = timeout_seconds
        self.max_batch_bytes = max_batch_bytes
        self.clock = clock

    @staticmethod
    def validate_ref(ref: str) -> None:
        validate_ref(ref)

    def resolve_ref(self, ref: str) -> str:
        validate_ref(ref)
        resolved = self._try_resolve_commit(ref)
        if resolved is not None:
            return resolved

        parent = self._parent_request_target(ref)
        if parent is not None:
            parent_oid = self._try_resolve_commit(parent)
            if parent_oid is not None and self._is_root_commit(parent_oid):
                return EMPTY_TREE_OID

        if self._try_resolve_commit("HEAD") is None:
            self._run(["rev-parse", "--git-dir"])
            return EMPTY_TREE_OID
        raise RefResolutionError(ref)

    def list_tree(self, oid: str, timeout: float | None = None) -> list[TreeEntry]:
        _assert_oid(oid)
        output = self._run(["ls-tree", "-r", "-z", "--long", oid], timeout=timeout)
        return [
            self._parse_tree_entry(record) for record in _split_nul(output) if record
        ]

    def list_work_tree(self, timeout: float | None = None) -> list[TreeEntry]:
        output = self._run(
            ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            timeout=timeout,
        )
        entries: list[TreeEntry] = []
        for raw_field in _split_nul(output):
            if not raw_field:
                continue
            inspected = self._inspect_work_tree_path(_decode_path(raw_field))
            if inspected is not None:
                entries.append(inspected)
        return entries

    def changed_paths(self, base_oid: str, head_oid: str | None = None) -> set[str]:
        _assert_oid(base_oid)
        if head_oid is not None:
            _assert_oid(head_oid)
        args = [
            "diff",
            "--name-status",
            "-z",
            "--no-renames",
            "--end-of-options",
            base_oid,
        ]
        if head_oid is not None:
            args.append(head_oid)
        changed = self._parse_name_status(self._run(args))
        if head_oid is None:
            untracked = self._run(["ls-files", "--others", "--exclude-standard", "-z"])
            changed.update(
                _normalize_path(_decode_path(field))
                for field in _split_nul(untracked)
                if field
            )
        return changed

    def read_blob(self, oid: str, timeout: float | None = None) -> bytes:
        _assert_oid(oid)
        return self._run(["cat-file", "blob", oid], timeout=timeout)

    def read_at(
        self, oid: str, requested_path: str, timeout: float | None = None
    ) -> bytes:
        _assert_oid(oid)
        normalized_path = _normalize_path(requested_path)
        matches = [
            entry
            for entry in self.list_tree(oid, timeout=timeout)
            if entry.path == normalized_path
        ]
        if len(matches) != 1:
            if not matches:
                raise ValueError(f"Path is absent from tree: {requested_path!r}")
            raise ValueError(f"Multiple tree paths normalize to: {normalized_path!r}")
        entry = matches[0]
        if entry.mode in {"120000", "160000"} or entry.type == "commit":
            raise ValueError(
                f"Refusing to read symlink or submodule: {normalized_path!r}"
            )
        return self.read_blob(entry.oid, timeout=timeout)

    def read_blobs(
        self,
        oids: Sequence[str],
        timeout: float | None = None,
        deadline: float | None = None,
    ) -> dict[str, bytes]:
        for oid in oids:
            _assert_oid(oid)
        if not oids:
            return {}
        try:
            output = self._run(
                ["cat-file", "--batch"],
                input_data=("\n".join(oids) + "\n").encode("ascii"),
                timeout=timeout,
            )
            if deadline is not None and self._expired(deadline):
                raise subprocess.TimeoutExpired("git cat-file --batch", timeout)
            return self._parse_batch_blobs(oids, output)
        except subprocess.TimeoutExpired:
            raise
        except (OSError, subprocess.SubprocessError, ValueError):
            blobs: dict[str, bytes] = {}
            for oid in oids:
                remaining = timeout if deadline is None else self._remaining(deadline)
                blobs[oid] = self.read_blob(oid, timeout=remaining)
            return blobs

    def read_tree_candidates(
        self,
        oid: str,
        candidate: Callable[[str, int], bool],
        changed_paths: set[str] | frozenset[str] = frozenset(),
        side: Literal["base", "head"] = "base",
    ) -> CandidateReadResult:
        deadline = self.clock() + self.timeout_seconds
        try:
            entries = self.list_tree(oid, timeout=self._remaining(deadline))
        except subprocess.TimeoutExpired:
            return self._timeout_result(side, changed_paths)
        candidates = [
            entry for entry in entries if candidate(entry.path, entry.size_bytes)
        ]
        limited = self._enforce_candidate_limit(candidates, side, changed_paths)
        if limited is not None:
            return limited

        result = CandidateReadResult()
        readable: list[TreeEntry] = []
        collision_paths = self._canonical_collision_paths(candidates)
        for index, entry in enumerate(candidates):
            if self._expired(deadline):
                self._mark_remaining(
                    result, candidates[index:], side, "timeout", changed_paths
                )
                break
            if entry.path in collision_paths:
                result.unanalyzed.append(
                    self._unanalyzed(
                        entry.path,
                        side,
                        "parse_error",
                        "multiple repository paths normalize to the same NFC path",
                        changed_paths,
                    )
                )
            elif entry.mode in {"120000", "160000"} or entry.type == "commit":
                result.unanalyzed.append(
                    self._unanalyzed(
                        entry.path,
                        side,
                        "symlink",
                        "symlinks, submodules, and nonregular files are not read",
                        changed_paths,
                    )
                )
            elif entry.size_bytes > self.max_file_bytes:
                result.unanalyzed.append(
                    self._unanalyzed(
                        entry.path,
                        side,
                        "too_large",
                        f"file is {entry.size_bytes} bytes; limit is {self.max_file_bytes}",
                        changed_paths,
                    )
                )
            else:
                readable.append(entry)

        if not readable or any(item.reason == "timeout" for item in result.unanalyzed):
            return result
        cursor = 0
        while cursor < len(readable):
            batch: list[TreeEntry] = []
            batch_bytes = 0
            while cursor + len(batch) < len(readable):
                entry = readable[cursor + len(batch)]
                if batch and batch_bytes + entry.size_bytes > self.max_batch_bytes:
                    break
                batch.append(entry)
                batch_bytes += entry.size_bytes
            try:
                blobs = self.read_blobs(
                    list(dict.fromkeys(entry.oid for entry in batch)),
                    timeout=self._remaining(deadline),
                    deadline=deadline,
                )
                for entry in batch:
                    content = blobs.get(entry.oid)
                    if content is None:
                        raise ValueError(f"git cat-file omitted {entry.oid}")
                    self._accept_content(
                        result, entry.path, side, content, changed_paths
                    )
                cursor += len(batch)
            except subprocess.TimeoutExpired:
                self._mark_remaining(
                    result,
                    readable[cursor:],
                    side,
                    "timeout",
                    changed_paths,
                    "20-second extraction budget expired",
                )
                break
            except (OSError, subprocess.SubprocessError, ValueError):
                self._mark_remaining(
                    result,
                    readable[cursor:],
                    side,
                    "parse_error",
                    changed_paths,
                    "could not read git blob",
                )
                break
        return result

    def read_work_tree_candidates(
        self,
        candidate: Callable[[str, int], bool],
        changed_paths: set[str] | frozenset[str] = frozenset(),
    ) -> CandidateReadResult:
        side: Literal["head"] = "head"
        deadline = self.clock() + self.timeout_seconds
        try:
            entries = self.list_work_tree(timeout=self._remaining(deadline))
        except subprocess.TimeoutExpired:
            return self._timeout_result(side, changed_paths)
        candidates = [
            entry for entry in entries if candidate(entry.path, entry.size_bytes)
        ]
        limited = self._enforce_candidate_limit(candidates, side, changed_paths)
        if limited is not None:
            return limited

        result = CandidateReadResult()
        collision_paths = self._canonical_collision_paths(candidates)
        for index, entry in enumerate(candidates):
            if self._expired(deadline):
                self._mark_remaining(
                    result, candidates[index:], side, "timeout", changed_paths
                )
                break
            if entry.path in collision_paths:
                result.unanalyzed.append(
                    self._unanalyzed(
                        entry.path,
                        side,
                        "parse_error",
                        "multiple repository paths normalize to the same NFC path",
                        changed_paths,
                    )
                )
                continue
            if entry.mode in {"120000", "160000"} or entry.type == "commit":
                result.unanalyzed.append(
                    self._unanalyzed(
                        entry.path,
                        side,
                        "symlink",
                        "symlinks, submodules, and nonregular files are not read",
                        changed_paths,
                    )
                )
                continue
            if entry.size_bytes > self.max_file_bytes:
                result.unanalyzed.append(
                    self._unanalyzed(
                        entry.path,
                        side,
                        "too_large",
                        f"file is {entry.size_bytes} bytes; limit is {self.max_file_bytes}",
                        changed_paths,
                    )
                )
                continue
            try:
                content = self._read_contained_file(entry.raw_path)
                if self._expired(deadline):
                    self._mark_remaining(
                        result, candidates[index:], side, "timeout", changed_paths
                    )
                    break
                if len(content) > self.max_file_bytes:
                    result.unanalyzed.append(
                        self._unanalyzed(
                            entry.path,
                            side,
                            "too_large",
                            f"file grew beyond the {self.max_file_bytes}-byte limit while reading",
                            changed_paths,
                        )
                    )
                else:
                    self._accept_content(
                        result, entry.path, side, content, changed_paths
                    )
            except OSError:
                reason: UnanalyzedReason = (
                    "symlink"
                    if self._path_contains_symlink(entry.raw_path)
                    else "parse_error"
                )
                detail = (
                    "path contains a symlink"
                    if reason == "symlink"
                    else "could not safely read working-tree file"
                )
                result.unanalyzed.append(
                    self._unanalyzed(
                        entry.path,
                        side,
                        reason,
                        detail,
                        changed_paths,
                    )
                )
        return result

    def is_shallow(self) -> bool:
        return (
            self._run(["rev-parse", "--is-shallow-repository"]).decode().strip()
            == "true"
        )

    def _try_resolve_commit(self, ref: str) -> str | None:
        try:
            oid = (
                self._run(
                    [
                        "rev-parse",
                        "--verify",
                        "--quiet",
                        "--end-of-options",
                        f"{ref}^{{commit}}",
                    ]
                )
                .decode("ascii")
                .strip()
            )
            _assert_oid(oid)
            return oid
        except subprocess.CalledProcessError as error:
            if error.returncode == 1:
                return None
            raise

    @staticmethod
    def _parent_request_target(ref: str) -> str | None:
        if ref.endswith(("^1", "~1")):
            return ref[:-2]
        if ref.endswith("^"):
            return ref[:-1]
        return None

    def _is_root_commit(self, oid: str) -> bool:
        fields = self._run(["rev-list", "--parents", "-n", "1", oid]).decode().split()
        return fields == [oid]

    @staticmethod
    def _parse_tree_entry(record: bytes) -> TreeEntry:
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, raw_oid, raw_size = metadata.split()
            oid = raw_oid.decode("ascii")
            _assert_oid(oid)
            decoded_type = object_type.decode("ascii")
            if decoded_type not in {"blob", "commit"}:
                raise ValueError(f"Unsupported git object type: {decoded_type}")
            decoded_path = _decode_path(raw_path)
            return TreeEntry(
                path=_normalize_path(decoded_path),
                raw_path=decoded_path,
                mode=mode.decode("ascii"),
                type=decoded_type,  # type: ignore[arg-type]
                oid=oid,
                size_bytes=0 if raw_size == b"-" else int(raw_size),
            )
        except (UnicodeError, ValueError) as error:
            raise ValueError("Malformed git ls-tree record") from error

    @staticmethod
    def _parse_name_status(output: bytes) -> set[str]:
        fields = [field for field in _split_nul(output) if field]
        changed: set[str] = set()
        index = 0
        while index < len(fields):
            token = fields[index]
            if b"\t" in token:
                changed.add(_normalize_path(_decode_path(token.split(b"\t", 1)[1])))
                index += 1
                continue
            if index + 1 >= len(fields):
                raise ValueError("Malformed git --name-status -z output")
            changed.add(_normalize_path(_decode_path(fields[index + 1])))
            index += 2
        return changed

    def _inspect_work_tree_path(self, raw_path: str) -> TreeEntry | None:
        self._contained_path(raw_path)
        current = self.repo_path.resolve()
        normalized_path = _normalize_path(raw_path)
        parts = raw_path.split("/")
        if os.sep == "\\" and "\\" in raw_path:
            raise ValueError(f"Git returned an unsafe path: {raw_path!r}")
        for index, part in enumerate(parts):
            current = current / part
            try:
                metadata = current.lstat()
            except (FileNotFoundError, NotADirectoryError):
                return None
            if stat.S_ISLNK(metadata.st_mode):
                return TreeEntry(
                    normalized_path, raw_path, "120000", "blob", "", metadata.st_size
                )
            if index == len(parts) - 1:
                if stat.S_ISDIR(metadata.st_mode):
                    return TreeEntry(
                        normalized_path, raw_path, "160000", "commit", "", 0
                    )
                if not stat.S_ISREG(metadata.st_mode):
                    return TreeEntry(
                        normalized_path,
                        raw_path,
                        "120000",
                        "blob",
                        "",
                        metadata.st_size,
                    )
                mode = "100755" if metadata.st_mode & 0o111 else "100644"
                return TreeEntry(
                    normalized_path, raw_path, mode, "blob", "", metadata.st_size
                )
        return None

    def _contained_path(self, relative_path: str) -> Path:
        if not relative_path or relative_path.startswith("/"):
            raise ValueError(f"Git returned a non-relative path: {relative_path!r}")
        parts = relative_path.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise ValueError(f"Git returned an unsafe path: {relative_path!r}")
        root = self.repo_path.resolve()
        target = root.joinpath(*parts)
        try:
            target.relative_to(root)
        except ValueError as error:
            raise ValueError(
                f"Git path escapes the repository: {relative_path!r}"
            ) from error
        return target

    def _path_contains_symlink(self, relative_path: str) -> bool:
        current = self.repo_path.resolve()
        for part in relative_path.split("/"):
            current = current / part
            try:
                if stat.S_ISLNK(current.lstat().st_mode):
                    return True
            except OSError:
                return False
        return False

    def _read_contained_file(self, relative_path: str) -> bytes:
        target = self._contained_path(relative_path)
        repository_root = self.repo_path.resolve(strict=True)
        if self._path_contains_symlink(relative_path):
            raise OSError("path contains a symlink")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(target, flags)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError("candidate is not a regular file")
            self._assert_descriptor_contained(descriptor, repository_root)
            chunks: list[bytes] = []
            remaining = self.max_file_bytes + 1
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    @staticmethod
    def _assert_descriptor_contained(descriptor: int, repository_root: Path) -> None:
        descriptor_path = Path(f"/proc/self/fd/{descriptor}")
        if not descriptor_path.exists():
            return
        opened_path = descriptor_path.resolve(strict=True)
        try:
            opened_path.relative_to(repository_root)
        except ValueError as error:
            raise OSError("opened file escapes the repository") from error

    @staticmethod
    def _canonical_collision_paths(entries: Sequence[TreeEntry]) -> set[str]:
        counts: dict[str, int] = {}
        for entry in entries:
            counts[entry.path] = counts.get(entry.path, 0) + 1
        return {path for path, count in counts.items() if count > 1}

    @staticmethod
    def _parse_batch_blobs(oids: Sequence[str], output: bytes) -> dict[str, bytes]:
        blobs: dict[str, bytes] = {}
        offset = 0
        for expected_oid in oids:
            line_end = output.find(b"\n", offset)
            if line_end < 0:
                raise ValueError("Malformed git cat-file --batch header")
            header = output[offset:line_end].decode("ascii").split(" ")
            if len(header) != 3:
                raise ValueError("Unexpected git cat-file --batch header")
            oid, object_type, raw_size = header
            try:
                size = int(raw_size)
            except ValueError as error:
                raise ValueError("Unexpected git cat-file --batch size") from error
            if oid != expected_oid or object_type != "blob" or size < 0:
                raise ValueError("Unexpected git cat-file --batch header")
            content_start = line_end + 1
            content_end = content_start + size
            if content_end >= len(output) or output[content_end] != 10:
                raise ValueError("Malformed git cat-file --batch payload")
            blobs[oid] = output[content_start:content_end]
            offset = content_end + 1
        if offset != len(output):
            raise ValueError("Unexpected trailing git cat-file output")
        return blobs

    def _enforce_candidate_limit(
        self,
        candidates: Sequence[TreeEntry],
        side: Literal["base", "head"],
        changed_paths: set[str] | frozenset[str],
    ) -> CandidateReadResult | None:
        if len(candidates) <= self.max_candidates:
            return None
        detail = (
            f"side has {len(candidates)} candidates; limit is {self.max_candidates}"
        )
        return CandidateReadResult(
            unanalyzed=[
                self._unanalyzed(
                    entry.path, side, "too_many_candidates", detail, changed_paths
                )
                for entry in candidates
            ]
        )

    def _accept_content(
        self,
        result: CandidateReadResult,
        file: str,
        side: Literal["base", "head"],
        content: bytes,
        changed_paths: set[str] | frozenset[str],
    ) -> None:
        if b"\0" in content[:BINARY_SNIFF_BYTES]:
            result.unanalyzed.append(
                self._unanalyzed(
                    file,
                    side,
                    "binary",
                    "NUL byte found in the first 8192 bytes",
                    changed_paths,
                )
            )
        else:
            result.files[file] = content.decode("utf-8", errors="replace")

    def _mark_remaining(
        self,
        result: CandidateReadResult,
        entries: Sequence[TreeEntry],
        side: Literal["base", "head"],
        reason: UnanalyzedReason,
        changed_paths: set[str] | frozenset[str],
        detail: str = "20-second extraction budget expired",
    ) -> None:
        result.unanalyzed.extend(
            self._unanalyzed(entry.path, side, reason, detail, changed_paths)
            for entry in entries
        )

    def _timeout_result(
        self,
        side: Literal["base", "head"],
        changed_paths: set[str] | frozenset[str],
    ) -> CandidateReadResult:
        return CandidateReadResult(
            unanalyzed=[
                self._unanalyzed(
                    ".",
                    side,
                    "timeout",
                    "20-second extraction budget expired",
                    changed_paths,
                )
            ]
        )

    @staticmethod
    def _unanalyzed(
        file: str,
        side: Literal["base", "head"],
        reason: UnanalyzedReason,
        detail: str,
        changed_paths: set[str] | frozenset[str],
    ) -> Unanalyzed:
        return Unanalyzed(file, side, reason, detail, file in changed_paths)

    def _expired(self, deadline: float) -> bool:
        return self.clock() >= deadline

    def _remaining(self, deadline: float) -> float:
        remaining = deadline - self.clock()
        if remaining <= 0:
            raise subprocess.TimeoutExpired("git", self.timeout_seconds)
        return max(0.001, remaining)

    def _run(
        self,
        args: Sequence[str],
        input_data: bytes | None = None,
        timeout: float | None = None,
    ) -> bytes:
        return self._runner(
            list(args), cwd=self.repo_path, input_data=input_data, timeout=timeout
        )
