"""Real-repository tests for hardened attack-surface git plumbing."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from rafter_cli.utils.git_tree import (
    EMPTY_TREE_OID,
    MAX_CANDIDATES,
    BaseTreeReader,
    InvalidRefError,
    RefResolutionError,
)


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        shell=False,
    ).stdout


def init_repo(tmp_path: Path, name: str = "repo", commit: bool = True) -> Path:
    repo = tmp_path / name
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "tests@example.com")
    git(repo, "config", "user.name", "Rafter Tests")
    if commit:
        (repo / "tracked.txt").write_text("base\n")
        git(repo, "add", "--", "tracked.txt")
        git(repo, "commit", "-qm", "initial")
    return repo


def commit_all(repo: Path, message: str) -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", message)
    return git(repo, "rev-parse", "HEAD").decode().strip()


def root_oid(repo: Path) -> str:
    return git(repo, "rev-parse", "HEAD").decode().strip()


class TestRefHandling:
    def test_resolve_ref_uses_end_of_options(self):
        calls: list[list[str]] = []
        oid = "a" * 40

        def runner(args: list[str], **_kwargs: object) -> bytes:
            calls.append(list(args))
            return f"{oid}\n".encode()

        reader = BaseTreeReader(Path("/repo"), runner=runner)
        assert reader.resolve_ref("main") == oid
        assert calls == [
            ["rev-parse", "--verify", "--quiet", "--end-of-options", "main^{commit}"]
        ]

    @pytest.mark.parametrize("ref", ["--upload-pack=/bin/false", "-i"])
    def test_option_shaped_ref_is_rejected_before_git(self, ref: str):
        calls = 0

        def runner(_args: list[str], **_kwargs: object) -> bytes:
            nonlocal calls
            calls += 1
            return b""

        reader = BaseTreeReader(Path("/repo"), runner=runner)
        with pytest.raises(InvalidRefError) as raised:
            reader.resolve_ref(ref)
        assert raised.value.code == "invalid_ref"
        assert raised.value.exit_code == 2
        assert calls == 0

    def test_missing_ref_is_not_empty_tree(self, tmp_path: Path):
        reader = BaseTreeReader(init_repo(tmp_path))
        with pytest.raises(RefResolutionError):
            reader.resolve_ref("does-not-exist")

    def test_git_spawn_failure_is_not_mistaken_for_unborn_repo(self):
        def runner(_args: list[str], **_kwargs: object) -> bytes:
            raise FileNotFoundError("git is unavailable")

        reader = BaseTreeReader(Path("/repo"), runner=runner)
        with pytest.raises(FileNotFoundError, match="git is unavailable"):
            reader.resolve_ref("HEAD")

    def test_non_repository_is_not_mistaken_for_unborn_repo(self, tmp_path: Path):
        with pytest.raises(subprocess.CalledProcessError):
            BaseTreeReader(tmp_path).resolve_ref("HEAD")

    def test_downstream_non_oid_is_rejected_before_git(self):
        calls = 0

        def runner(_args: list[str], **_kwargs: object) -> bytes:
            nonlocal calls
            calls += 1
            return b""

        reader = BaseTreeReader(Path("/repo"), runner=runner)
        with pytest.raises(ValueError, match="resolved 40-hex"):
            reader.list_tree("--upload-pack=/bin/false")
        with pytest.raises(ValueError, match="resolved 40-hex"):
            reader.changed_paths("-i")
        with pytest.raises(ValueError, match="resolved 40-hex"):
            reader.changed_paths("a" * 40, "")
        with pytest.raises(ValueError, match="resolved 40-hex"):
            reader.read_blob("HEAD:policy.json")
        assert calls == 0

    def test_only_root_parent_or_unborn_repo_maps_to_empty_tree(self, tmp_path: Path):
        repo = init_repo(tmp_path, "root")
        root = root_oid(repo)
        reader = BaseTreeReader(repo)
        assert reader.resolve_ref("HEAD") == root
        assert reader.resolve_ref("HEAD^") == EMPTY_TREE_OID

        unborn = init_repo(tmp_path, "unborn", commit=False)
        assert BaseTreeReader(unborn).resolve_ref("HEAD") == EMPTY_TREE_OID


class TestTreePlumbing:
    def test_special_filename_round_trips_in_tree_worktree_and_diff(
        self, tmp_path: Path
    ):
        repo = init_repo(tmp_path)
        special = 'policy\nwith\ttab "quote" and \\slash-e\u0301.json'
        normalized = 'policy\nwith\ttab "quote" and \\slash-é.json'
        (repo / special).write_text('{"Statement":[]}\n')
        oid = commit_all(repo, "special path")
        with (repo / special).open("a") as handle:
            handle.write("changed\n")

        reader = BaseTreeReader(repo)
        assert normalized in [entry.path for entry in reader.list_tree(oid)]
        assert normalized in [entry.path for entry in reader.list_work_tree()]
        assert normalized in reader.changed_paths(root_oid(repo))
        result = reader.read_work_tree_candidates(
            lambda candidate, _size: candidate.endswith(".json")
        )
        assert '{"Statement":[]}' in result.files[normalized]

    def test_canonical_path_collision_abstains(self, tmp_path: Path):
        repo = init_repo(tmp_path)
        (repo / "policy-é.json").write_text("composed\n")
        (repo / "policy-e\u0301.json").write_text("decomposed\n")

        result = BaseTreeReader(repo).read_work_tree_candidates(
            lambda candidate, _size: candidate.endswith(".json")
        )
        assert result.files == {}
        assert len(result.unanalyzed) == 2
        assert all(item.reason == "parse_error" for item in result.unanalyzed)

    def test_untracked_is_in_worktree_listing_and_changed_paths(self, tmp_path: Path):
        repo = init_repo(tmp_path)
        (repo / "new policy.json").write_text("{}\n")
        reader = BaseTreeReader(repo)
        assert "new policy.json" in [entry.path for entry in reader.list_work_tree()]
        assert "new policy.json" in reader.changed_paths(root_oid(repo))

    def test_deleted_tracked_path_is_not_in_worktree_listing(self, tmp_path: Path):
        repo = init_repo(tmp_path)
        (repo / "tracked.txt").unlink()
        assert "tracked.txt" not in [
            entry.path for entry in BaseTreeReader(repo).list_work_tree()
        ]

    def test_blob_and_tree_candidates_are_read(self, tmp_path: Path):
        repo = init_repo(tmp_path)
        (repo / "policy.json").write_text('{"Statement":[]}\n')
        oid = commit_all(repo, "policy")
        reader = BaseTreeReader(repo)
        entry = next(
            item for item in reader.list_tree(oid) if item.path == "policy.json"
        )
        assert reader.read_blob(entry.oid) == b'{"Statement":[]}\n'
        assert reader.read_at(oid, "policy.json") == b'{"Statement":[]}\n'
        result = reader.read_tree_candidates(
            oid, lambda candidate, _size: candidate.endswith(".json")
        )
        assert result.files["policy.json"] == '{"Statement":[]}\n'
        assert result.unanalyzed == []

    def test_multiple_candidates_use_one_cat_file_batch(self, tmp_path: Path):
        repo = init_repo(tmp_path)
        (repo / "one.json").write_text('{"one":1}\n')
        (repo / "two.json").write_text('{"two":2}\n')
        oid = commit_all(repo, "two blobs")
        calls: list[list[str]] = []

        def runner(
            args: list[str],
            *,
            cwd: Path,
            input_data: bytes | None = None,
            timeout: float | None = None,
        ) -> bytes:
            calls.append(list(args))
            return subprocess.run(
                ["git", *args],
                cwd=cwd,
                input=input_data,
                timeout=timeout,
                check=True,
                capture_output=True,
                shell=False,
            ).stdout

        result = BaseTreeReader(repo, runner=runner).read_tree_candidates(
            oid, lambda candidate, _size: candidate.endswith(".json")
        )
        assert list(result.files) == ["one.json", "two.json"]
        assert [args for args in calls if args[0] == "cat-file"] == [
            ["cat-file", "--batch"]
        ]

    def test_cat_file_batches_are_bounded_by_candidate_bytes(self, tmp_path: Path):
        repo = init_repo(tmp_path)
        (repo / "one.json").write_text("1234567890")
        (repo / "two.json").write_text("abcdefghij")
        oid = commit_all(repo, "two blobs")
        calls: list[list[str]] = []

        def runner(
            args: list[str],
            *,
            cwd: Path,
            input_data: bytes | None = None,
            timeout: float | None = None,
        ) -> bytes:
            calls.append(list(args))
            return subprocess.run(
                ["git", *args],
                cwd=cwd,
                input=input_data,
                timeout=timeout,
                check=True,
                capture_output=True,
                shell=False,
            ).stdout

        result = BaseTreeReader(
            repo, runner=runner, max_batch_bytes=10
        ).read_tree_candidates(
            oid, lambda candidate, _size: candidate.endswith(".json")
        )
        assert len(result.files) == 2
        assert [args for args in calls if args[0] == "cat-file"] == [
            ["cat-file", "--batch"],
            ["cat-file", "--batch"],
        ]

    def test_changed_paths_between_resolved_oids(self, tmp_path: Path):
        repo = init_repo(tmp_path)
        base = root_oid(repo)
        (repo / "next.txt").write_text("next\n")
        head = commit_all(repo, "next")
        assert BaseTreeReader(repo).changed_paths(base, head) == {"next.txt"}

    def test_depth_one_clone_is_shallow(self, tmp_path: Path):
        source = init_repo(tmp_path, "source")
        (source / "second.txt").write_text("second\n")
        commit_all(source, "second")
        clone = tmp_path / "clone"
        subprocess.run(
            ["git", "clone", "-q", "--depth=1", f"file://{source}", str(clone)],
            check=True,
            capture_output=True,
            shell=False,
        )
        assert BaseTreeReader(clone).is_shallow() is True
        assert BaseTreeReader(source).is_shallow() is False


class TestHardeningAndBudgets:
    def test_symlinks_and_symlink_ancestors_are_never_followed(self, tmp_path: Path):
        repo = init_repo(tmp_path, "repo")
        outside = tmp_path / "outside"
        outside.mkdir()
        marker = "outside-secret-marker"
        (outside / "policy.json").write_text(marker)

        (repo / "link.json").symlink_to(outside / "policy.json")
        (repo / "nested").mkdir()
        (repo / "nested" / "policy.json").write_text("safe\n")
        oid = commit_all(repo, "symlinks")

        (repo / "nested" / "policy.json").unlink()
        (repo / "nested").rmdir()
        (repo / "nested").symlink_to(outside, target_is_directory=True)

        reader = BaseTreeReader(repo)
        base = reader.read_tree_candidates(
            oid, lambda candidate, _size: candidate.endswith(".json")
        )
        head = reader.read_work_tree_candidates(
            lambda candidate, _size: candidate.endswith(".json")
        )

        assert any(
            item.file == "link.json"
            and item.side == "base"
            and item.reason == "symlink"
            for item in base.unanalyzed
        )
        assert {(item.file, item.side, item.reason) for item in head.unanalyzed} >= {
            ("link.json", "head", "symlink"),
            ("nested/policy.json", "head", "symlink"),
        }
        assert marker not in "\n".join([*base.files.values(), *head.files.values()])

    @pytest.mark.skipif(os.name == "nt", reason="mkfifo is not available on Windows")
    def test_nonregular_candidate_is_never_opened(self, tmp_path: Path):
        repo = init_repo(tmp_path)
        (repo / "pipe.json").write_text("regular\n")
        commit_all(repo, "tracked regular file")
        (repo / "pipe.json").unlink()
        os.mkfifo(repo / "pipe.json")

        result = BaseTreeReader(repo).read_work_tree_candidates(
            lambda candidate, _size: candidate.endswith(".json")
        )
        assert "pipe.json" not in result.files
        assert any(
            item.file == "pipe.json" and item.reason == "symlink"
            for item in result.unanalyzed
        )

    def test_two_mib_candidate_is_too_large(self, tmp_path: Path):
        repo = init_repo(tmp_path)
        (repo / "large.json").write_bytes(b"A" * (2 * 1024 * 1024))
        oid = commit_all(repo, "large")
        result = BaseTreeReader(repo).read_tree_candidates(
            oid,
            lambda candidate, _size: candidate.endswith(".json"),
            {"large.json"},
        )
        assert "large.json" not in result.files
        assert any(
            item.file == "large.json" and item.reason == "too_large" and item.changed
            for item in result.unanalyzed
        )

    def test_more_than_2000_candidates_abstains_from_whole_side(self, tmp_path: Path):
        repo = init_repo(tmp_path)
        for index in range(MAX_CANDIDATES + 1):
            (repo / f"candidate-{index:04d}.json").write_text("{}")

        result = BaseTreeReader(repo).read_work_tree_candidates(
            lambda candidate, _size: candidate.endswith(".json")
        )
        assert MAX_CANDIDATES == 2000
        assert result.files == {}
        assert len(result.unanalyzed) == MAX_CANDIDATES + 1
        assert all(item.reason == "too_many_candidates" for item in result.unanalyzed)

    def test_nul_in_first_8k_is_binary(self, tmp_path: Path):
        repo = init_repo(tmp_path)
        (repo / "binary.json").write_bytes(b"before\0after")
        result = BaseTreeReader(repo).read_work_tree_candidates(
            lambda candidate, _size: candidate.endswith(".json")
        )
        assert result.files == {}
        assert any(
            item.file == "binary.json" and item.reason == "binary"
            for item in result.unanalyzed
        )

    def test_expired_budget_becomes_timeout(self, tmp_path: Path):
        repo = init_repo(tmp_path)
        (repo / "policy.json").write_text("{}\n")
        ticks = iter([0, 0, 2, 2])
        result = BaseTreeReader(
            repo, timeout_seconds=0.1, clock=lambda: next(ticks, 2)
        ).read_work_tree_candidates(
            lambda candidate, _size: candidate.endswith(".json")
        )
        assert result.files == {}
        assert any(
            item.file == "policy.json" and item.reason == "timeout"
            for item in result.unanalyzed
        )

    def test_subprocess_is_argv_only_and_unsafe_helper_is_not_imported(self):
        source = (
            Path(__file__).resolve().parents[1] / "rafter_cli" / "utils" / "git_tree.py"
        ).read_text()
        assert "subprocess.run(" in source
        assert "shell=False" in source
        assert "from .git import" not in source
        assert "from rafter_cli.utils.git import" not in source
