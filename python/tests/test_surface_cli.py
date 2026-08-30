"""`rafter surface diff` CLI contract (§6, §9.1, §9.2) — the full exit-code
matrix, its precedence, stream discipline, and the three text outcomes that
must never read alike.

Real temp git repos, CLI invoked as a subprocess. Properties come from the W4
stub extractor (``*.surface-stub.json``), so these tests exercise the shell
without waiting on the Wave 2 extractors.

Mirrors ``node/tests/surface-cli.test.ts``.
"""

import json
import os
import site
import subprocess
import sys

import pytest

_USER_BASE = site.getuserbase()


def rafter(args, *, cwd=None):
    """Run rafter CLI as a subprocess and return (stdout, stderr, exitcode)."""
    env = os.environ.copy()
    env["PYTHONUSERBASE"] = _USER_BASE
    result = subprocess.run(
        [sys.executable, "-m", "rafter_cli", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
        env=env,
        timeout=60,
    )
    return result.stdout, result.stderr, result.returncode


_NODE_CLI = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "node",
    "dist",
    "index.js",
)
# Byte-for-byte parity on the exit-3 envelope needs the built Node CLI; skip it
# when dist/ has not been built.
_NODE_AVAILABLE = os.path.isfile(_NODE_CLI)


def rafter_node(args, *, cwd=None):
    result = subprocess.run(
        ["node", _NODE_CLI, *args], capture_output=True, text=True, cwd=cwd, timeout=60
    )
    return result.stdout, result.stderr, result.returncode


def git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def port(key, binding, label=None):
    return {
        "kind": "container.port",
        "key": f"container.port:compose:{key}",
        "subject": f"service {key}",
        "label": label or f"port {key}",
        "levels": {"binding": binding},
        "line": 3,
    }


def iam(key, resource, action="literal"):
    return {
        "kind": "iam.allow",
        "key": f"iam.allow:iam-json:{key}",
        "subject": f"statement {key}",
        "label": f"Allow s3:GetObject on {resource}",
        "levels": {
            "action": action,
            "resource": resource,
            "principal": "absent-or-literal",
            "condition": "present",
        },
        "line": 18,
    }


def write_stub(repo, file, properties, unanalyzed=()):
    (repo / file).write_text(
        json.dumps({"properties": properties, "unanalyzed": list(unanalyzed)}, indent=2),
        encoding="utf-8",
    )


def write_broken(repo, file):
    (repo / file).write_text("{not json", encoding="utf-8")


@pytest.fixture()
def repo(tmp_path):
    git(tmp_path, "init", "-q", ".")
    git(tmp_path, "config", "user.email", "test@rafter.so")
    git(tmp_path, "config", "user.name", "Rafter Test")
    git(tmp_path, "config", "commit.gpgsign", "false")
    return tmp_path


def commit(repo, message="state"):
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)


def commit0(repo):
    """A repo needs one commit before HEAD resolves; this is the smallest one."""
    (repo / "README.md").write_text("seed\n", encoding="utf-8")
    commit(repo, "seed")


# ---------------------------------------------------------------------------
# Exit-code matrix (§6.3)
# ---------------------------------------------------------------------------


class TestExitCodes:
    def test_exit_0_when_surface_unchanged(self, repo):
        write_stub(repo, "a.surface-stub.json", [port("redis", "loopback-published")])
        commit(repo)
        stdout, _, rc = rafter(["surface", "diff"], cwd=repo)
        assert rc == 0
        assert "Attack surface unchanged" in stdout

    def test_exit_1_on_danger_increase(self, repo):
        write_stub(repo, "a.surface-stub.json", [port("redis", "loopback-published")])
        commit(repo)
        write_stub(repo, "a.surface-stub.json", [port("redis", "host-published")])
        stdout, _, rc = rafter(["surface", "diff"], cwd=repo)
        assert rc == 1
        assert "became more dangerous" in stdout

    def test_exit_0_when_increase_below_threshold(self, repo):
        write_stub(repo, "a.surface-stub.json", [port("redis", "not-published")])
        commit(repo)
        write_stub(repo, "a.surface-stub.json", [port("redis", "loopback-published")])
        # loopback-published is severity "low"; the default threshold is "high".
        assert rafter(["surface", "diff"], cwd=repo)[2] == 0
        assert rafter(["surface", "diff", "--fail-on", "low"], cwd=repo)[2] == 1

    def test_exit_2_on_invalid_flag_value(self, repo):
        commit0(repo)
        _, stderr, rc = rafter(["surface", "diff", "--format", "yaml"], cwd=repo)
        assert rc == 2
        assert "--format" in stderr

    def test_exit_2_on_unknown_flag(self, repo):
        commit0(repo)
        assert rafter(["surface", "diff", "--nope"], cwd=repo)[2] == 2

    def test_exit_2_on_option_shaped_ref(self, repo):
        commit0(repo)
        for ref in ("--upload-pack=/bin/false", "-i"):
            _, stderr, rc = rafter(["surface", "diff", f"--base={ref}"], cwd=repo)
            assert rc == 2
            assert "Invalid git ref" in stderr

    def test_exit_2_outside_a_git_repository(self, tmp_path):
        bare = tmp_path / "plain"
        bare.mkdir()
        _, stderr, rc = rafter(["surface", "diff"], cwd=bare)
        assert rc == 2
        assert "Not a git repository" in stderr

    def test_exit_3_with_actionable_message(self, repo):
        commit0(repo)
        stdout, stderr, rc = rafter(["surface", "diff", "--base", "origin/main"], cwd=repo)
        assert rc == 3
        assert "Cannot resolve base ref 'origin/main'" in stderr
        assert "fetch-depth: 0" in stderr
        assert "--fetch-base" in stderr
        # Never silently treated as an empty base: nothing is reported as appeared.
        assert stdout == ""

    def test_exit_3_emits_machine_readable_envelope_under_json(self, repo):
        commit0(repo)
        stdout, _, rc = rafter(["surface", "diff", "--json", "--base", "origin/main"], cwd=repo)
        assert rc == 3
        envelope = json.loads(stdout)
        assert envelope["error"] == "base_unreachable"
        assert envelope["schema_version"] == 1
        assert envelope["base"] == "origin/main"
        assert envelope["shallow"] is False
        assert "git fetch --no-tags --depth=50 origin main" in envelope["hint"]
        assert "not a clean result" in envelope["_note"]
        # Not a report: no transitions array to mistake for "nothing changed".
        assert "transitions" not in envelope

    def test_shallow_clone_reports_shallow_and_fetch_depth_remedy(self, repo, tmp_path):
        # A depth-1 clone cannot resolve the origin repo's first commit.
        (repo / "one.txt").write_text("1\n", encoding="utf-8")
        commit(repo, "first")
        first_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True
        ).stdout.strip()
        (repo / "two.txt").write_text("2\n", encoding="utf-8")
        commit(repo, "second")

        shallow = tmp_path / "shallow-clone"
        subprocess.run(
            ["git", "clone", "-q", "--depth=1", f"file://{repo}", str(shallow)],
            check=True,
            capture_output=True,
        )
        stdout, _, rc = rafter(
            ["surface", "diff", "--json", "--base", first_sha], cwd=shallow
        )
        assert rc == 3
        envelope = json.loads(stdout)
        assert envelope["shallow"] is True
        assert "fetch-depth: 0" in envelope["hint"]

    @pytest.mark.skipif(not _NODE_AVAILABLE, reason="node dist/ is not built")
    def test_exit_3_envelope_is_byte_identical_across_runtimes(self, repo):
        commit0(repo)
        args = ["surface", "diff", "--json", "--base", "origin/main"]
        py_stdout, _, py_rc = rafter(args, cwd=repo)
        node_stdout, _, node_rc = rafter_node(args, cwd=repo)
        assert py_rc == 3
        assert node_rc == 3
        assert py_stdout == node_stdout

    def test_exit_4_when_changed_candidate_unanalyzable(self, repo):
        commit0(repo)
        write_broken(repo, "broken.surface-stub.json")
        stdout, _, rc = rafter(["surface", "diff"], cwd=repo)
        assert rc == 4
        assert "INCONCLUSIVE" in stdout

    def test_untouched_unanalyzable_file_does_not_gate(self, repo):
        write_broken(repo, "legacy.surface-stub.json")
        commit(repo)
        stdout, _, rc = rafter(["surface", "diff"], cwd=repo)
        assert rc == 0
        assert "INCONCLUSIVE" not in stdout
        assert "could not be analyzed" in stdout


# ---------------------------------------------------------------------------
# Precedence 3 > 2 > 4 > 1 > 0
# ---------------------------------------------------------------------------


class TestPrecedence:
    def test_4_beats_1(self, repo):
        write_stub(repo, "a.surface-stub.json", [port("redis", "loopback-published")])
        commit(repo)
        write_stub(repo, "a.surface-stub.json", [port("redis", "host-published")])
        write_broken(repo, "broken.surface-stub.json")
        assert rafter(["surface", "diff"], cwd=repo)[2] == 4
        # The body still carries every transition found (§6.3).
        stdout, _, _ = rafter(["surface", "diff", "--json"], cwd=repo)
        report = json.loads(stdout)
        assert report["summary"]["increased"] == 1
        assert report["coverage"]["inconclusive"] is True

    def test_2_beats_4(self, repo):
        write_stub(repo, "a.surface-stub.json", [port("redis", "loopback-published")])
        commit(repo)
        write_broken(repo, "broken.surface-stub.json")
        assert rafter(["surface", "diff", "--fail-on", "sometimes"], cwd=repo)[2] == 2

    def test_3_beats_4(self, repo):
        commit0(repo)
        write_broken(repo, "broken.surface-stub.json")
        assert rafter(["surface", "diff", "--base", "origin/main"], cwd=repo)[2] == 3


# ---------------------------------------------------------------------------
# --fail-on none and --on-inconclusive
# ---------------------------------------------------------------------------


class TestReportOnlyMode:
    def test_fail_on_none_forces_0_and_downgrades_4(self, repo):
        write_stub(repo, "a.surface-stub.json", [port("redis", "loopback-published")])
        commit(repo)
        write_stub(repo, "a.surface-stub.json", [port("redis", "host-published")])
        write_broken(repo, "broken.surface-stub.json")
        stdout, stderr, rc = rafter(["surface", "diff", "--fail-on", "none"], cwd=repo)
        assert rc == 0
        # Report-only reports: the inconclusive block is still printed.
        assert "INCONCLUSIVE" in stdout
        assert "downgraded to a warning" in stderr

    def test_fail_on_none_does_not_suppress_exit_3(self, repo):
        commit0(repo)
        rc = rafter(
            ["surface", "diff", "--base", "origin/main", "--fail-on", "none"], cwd=repo
        )[2]
        assert rc == 3

    def test_on_inconclusive_warn_downgrades_exit_4(self, repo):
        commit0(repo)
        write_broken(repo, "broken.surface-stub.json")
        stdout, _, rc = rafter(["surface", "diff", "--on-inconclusive", "warn"], cwd=repo)
        assert rc == 0
        assert "INCONCLUSIVE" in stdout
        assert "--on-inconclusive warn" in stdout

    def test_explicit_on_inconclusive_exit_wins_over_fail_on_none(self, repo):
        commit0(repo)
        write_broken(repo, "broken.surface-stub.json")
        rc = rafter(
            ["surface", "diff", "--fail-on", "none", "--on-inconclusive", "exit"], cwd=repo
        )[2]
        assert rc == 4


# ---------------------------------------------------------------------------
# Stream discipline (§9.2)
# ---------------------------------------------------------------------------


class TestStreamDiscipline:
    def test_stdout_is_json_only_under_json_flag(self, repo):
        write_stub(repo, "a.surface-stub.json", [port("redis", "loopback-published")])
        commit(repo)
        write_stub(repo, "a.surface-stub.json", [port("redis", "host-published")])
        write_broken(repo, "broken.surface-stub.json")
        stdout, stderr, _ = rafter(
            ["surface", "diff", "--json", "--fail-on", "none", "--explain"], cwd=repo
        )
        report = json.loads(stdout)
        assert report["schema_version"] == 1
        assert len(report["base"]["resolved"]) == 40
        assert report["head"]["ref"] == "WORKTREE"
        assert report["head"]["resolved"] is None
        assert "→" not in report["transitions"][0]["label"]
        assert "downgraded to a warning" in stderr
        assert "{" not in stderr

    def test_quiet_suppresses_status_but_keeps_the_result(self, repo):
        commit0(repo)
        write_broken(repo, "broken.surface-stub.json")
        stdout, stderr, _ = rafter(
            ["surface", "diff", "--json", "--on-inconclusive", "warn", "--quiet"], cwd=repo
        )
        assert stderr == ""
        assert json.loads(stdout)["coverage"]["inconclusive"] is True


# ---------------------------------------------------------------------------
# The three text outcomes must not be confusable (§9.2)
# ---------------------------------------------------------------------------


class TestTextOutcomes:
    def test_clean_degraded_and_inconclusive_are_distinct(self, repo):
        write_stub(repo, "a.surface-stub.json", [port("redis", "loopback-published")])
        commit(repo)
        clean = rafter(["surface", "diff"], cwd=repo)[0]

        write_broken(repo, "legacy.surface-stub.json")
        commit(repo, "legacy")
        degraded = rafter(["surface", "diff"], cwd=repo)[0]

        write_broken(repo, "touched.surface-stub.json")
        inconclusive = rafter(["surface", "diff"], cwd=repo)[0]

        assert clean.strip().startswith("Attack surface unchanged")
        assert "no change detected, but" in degraded
        assert "Attack surface unchanged" not in degraded
        assert "INCONCLUSIVE" not in degraded
        assert "INCONCLUSIVE" in inconclusive
        assert "This is not a clean result" in inconclusive
        assert "Attack surface unchanged" not in inconclusive
        assert "no change detected" not in inconclusive
        assert len({clean, degraded, inconclusive}) == 3


# ---------------------------------------------------------------------------
# Rendering details
# ---------------------------------------------------------------------------


class TestRendering:
    def test_delta_phrasing_is_composed_by_the_renderer(self, repo):
        write_stub(repo, "p.surface-stub.json", [iam("policy.json|sid=App", "prefix-wildcard")])
        commit(repo)
        write_stub(repo, "p.surface-stub.json", [iam("policy.json|sid=App", "global-wildcard")])
        stdout, _, rc = rafter(["surface", "diff"], cwd=repo)
        assert rc == 1
        assert "resource widened: prefix-wildcard → global-wildcard" in stdout
        # The label itself stays a property description (amendment A1).
        assert "Allow s3:GetObject on global-wildcard" in stdout

    def test_incomparable_is_reported_not_suppressed(self, repo):
        write_stub(
            repo,
            "p.surface-stub.json",
            [iam("policy.json|sid=App", "prefix-wildcard", "service-wildcard")],
        )
        commit(repo)
        write_stub(
            repo, "p.surface-stub.json", [iam("policy.json|sid=App", "global-wildcard", "literal")]
        )
        stdout, _, rc = rafter(["surface", "diff", "--fail-on", "medium"], cwd=repo)
        assert rc == 1
        assert "ambiguous" in stdout
        assert "incomparable — review by hand" in stdout

    def test_min_severity_filters_display_only(self, repo):
        write_stub(repo, "a.surface-stub.json", [port("redis", "not-published")])
        commit(repo)
        write_stub(repo, "a.surface-stub.json", [port("redis", "loopback-published")])
        stdout, _, rc = rafter(
            ["surface", "diff", "--fail-on", "low", "--min-severity", "high"], cwd=repo
        )
        assert rc == 1
        assert "no property became more dangerous" in stdout
        assert "binding widened" not in stdout

    def test_explain_enumerates_unanalyzed_candidates(self, repo):
        write_broken(repo, "legacy.surface-stub.json")
        commit(repo)
        stdout, _, _ = rafter(["surface", "diff", "--explain"], cwd=repo)
        assert "Unanalyzed candidates" in stdout
        assert "legacy.surface-stub.json" in stdout
        assert "parse_error" in stdout

    def test_include_decreased(self, repo):
        write_stub(repo, "a.surface-stub.json", [port("redis", "host-published")])
        commit(repo)
        write_stub(repo, "a.surface-stub.json", [port("redis", "not-published")])
        hidden_stdout, _, rc = rafter(["surface", "diff"], cwd=repo)
        assert rc == 0
        assert "(--include-decreased)" in hidden_stdout
        shown_stdout, _, _ = rafter(["surface", "diff", "--include-decreased"], cwd=repo)
        assert "binding narrowed: host-published → not-published" in shown_stdout

    def test_head_ref_comparison(self, repo):
        write_stub(repo, "a.surface-stub.json", [port("redis", "loopback-published")])
        commit(repo, "base")
        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True
        ).stdout.strip()
        write_stub(repo, "a.surface-stub.json", [port("redis", "host-published")])
        commit(repo, "head")
        stdout, _, rc = rafter(
            ["surface", "diff", "--base", base_sha, "--head", "HEAD", "--json"], cwd=repo
        )
        assert rc == 1
        report = json.loads(stdout)
        assert len(report["head"]["resolved"]) == 40
        assert report["summary"]["increased"] == 1
