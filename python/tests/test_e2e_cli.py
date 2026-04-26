"""End-to-end CLI tests — invoke rafter as a subprocess and validate
exit codes, stdout, and stderr. Mirrors node/tests/e2e-cli.test.ts."""

import json
import os
import pathlib
import re
import site
import subprocess
import sys
import tempfile

import pytest

# Captured under the real HOME so user-site packages (e.g. typer) remain
# importable in subprocesses launched with HOME overridden via env_override.
_USER_BASE = site.getuserbase()


def rafter(args, *, cwd=None, env_override=None):
    """Run rafter CLI as a subprocess and return (stdout, stderr, exitcode)."""
    if isinstance(args, str):
        args = args.split()
    env = os.environ.copy()
    env["PYTHONUSERBASE"] = _USER_BASE
    if env_override:
        env.update(env_override)
    result = subprocess.run(
        [sys.executable, "-m", "rafter_cli", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
        env=env,
        timeout=30,
    )
    return result.stdout, result.stderr, result.returncode


# Resolve project root (python/ is one level up from tests/)
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent


# ---------------------------------------------------------------------------
# Version and help
# ---------------------------------------------------------------------------


class TestVersionAndHelp:
    def test_version_outputs_semver(self):
        stdout, _, rc = rafter("--version")
        assert rc == 0
        assert re.search(r"\d+\.\d+\.\d+", stdout)

    def test_short_version_flag(self):
        long_out, _, _ = rafter("--version")
        short_out, _, rc = rafter("-V")
        assert rc == 0
        assert short_out.strip() == long_out.strip()

    def test_version_matches_pyproject(self):
        """--version output must match pyproject.toml version."""
        pyproject = (_PROJECT_ROOT / "python" / "pyproject.toml").read_text()
        m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
        assert m, "Could not find version in pyproject.toml"
        expected = m.group(1)
        stdout, _, rc = rafter("--version")
        assert rc == 0
        assert expected in stdout

    def test_help_outputs_usage(self):
        stdout, _, rc = rafter("--help")
        assert rc == 0
        assert "rafter" in stdout.lower()

    def test_help_lists_all_top_level_commands(self):
        stdout, _, rc = rafter("--help")
        assert rc == 0
        for cmd in [
            "scan", "agent", "mcp", "policy", "ci",
            "hook", "brief", "notify", "run", "get",
            "usage", "issues", "completion",
        ]:
            assert cmd in stdout, f"Missing command '{cmd}' in --help output"

    def test_agent_help_shows_subcommands(self):
        stdout, _, rc = rafter("agent --help")
        assert rc == 0
        for sub in ["scan", "exec", "audit"]:
            assert sub in stdout

    def test_scan_help_shows_subcommands(self):
        stdout, _, rc = rafter("scan --help")
        assert rc == 0
        assert "remote" in stdout

    def test_policy_help_shows_subcommands(self):
        stdout, _, rc = rafter("policy --help")
        assert rc == 0
        assert "export" in stdout

    def test_mcp_help_shows_subcommands(self):
        stdout, _, rc = rafter("mcp --help")
        assert rc == 0
        assert "serve" in stdout

    def test_ci_help_shows_subcommands(self):
        stdout, _, rc = rafter("ci --help")
        assert rc == 0
        assert "init" in stdout


# ---------------------------------------------------------------------------
# Command routing
# ---------------------------------------------------------------------------


class TestCommandRouting:
    def test_no_arguments_shows_help(self):
        stdout, stderr, _ = rafter([])
        combined = stdout + stderr
        assert "rafter" in combined.lower()

    def test_unknown_command_exits_nonzero(self):
        _, _, rc = rafter("nonexistent-command")
        assert rc != 0

    def test_scan_local_routes_to_scanner(self):
        _, _, rc = rafter("scan local /tmp/nonexistent-rafter-routing-test")
        assert rc == 2  # path not found

    def test_agent_exec_routes_to_interceptor(self):
        stdout, _, rc = rafter(["agent", "exec", "echo routing-test"])
        assert rc == 0

    def test_agent_config_show_routes_to_config(self):
        with tempfile.TemporaryDirectory(prefix="rafter-route-") as tmp:
            stdout, _, rc = rafter("agent config show", env_override={"HOME": tmp})
            # May exit 0 or 1 depending on config presence, but should not crash
            assert rc in (0, 1)

    def test_policy_export_routes_to_exporter(self):
        stdout, _, rc = rafter("policy export --format claude")
        assert rc == 0
        assert len(stdout) > 0


# ---------------------------------------------------------------------------
# Local secret scanning
# ---------------------------------------------------------------------------


class TestLocalScanning:
    def test_exits_0_for_clean_file(self, tmp_path):
        f = tmp_path / "clean.txt"
        f.write_text("no secrets here\n")
        _, _, rc = rafter(f"scan local {f} --engine patterns --quiet")
        assert rc == 0

    def test_exits_1_when_secrets_detected(self, tmp_path):
        f = tmp_path / "secrets.txt"
        f.write_text("AKIAIOSFODNN7EXAMPLE\n")
        _, _, rc = rafter(f"scan local {f} --engine patterns --quiet")
        assert rc == 1

    def test_json_outputs_valid_json(self, tmp_path):
        f = tmp_path / "secrets.txt"
        f.write_text("AKIAIOSFODNN7EXAMPLE\n")
        stdout, _, rc = rafter(f"scan local {f} --engine patterns --json")
        assert rc == 1
        parsed = json.loads(stdout)
        assert isinstance(parsed, list)
        assert parsed[0]["matches"][0]["pattern"]["name"] == "AWS Access Key ID"

    def test_sarif_format_outputs_sarif_schema(self, tmp_path):
        f = tmp_path / "secrets.txt"
        f.write_text("AKIAIOSFODNN7EXAMPLE\n")
        stdout, _, rc = rafter(f"scan local {f} --engine patterns --format sarif")
        assert rc == 1
        sarif = json.loads(stdout)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "rafter"
        assert len(sarif["runs"][0]["results"]) > 0

    def test_scans_directory_recursively(self, tmp_path):
        sub = tmp_path / "src"
        sub.mkdir()
        (sub / "config.ts").write_text("const key = 'AKIAIOSFODNN7EXAMPLE';\n")
        stdout, _, rc = rafter(f"scan local {tmp_path} --engine patterns --json")
        assert rc == 1
        parsed = json.loads(stdout)
        assert len(parsed) > 0

    def test_exits_2_for_nonexistent_path(self):
        _, _, rc = rafter("scan local /tmp/nonexistent-rafter-path-12345 --engine patterns")
        assert rc == 2

    def test_invalid_engine_does_not_crash(self, tmp_path):
        """Python implementation rejects unknown engines with exit code 2."""
        f = tmp_path / "clean.txt"
        f.write_text("ok\n")
        _, _, rc = rafter(f"scan local {f} --engine badengine")
        # Python rejects invalid engines with exit code 2
        assert rc == 2

    def test_invalid_format_does_not_crash(self, tmp_path):
        """Python implementation falls back gracefully for unknown formats."""
        f = tmp_path / "clean.txt"
        f.write_text("ok\n")
        _, _, rc = rafter(f"scan local {f} --engine patterns --format xml")
        assert rc == 0


# ---------------------------------------------------------------------------
# rafter secrets — top-level alias for local secret scanning
# ---------------------------------------------------------------------------


class TestRafterSecrets:
    def test_help_advertises_secrets_only_scope(self):
        stdout, _, rc = rafter("secrets --help")
        assert rc == 0
        assert "secrets only" in stdout.lower()
        assert "rafter run" in stdout.lower()

    def test_detects_secrets_same_as_scan_local(self, tmp_path):
        f = tmp_path / "secrets.txt"
        f.write_text("AKIAIOSFODNN7EXAMPLE\n")
        a_stdout, _, a_rc = rafter(f"secrets {f} --engine patterns --json")
        b_stdout, _, b_rc = rafter(f"scan local {f} --engine patterns --json")
        assert a_rc == 1
        assert b_rc == 1
        assert json.loads(a_stdout) == json.loads(b_stdout)

    def test_exits_0_for_clean_file(self, tmp_path):
        f = tmp_path / "clean.txt"
        f.write_text("no secrets here\n")
        _, _, rc = rafter(f"secrets {f} --engine patterns --quiet")
        assert rc == 0


# ---------------------------------------------------------------------------
# Command risk assessment
# ---------------------------------------------------------------------------


class TestCommandRiskAssessment:
    def test_agent_exec_blocks_critical_commands(self):
        _, _, rc = rafter(["agent", "exec", "rm -rf /"])
        assert rc != 0

    def test_agent_exec_allows_safe_commands(self):
        _, _, rc = rafter(["agent", "exec", "echo hello"])
        assert rc == 0


# ---------------------------------------------------------------------------
# Agent mode flag
# ---------------------------------------------------------------------------


class TestAgentModeFlag:
    def test_agent_flag_produces_plain_output(self, tmp_path):
        f = tmp_path / "clean.txt"
        f.write_text("no secrets\n")
        stdout, _, rc = rafter(f"-a scan local {f} --engine patterns")
        assert rc == 0
        # Should not contain ANSI escape codes
        assert "\x1b[" not in stdout


# ---------------------------------------------------------------------------
# Agent scan deprecation
# ---------------------------------------------------------------------------


class TestAgentScanDeprecation:
    def test_agent_scan_emits_deprecation_warning(self, tmp_path):
        f = tmp_path / "clean.txt"
        f.write_text("no secrets\n")
        _, stderr, _ = rafter(f"agent scan {f} --engine patterns")
        assert "deprecated" in stderr.lower()
        assert "rafter secrets" in stderr

    def test_scan_local_does_not_emit_deprecation(self, tmp_path):
        f = tmp_path / "clean.txt"
        f.write_text("no secrets\n")
        _, stderr, _ = rafter(f"scan local {f} --engine patterns")
        assert "deprecated" not in stderr.lower()


# ---------------------------------------------------------------------------
# Version parity (node/package.json == python/pyproject.toml)
# ---------------------------------------------------------------------------


class TestVersionParity:
    def test_node_and_python_versions_match(self):
        node_pkg = json.loads(
            (_PROJECT_ROOT / "node" / "package.json").read_text()
        )
        pyproject = (_PROJECT_ROOT / "python" / "pyproject.toml").read_text()
        m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
        assert m, "Could not find version in pyproject.toml"
        assert node_pkg["version"] == m.group(1)


# ---------------------------------------------------------------------------
# Backend commands without API key
# ---------------------------------------------------------------------------


class TestBackendWithoutApiKey:
    def test_run_exits_1_without_api_key(self):
        _, stderr, rc = rafter(
            "run --repo test/repo --branch main",
            env_override={"RAFTER_API_KEY": ""},
        )
        assert rc == 1
        assert "api key" in stderr.lower() or "api key" in stderr

    def test_usage_exits_1_without_api_key(self):
        _, _, rc = rafter("usage", env_override={"RAFTER_API_KEY": ""})
        assert rc == 1
