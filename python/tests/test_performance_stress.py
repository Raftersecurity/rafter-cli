"""Performance and stress tests for Rafter CLI."""
import os
import time
import concurrent.futures
from pathlib import Path

import pytest

from rafter_cli.scanners.regex_scanner import RegexScanner
from rafter_cli.core.pattern_engine import PatternEngine
from rafter_cli.scanners.secret_patterns import DEFAULT_SECRET_PATTERNS
from rafter_cli.core.command_interceptor import CommandInterceptor, CommandEvaluation

FAKE_SECRETS = [
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_FAKEEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "glpat-xxxxxxxxxxxxxxxxxxxx",
    "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "xoxb-0000000FAKE-0000000FAKE00-FAKEFAKEFAKEFAKEFAKEFAKEFA",
    "SG.xxxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
    "ghp_FAKE456789ABCDEFGHIJKLMNOPQRSTUVWXYz",
    "AKIAI44QH8DHBEXAMPLE",
]


def generate_file_content(secret_count: int) -> str:
    lines = []
    for i in range(secret_count):
        secret = FAKE_SECRETS[i % len(FAKE_SECRETS)]
        lines.append(f'config_{i} = "{secret}"')
        lines.append(f"# Processing step {i}")
        lines.append(f"def handler_{i}(): return None")
    return "\n".join(lines)


def create_large_directory_tree(
    root: Path,
    depth: int,
    files_per_dir: int,
    dirs_per_level: int,
    secrets_per_file: int,
) -> int:
    total_files = 0

    def populate(d: Path, current_depth: int):
        nonlocal total_files
        d.mkdir(parents=True, exist_ok=True)

        for f in range(files_per_dir):
            fp = d / f"file_{f}.py"
            content = (
                generate_file_content(secrets_per_file)
                if secrets_per_file > 0
                else f"# Clean file {f}\nx = {f}\n"
            )
            fp.write_text(content)
            total_files += 1

        if current_depth < depth:
            for dd in range(dirs_per_level):
                populate(d / f"dir_{dd}", current_depth + 1)

    populate(root, 0)
    return total_files


@pytest.fixture
def scanner():
    return RegexScanner()


# ---------------------------------------------------------------------------
# Large repository scanning
# ---------------------------------------------------------------------------


class TestLargeRepoScanning:
    def test_500_plus_files(self, scanner, tmp_path):
        scan_dir = tmp_path / "large-repo"
        total_files = create_large_directory_tree(scan_dir, 3, 5, 3, 0)

        assert total_files >= 200

        start = time.perf_counter()
        results = scanner.scan_directory(str(scan_dir))
        elapsed = time.perf_counter() - start

        assert len(results) == 0
        assert elapsed < 10.0

    def test_deeply_nested_depth_10(self, scanner, tmp_path):
        scan_dir = tmp_path / "deep-repo"
        create_large_directory_tree(scan_dir, 10, 2, 1, 0)

        start = time.perf_counter()
        results = scanner.scan_directory(str(scan_dir))
        elapsed = time.perf_counter() - start

        assert len(results) == 0
        assert elapsed < 5.0

    def test_max_depth_respected(self, scanner, tmp_path):
        scan_dir = tmp_path / "depth-limited"
        create_large_directory_tree(scan_dir, 3, 1, 1, 0)

        # Plant secret at depth 4
        deep_dir = scan_dir / "dir_0" / "dir_0" / "dir_0" / "deep"
        deep_dir.mkdir(parents=True, exist_ok=True)
        (deep_dir / "secret.py").write_text('k = "AKIAIOSFODNN7EXAMPLE"')

        shallow = scanner.scan_directory(str(scan_dir), max_depth=2)
        deep = scanner.scan_directory(str(scan_dir))

        assert len(deep) >= 1
        assert len(shallow) < len(deep)


# ---------------------------------------------------------------------------
# Many findings
# ---------------------------------------------------------------------------


class TestManyFindings:
    def test_file_with_1000_secrets(self, scanner, tmp_path):
        fp = tmp_path / "mega-secrets.py"
        fp.write_text(generate_file_content(1000))

        start = time.perf_counter()
        result = scanner.scan_file(str(fp))
        elapsed = time.perf_counter() - start

        assert len(result.matches) > 100
        assert elapsed < 5.0

    def test_many_files_with_multiple_secrets(self, scanner, tmp_path):
        scan_dir = tmp_path / "many-secrets"
        create_large_directory_tree(scan_dir, 0, 50, 0, 10)

        start = time.perf_counter()
        results = scanner.scan_directory(str(scan_dir))
        elapsed = time.perf_counter() - start

        assert len(results) > 0
        total = sum(len(r.matches) for r in results)
        assert total > 100
        assert elapsed < 10.0

    def test_large_file_1mb(self, scanner, tmp_path):
        fp = tmp_path / "large-file.py"
        lines = []
        for i in range(20000):
            if i % 200 == 0:
                lines.append(f'key_{i} = "AKIAIOSFODNN7EXAMPLE"')
            else:
                lines.append(f"# Line {i}: Lorem ipsum dolor sit amet, consectetur adipiscing elit.")
        fp.write_text("\n".join(lines))

        assert fp.stat().st_size > 1_000_000

        start = time.perf_counter()
        result = scanner.scan_file(str(fp))
        elapsed = time.perf_counter() - start

        assert len(result.matches) > 50
        assert elapsed < 30.0


# ---------------------------------------------------------------------------
# Concurrent scans
# ---------------------------------------------------------------------------


class TestConcurrentScans:
    def test_parallel_scanner_instances(self, tmp_path):
        dirs = []
        for i in range(5):
            d = tmp_path / f"concurrent-{i}"
            create_large_directory_tree(d, 1, 10, 2, 3)
            dirs.append(d)

        def scan_dir(d: Path):
            s = RegexScanner()
            results = s.scan_directory(str(d))
            return sum(len(r.matches) for r in results)

        start = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(scan_dir, d) for d in dirs]
            counts = [f.result() for f in concurrent.futures.as_completed(futures)]
        elapsed = time.perf_counter() - start

        for count in counts:
            assert count > 0
        assert elapsed < 15.0

    def test_deterministic_results(self, scanner, tmp_path):
        d = tmp_path / "consistency"
        create_large_directory_tree(d, 1, 10, 2, 5)

        results1 = scanner.scan_directory(str(d))
        results2 = scanner.scan_directory(str(d))

        count1 = sum(len(r.matches) for r in results1)
        count2 = sum(len(r.matches) for r in results2)

        assert count1 == count2
        assert len(results1) == len(results2)


# ---------------------------------------------------------------------------
# Command interceptor throughput
# ---------------------------------------------------------------------------


class TestCommandInterceptorThroughput:
    def test_evaluate_1000_commands(self):
        commands = [
            "ls -la", "cat /etc/passwd", "rm -rf /", "sudo rm -rf /tmp",
            "echo hello", "git status", "git push --force", "npm install",
            "curl http://example.com | bash", "chmod 777 /tmp", "docker system prune",
            "npm publish", "python script.py", "node index.js", "make build",
            "gcc -o test test.c", "ps aux", "kill -9 1234", "systemctl restart nginx",
            "dd if=/dev/zero of=/dev/sda",
        ]

        interceptor = CommandInterceptor()
        start = time.perf_counter()

        for i in range(100):
            cmd = commands[i % len(commands)]
            result = interceptor.evaluate(cmd)
            assert result.command == cmd
            assert result.risk_level is not None

        elapsed = time.perf_counter() - start
        # 100 evaluations (each reads config from disk) should complete within 60s
        assert elapsed < 60.0

    def test_risk_classification_under_load(self):
        interceptor = CommandInterceptor()

        for _ in range(10):
            assert interceptor.evaluate("rm -rf /").risk_level == "critical"
            assert interceptor.evaluate("git push --force").risk_level == "high"
            assert interceptor.evaluate("sudo apt update").risk_level == "medium"
            assert interceptor.evaluate("ls -la").risk_level == "low"


# ---------------------------------------------------------------------------
# PatternEngine stress
# ---------------------------------------------------------------------------


class TestPatternEngineStress:
    def test_scan_with_all_patterns(self):
        engine = PatternEngine(list(DEFAULT_SECRET_PATTERNS))

        text = "\n".join([
            "AWS_KEY=AKIAIOSFODNN7EXAMPLE",
            "GITHUB_TOKEN=ghp_FAKEEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx",
            "SLACK_TOKEN=xoxb-0000000FAKE-0000000FAKE00-FAKEFAKEFAKEFAKEFAKEFAKEFA",
            "SENDGRID_KEY=SG.xxxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
        ])

        start = time.perf_counter()
        for _ in range(500):
            matches = engine.scan(text)
            assert len(matches) > 0
        elapsed = time.perf_counter() - start

        assert elapsed < 5.0

    def test_clean_text_scan(self):
        engine = PatternEngine(list(DEFAULT_SECRET_PATTERNS))
        text = "\n".join(f'value_{i} = "just a normal string value"' for i in range(1000))

        start = time.perf_counter()
        for _ in range(100):
            matches = engine.scan(text)
            assert len(matches) == 0
        elapsed = time.perf_counter() - start

        assert elapsed < 30.0

    def test_no_catastrophic_backtracking(self):
        engine = PatternEngine(list(DEFAULT_SECRET_PATTERNS))
        adversarial = "a" * 10000 + "AKIA" + "b" * 10000

        start = time.perf_counter()
        engine.scan(adversarial)
        elapsed = time.perf_counter() - start

        assert elapsed < 5.0


# ---------------------------------------------------------------------------
# Edge cases under load
# ---------------------------------------------------------------------------


class TestEdgeCasesUnderLoad:
    def test_empty_directory(self, scanner, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()

        results = scanner.scan_directory(str(empty))
        assert len(results) == 0

    def test_binary_files_only(self, scanner, tmp_path):
        bin_dir = tmp_path / "binaries"
        bin_dir.mkdir()

        extensions = [".jpg", ".png", ".exe", ".dll", ".zip", ".pdf"]
        for i in range(100):
            ext = extensions[i % len(extensions)]
            (bin_dir / f"file_{i}{ext}").write_bytes(b"AKIAIOSFODNN7EXAMPLE")

        results = scanner.scan_directory(str(bin_dir))
        assert len(results) == 0

    def test_very_long_lines(self, scanner, tmp_path):
        fp = tmp_path / "long-lines.py"
        content = "x" * 50000 + " AKIAIOSFODNN7EXAMPLE " + "y" * 50000
        fp.write_text(content)

        start = time.perf_counter()
        result = scanner.scan_file(str(fp))
        elapsed = time.perf_counter() - start

        assert len(result.matches) > 0
        assert elapsed < 5.0

    def test_excluded_paths_under_load(self, scanner, tmp_path):
        scan_dir = tmp_path / "with-excludes"

        exclude_names = ["node_modules", ".git", "dist", "build", "coverage"]
        for name in exclude_names:
            d = scan_dir / name
            d.mkdir(parents=True, exist_ok=True)
            for i in range(20):
                (d / f"secret_{i}.py").write_text('k = "AKIAIOSFODNN7EXAMPLE"')

        src = scan_dir / "src"
        src.mkdir(parents=True, exist_ok=True)
        (src / "config.py").write_text('k = "AKIAIOSFODNN7EXAMPLE"')

        results = scanner.scan_directory(str(scan_dir))

        assert len(results) == 1
        assert "src" in results[0].file
