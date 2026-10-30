"""sable-3n3l: a subprocess a test spawns must import THIS checkout's
rafter_cli, not whatever an editable or global install points at."""
import subprocess
import sys
from pathlib import Path

REPO_PYTHON = Path(__file__).resolve().parent.parent


def test_subprocess_imports_this_checkout(tmp_path):
    out = subprocess.run(
        [sys.executable, "-c", "import rafter_cli; print(rafter_cli.__file__)"],
        cwd=tmp_path, capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert Path(out).resolve().is_relative_to(REPO_PYTHON)
