"""Differential-vs-main gate (rf-6pqx). Runs a generated shell-argument corpus
through BOTH origin/main's classifier and this working tree's, and asserts the
candidate is NEVER more permissive than main except a pure data-heredoc body
(the one construct #230 intentionally strips).

Committed so the check is part of the gate, not something someone happened to
run: the stop-ship on db9a809 slipped past a battery whose only here-string case
was single-line. FAILS LOUDLY if the main baseline cannot be obtained — a
differential that silently skips is a vacuous check.
"""
import subprocess, sys, tempfile, unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_CANDIDATE = _REPO / "python" / "rafter_cli" / "core" / "risk_rules.py"
_DIFF = Path(__file__).resolve().parent / "rf6pqx_differential.py"
_MAIN_PATH = "python/rafter_cli/core/risk_rules.py"


class TestRf6pqxDifferential(unittest.TestCase):
    def test_candidate_never_more_permissive_than_main(self) -> None:
        blob = subprocess.run(["git", "show", f"origin/main:{_MAIN_PATH}"],
                              cwd=_REPO, capture_output=True, text=True)
        if blob.returncode != 0 or not blob.stdout.strip():
            blob = subprocess.run(["git", "show", f"main:{_MAIN_PATH}"],
                                  cwd=_REPO, capture_output=True, text=True)
        self.assertEqual(blob.returncode, 0,
                         f"could not obtain main baseline for the differential gate: {blob.stderr}")
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
            tf.write(blob.stdout); main_path = tf.name
        res = subprocess.run([sys.executable, str(_DIFF), main_path, str(_CANDIDATE)],
                             capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"differential not clean:\n{res.stdout}\n{res.stderr}")


if __name__ == "__main__":
    unittest.main()
