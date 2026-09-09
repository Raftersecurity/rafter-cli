"""rf-6pqx + rf-3rsj + public #230 regression battery (Python runtime).

A newline is a statement separator (rf-6pqx): ``echo x\\nrm -rf /`` must not be
hidden by the leading text-exec. Heredoc bodies a command consumes as DATA are
stripped so the newline fix does not make ordinary documentation writes CRITICAL
(rf-3rsj) — the same over-block public #230 reported — while a body EXECUTED by a
shell/eval owner (``bash <<EOF``) stays scannable (se-y6vo). Also covers
backslash-newline line continuations and fail-closed-on-unterminated-quote.

The battery JSON is shared BYTE-FOR-BYTE with the Node suite
(node/tests/risk-rules-newline-heredoc.test.ts) so a Python-clean result cannot
hide a Node bug, and vice versa. Co-designed with kerckhoffs (se-ijzs) and
achebe (#230).
"""
import json
import unittest
from pathlib import Path

from rafter_cli.core.risk_rules import assess_command_risk

_BATTERY_PATH = Path(__file__).resolve().parents[2] / "rf-6pqx-newline-heredoc-battery.json"
_BATTERY = json.loads(_BATTERY_PATH.read_text())


class TestNewlineHeredocBattery(unittest.TestCase):
    def test_battery(self) -> None:
        self.assertTrue(_BATTERY, "battery fixture is empty")
        for case in _BATTERY:
            with self.subTest(label=case["label"]):
                self.assertIn(assess_command_risk(case["cmd"]), set(case["want"]))


if __name__ == "__main__":
    unittest.main()
