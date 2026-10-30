"""sable-36oe: shell writes into rafter's own dir are protected (Python runtime).

A shell command that writes into ~/.rafter disarms the gate as surely as
``rafter agent config set agent.hooks.enabled false`` (rf-vnxs). Each protected
case is paired with a benign twin, so the table fails if the rule stops
catching the write OR starts blocking the read.

The battery JSON is shared byte-for-byte with the Node suite
(node/tests/risk-rules-rafter-dir.test.ts).
"""
import json
import time
import unittest
from pathlib import Path

from rafter_cli.core.risk_rules import assess_command_risk, modifies_rafter_security_config

_BATTERY_PATH = Path(__file__).resolve().parents[2] / "sable-36oe-rafter-dir-battery.json"
_BATTERY = json.loads(_BATTERY_PATH.read_text())


class TestRafterDirBattery(unittest.TestCase):
    def test_battery(self) -> None:
        self.assertTrue(_BATTERY, "battery fixture is empty")
        for case in _BATTERY:
            with self.subTest(label=case["label"]):
                self.assertEqual(modifies_rafter_security_config(case["cmd"]), case["protected"])
                if case["protected"]:
                    self.assertEqual(assess_command_risk(case["cmd"]), "critical")

    def test_adversarial_500kb_is_fast(self) -> None:
        # Fails if the scan goes superlinear: ~500 KB of `.rafter/` and `cat `
        # fragments, the shapes the component and glob walks touch.
        cmd = "cat ~/.rafter/" + "a.rafter/.raf*[/.rafter/cat " * 18000 + "| tee ~/.rafter/config.json"
        self.assertGreater(len(cmd), 500_000)
        t0 = time.perf_counter()
        self.assertTrue(modifies_rafter_security_config(cmd))
        self.assertLess(time.perf_counter() - t0, 5.0)


if __name__ == "__main__":
    unittest.main()
