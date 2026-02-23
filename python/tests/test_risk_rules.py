"""Tests for force push detection in risk_rules."""
import re
import unittest

from rafter_cli.core.risk_rules import (
    assess_command_risk,
    HIGH_PATTERNS,
    DEFAULT_REQUIRE_APPROVAL,
)


class TestForcePushDetection(unittest.TestCase):
    """HIGH_PATTERNS should detect all force push variants."""

    def test_git_push_force(self):
        self.assertEqual(assess_command_risk("git push --force origin main"), "high")

    def test_git_push_force_bare(self):
        self.assertEqual(assess_command_risk("git push --force"), "high")

    def test_git_push_f(self):
        self.assertEqual(assess_command_risk("git push -f origin main"), "high")

    def test_git_push_f_bare(self):
        self.assertEqual(assess_command_risk("git push -f"), "high")

    def test_git_push_force_with_lease(self):
        self.assertEqual(assess_command_risk("git push --force-with-lease origin main"), "high")

    def test_git_push_force_with_lease_bare(self):
        self.assertEqual(assess_command_risk("git push --force-with-lease"), "high")

    def test_git_push_force_if_includes(self):
        self.assertEqual(assess_command_risk("git push --force-if-includes origin main"), "high")

    def test_git_push_force_if_includes_bare(self):
        self.assertEqual(assess_command_risk("git push --force-if-includes"), "high")

    def test_refspec_push_plus_main(self):
        self.assertEqual(assess_command_risk("git push origin +main"), "high")

    def test_refspec_push_plus_refs(self):
        self.assertEqual(assess_command_risk("git push origin +refs/heads/main"), "high")

    def test_combined_flags_vf(self):
        self.assertEqual(assess_command_risk("git push -vf origin main"), "high")

    def test_git_push_origin_force(self):
        self.assertEqual(assess_command_risk("git push origin --force"), "high")

    def test_git_push_origin_f(self):
        self.assertEqual(assess_command_risk("git push origin -f"), "high")

    def test_normal_push_not_flagged(self):
        self.assertEqual(assess_command_risk("git push origin main"), "low")

    def test_bare_push_not_flagged(self):
        self.assertEqual(assess_command_risk("git push"), "low")

    def test_no_false_positive_branch_with_hyphen(self):
        self.assertEqual(assess_command_risk("git push origin feature-fix"), "low")


class TestDefaultRequireApproval(unittest.TestCase):
    """DEFAULT_REQUIRE_APPROVAL should list all force push variants."""

    def test_includes_force(self):
        self.assertIn("git push --force", DEFAULT_REQUIRE_APPROVAL)

    def test_includes_f(self):
        self.assertIn("git push -f", DEFAULT_REQUIRE_APPROVAL)

    def test_includes_force_with_lease(self):
        self.assertIn("git push --force-with-lease", DEFAULT_REQUIRE_APPROVAL)

    def test_includes_force_if_includes(self):
        self.assertIn("git push --force-if-includes", DEFAULT_REQUIRE_APPROVAL)

    def test_includes_refspec_pattern(self):
        self.assertIn(r"git push .* \+", DEFAULT_REQUIRE_APPROVAL)


class TestHighPatternsCompleteness(unittest.TestCase):
    """HIGH_PATTERNS should have patterns covering all force push variants."""

    def test_force_push_pattern_count(self):
        force_push_patterns = [
            p for p in HIGH_PATTERNS
            if re.search(p, "git push --force", re.IGNORECASE)
            or re.search(p, "git push -f", re.IGNORECASE)
            or re.search(p, "git push origin +main", re.IGNORECASE)
        ]
        self.assertGreaterEqual(len(force_push_patterns), 3)


if __name__ == "__main__":
    unittest.main()
