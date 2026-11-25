"""Tests for comparator.py -- Step 3's 'feed it three prepared responses' check.

No network involved: ProbeResponse objects are built by hand.
"""
import unittest

from ldapprobe.comparator import Verdict, compare_responses
from ldapprobe.http_client import ProbeResponse


class TestCompareResponses(unittest.TestCase):
    def setUp(self):
        self.baseline = ProbeResponse(200, "Please log in" * 10, 0.05)

    def test_unchanged_response_is_clean(self):
        unchanged = ProbeResponse(200, "Please log in" * 10, 0.05)
        verdict, evidence = compare_responses(self.baseline, unchanged)
        self.assertEqual(verdict, Verdict.CLEAN)
        self.assertEqual(evidence, [])

    def test_login_success_marker_is_vulnerable(self):
        changed = ProbeResponse(200, "Welcome to your dashboard", 0.05)
        verdict, evidence = compare_responses(self.baseline, changed)
        self.assertEqual(verdict, Verdict.VULNERABLE)
        self.assertTrue(any("marker" in e for e in evidence))

    def test_status_and_length_change_is_vulnerable(self):
        error_like = ProbeResponse(500, "Internal error, nothing else here", 0.05)
        verdict, evidence = compare_responses(self.baseline, error_like)
        self.assertEqual(verdict, Verdict.VULNERABLE)
        self.assertEqual(len(evidence), 2)

    def test_length_only_change_is_possibly_vulnerable(self):
        # baseline body is 140 chars; add enough extra text to clear the
        # default 15% length-change threshold (>= 21 chars) without
        # touching the status code or any login-success marker.
        slightly_longer = ProbeResponse(200, "Please log in" * 10 + "quite a bit of extra text", 0.05)
        verdict, evidence = compare_responses(self.baseline, slightly_longer)
        self.assertEqual(verdict, Verdict.POSSIBLY_VULNERABLE)

    def test_empty_baseline_handles_division_safely(self):
        empty_baseline = ProbeResponse(200, "", 0.01)
        nonempty = ProbeResponse(200, "now there is content", 0.01)
        verdict, evidence = compare_responses(empty_baseline, nonempty)
        self.assertEqual(verdict, Verdict.POSSIBLY_VULNERABLE)


if __name__ == "__main__":
    unittest.main()
