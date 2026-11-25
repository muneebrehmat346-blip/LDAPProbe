"""Tests for payloads.py (Step 4) and reporter.py (Step 6)."""
import json
import os
import tempfile
import unittest

from ldapprobe.payloads import get_payloads
from ldapprobe.reporter import build_report, format_report_text, save_report


class TestPayloadTable(unittest.TestCase):
    def test_all_four_categories_present(self):
        categories = {p["category"] for p in get_payloads()}
        for expected in ("wildcard", "parentheses", "backslash", "nullbyte"):
            self.assertIn(expected, categories)

    def test_returned_list_is_a_copy(self):
        first = get_payloads()
        first[0]["value"] = "tampered"
        second = get_payloads()
        self.assertNotEqual(second[0]["value"], "tampered")

    def test_every_payload_has_required_fields(self):
        for payload in get_payloads():
            for field in ("id", "category", "value", "description"):
                self.assertIn(field, payload)


class TestReporter(unittest.TestCase):
    def _sample_results(self):
        return [
            {
                "payload_id": "wildcard-basic",
                "category": "wildcard",
                "payload_value": "*",
                "verdict": "vulnerable",
                "evidence": ["status changed: baseline 200 -> 200",
                             "login-success marker appeared: 'dashboard'"],
                "error_pattern": None,
            },
            {
                "payload_id": "backslash-bare",
                "category": "backslash",
                "payload_value": "\\",
                "verdict": "clean",
                "evidence": [],
                "error_pattern": None,
            },
        ]

    def test_overall_verdict_is_most_severe(self):
        report = build_report("http://lab/login", "username", "GET", self._sample_results())
        self.assertEqual(report["overall_verdict"], "vulnerable")
        self.assertIsNotNone(report["remediation_note"])

    def test_all_clean_has_no_remediation_note(self):
        clean_results = [dict(r, verdict="clean", evidence=[]) for r in self._sample_results()]
        report = build_report("http://lab/login", "username", "GET", clean_results)
        self.assertEqual(report["overall_verdict"], "clean")
        self.assertIsNone(report["remediation_note"])

    def test_format_report_text_mentions_vulnerable_parameter(self):
        report = build_report("http://lab/login", "username", "GET", self._sample_results())
        text = format_report_text(report)
        self.assertIn("username", text)
        self.assertIn("VULNERABLE", text)

    def test_save_report_writes_txt_and_json(self):
        report = build_report("http://lab/login", "username", "GET", self._sample_results())
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "report")
            text_path, json_path = save_report(report, out_path)
            self.assertTrue(os.path.exists(text_path))
            self.assertTrue(os.path.exists(json_path))
            with open(json_path) as f:
                loaded = json.load(f)
            self.assertEqual(loaded["parameter"], "username")


if __name__ == "__main__":
    unittest.main()
