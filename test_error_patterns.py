"""Tests for error_patterns.py -- Step 5's 'clean vs error response' check."""
import unittest

from ldapprobe.error_patterns import find_directory_error


class TestFindDirectoryError(unittest.TestCase):
    def test_clean_response_has_no_match(self):
        self.assertIsNone(find_directory_error("Welcome back, please log in."))

    def test_error_response_is_matched(self):
        body = "Server error: LDAPException: Invalid DN syntax at position 4"
        self.assertEqual(find_directory_error(body), "ldapexception")

    def test_matching_is_case_insensitive(self):
        body = "LDAP: ERROR CODE 34 - invalid DN"
        self.assertEqual(find_directory_error(body), "ldap: error code")

    def test_unrelated_500_page_has_no_match(self):
        body = "<h1>500 Internal Server Error</h1><p>Something went wrong.</p>"
        self.assertIsNone(find_directory_error(body))


if __name__ == "__main__":
    unittest.main()
