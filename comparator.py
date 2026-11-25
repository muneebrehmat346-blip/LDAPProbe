"""Compares a payload response against the recorded baseline.

Step 3 of the build plan: one function, three checks (status, length,
content markers), one verdict out, with the evidence that led to it.
"""

LOGIN_SUCCESS_MARKERS = [
    "welcome",
    "dashboard",
    "logout",
    "my account",
    "logged in",
]


class Verdict:
    VULNERABLE = "vulnerable"
    POSSIBLY_VULNERABLE = "possibly vulnerable"
    CLEAN = "clean"


def compare_responses(baseline, test_response, length_threshold=0.15):
    """Compare test_response against baseline and return (verdict, evidence).

    - status: did the HTTP status code change?
    - length: did the response body length change by more than
      length_threshold (a fraction, default 15%)?
    - content markers: did a login-success word appear that wasn't in
      the baseline?

    evidence is a list of short strings explaining what was found, so
    the report can show its work instead of just a label.
    """
    evidence = []

    status_changed = test_response.status_code != baseline.status_code
    if status_changed:
        evidence.append(
            f"status changed: baseline {baseline.status_code} -> "
            f"{test_response.status_code}"
        )

    length_changed = _length_changed_significantly(
        baseline.length, test_response.length, length_threshold
    )
    if length_changed:
        evidence.append(
            f"response length changed: baseline {baseline.length} -> "
            f"{test_response.length} bytes"
        )

    login_marker = _find_login_success_marker(baseline.body, test_response.body)
    if login_marker:
        evidence.append(f"login-success marker appeared: '{login_marker}'")

    if login_marker or (status_changed and length_changed):
        return Verdict.VULNERABLE, evidence
    if status_changed or length_changed:
        return Verdict.POSSIBLY_VULNERABLE, evidence
    return Verdict.CLEAN, evidence


def _length_changed_significantly(baseline_length, test_length, threshold):
    if baseline_length == 0:
        return test_length != 0
    change = abs(test_length - baseline_length) / baseline_length
    return change >= threshold


def _find_login_success_marker(baseline_body, test_body):
    baseline_lower = baseline_body.lower()
    test_lower = test_body.lower()
    for marker in LOGIN_SUCCESS_MARKERS:
        if marker in test_lower and marker not in baseline_lower:
            return marker
    return None
