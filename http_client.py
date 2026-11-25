"""HTTP client wrapper for LDAPProbe.

Sends requests to the target lab application and returns a small,
testable response object instead of leaking the `requests` library's
details into the rest of the tool. This keeps comparator.py and
error_patterns.py free of any network code, so they can be unit
tested with plain Python objects (see tests/).
"""
import time

import requests


class ProbeResponse:
    """A normalized response: just what LDAPProbe needs to compare."""

    def __init__(self, status_code, body, elapsed_seconds):
        self.status_code = status_code
        self.body = body
        self.length = len(body)
        self.elapsed_seconds = elapsed_seconds

    def __repr__(self):
        return f"ProbeResponse(status={self.status_code}, length={self.length})"


def send_request(url, method, param_name, param_value, timeout=10):
    """Send one request with param_name set to param_value.

    method is 'GET' or 'POST' (case-insensitive). For GET, the
    parameter is sent as a query string parameter. For POST, it is
    sent as a form field. Returns a ProbeResponse.

    Raises requests.RequestException (or ValueError for a bad method)
    so the caller decides how to handle a failed request.
    """
    method = method.upper()
    start = time.monotonic()
    if method == "GET":
        resp = requests.get(url, params={param_name: param_value}, timeout=timeout)
    elif method == "POST":
        resp = requests.post(url, data={param_name: param_value}, timeout=timeout)
    else:
        raise ValueError(f"Unsupported method: {method!r} (use GET or POST)")
    elapsed = time.monotonic() - start
    return ProbeResponse(resp.status_code, resp.text, elapsed)
