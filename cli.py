"""LDAPProbe command-line interface.

Steps 1-6 of the build plan meet here: fetch a baseline, run every
payload, compare each response, scan for directory errors, and save
the report. Step 7 is simply: point this at your lab app.
"""
import argparse
import sys

from .comparator import compare_responses
from .error_patterns import find_directory_error
from .http_client import send_request
from .payloads import get_payloads
from .reporter import build_report, format_report_text, save_report

LAB_WARNING = (
    "LDAPProbe is a lab-only detection tool. Only run it against systems "
    "you own or have written permission to test, inside an isolated lab "
    "environment. It never extracts real directory data -- detection only."
)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="ldapprobe",
        description="Detect LDAP injection in a web app's login or search parameter.",
    )
    parser.add_argument(
        "--url", required=True,
        help="Target URL, e.g. http://localhost:8080/login",
    )
    parser.add_argument(
        "--param", required=True,
        help="Parameter name to test, e.g. username",
    )
    parser.add_argument(
        "--method", default="GET", choices=["GET", "POST", "get", "post"],
        help="HTTP method to use (default: GET)",
    )
    parser.add_argument(
        "--baseline-value", default="baseline_user",
        help="Harmless value used for the baseline request (default: baseline_user)",
    )
    parser.add_argument(
        "--output", default="ldapprobe_report",
        help="Report file path without extension (default: ldapprobe_report)",
    )
    parser.add_argument(
        "--timeout", type=float, default=10,
        help="Per-request timeout in seconds (default: 10)",
    )
    return parser.parse_args(argv)


def run(args):
    print(LAB_WARNING)
    print()
    print(f"Fetching baseline from {args.url} (param={args.param!r}) ...")
    try:
        baseline = send_request(
            args.url, args.method, args.param, args.baseline_value, args.timeout
        )
    except Exception as exc:
        print(f"Could not fetch baseline: {exc}", file=sys.stderr)
        return 1
    print(f"Baseline: status={baseline.status_code} length={baseline.length}")
    print()

    results = []
    for payload in get_payloads():
        try:
            resp = send_request(
                args.url, args.method, args.param, payload["value"], args.timeout
            )
        except Exception as exc:
            results.append({
                "payload_id": payload["id"],
                "category": payload["category"],
                "payload_value": payload["value"],
                "verdict": "error",
                "evidence": [f"request failed: {exc}"],
                "error_pattern": None,
            })
            print(f"  {payload['id']:<24} -> request failed")
            continue

        verdict, evidence = compare_responses(baseline, resp)
        error_pattern = find_directory_error(resp.body)
        if error_pattern and verdict == "clean":
            verdict = "possibly vulnerable"
            evidence.append(f"directory error text: '{error_pattern}'")

        results.append({
            "payload_id": payload["id"],
            "category": payload["category"],
            "payload_value": payload["value"],
            "verdict": verdict,
            "evidence": evidence,
            "error_pattern": error_pattern,
        })
        print(f"  {payload['id']:<24} -> {verdict}")

    report = build_report(args.url, args.param, args.method, results)
    print()
    print(format_report_text(report))

    text_path, json_path = save_report(report, args.output)
    print()
    print(f"Report saved to {text_path} and {json_path}")
    return 0


def main(argv=None):
    args = parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
