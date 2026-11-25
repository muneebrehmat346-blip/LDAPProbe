# LDAPProbe

A command-line LDAP injection tester, built in Python for the PNY
Trainings "Build Your Own Security Tool" project. It finds parameters
in a web app's login or search form that build an LDAP filter from
user input without escaping it — a classic directory-injection flaw.

**Detection only.** LDAPProbe never extracts real directory data. It
compares responses to spot a difference, nothing more.

> **Lab-only tool.** Only run LDAPProbe against systems you own or
> have written permission to test, inside an isolated lab. Testing a
> login page or any system you do not own, without written
> authorization, is unauthorized access — a criminal offence in most
> jurisdictions, including under Pakistan's Prevention of Electronic
> Crimes Act, 2016.

## What it does

You give it a URL and a parameter name. It:

1. Sends a **baseline** request with a harmless value and records the
   status code, body, and length.
2. Sends the same request again with each payload from a **table** of
   LDAP filter metacharacters — wildcards, parentheses, backslashes,
   and null bytes, in single and combined forms.
3. **Compares** each payload response to the baseline on status code,
   response length, and login-success content markers.
4. Scans each response for **directory error text** (e.g.
   `LDAPException`, `invalid DN syntax`) that a misconfigured backend
   might leak.
5. Classifies the parameter as **vulnerable**, **possibly
   vulnerable**, or **clean**, with the evidence for that call.
6. Saves a report (`.txt` and `.json`) with the verdict, the evidence
   per payload, and a remediation note.

## How detection works

LDAPProbe never tries to parse or understand the target's LDAP
backend — it only watches for *differences* a successful injection
would cause:

| Signal | What it means |
|---|---|
| Status code changes | The payload broke something the baseline didn't |
| Response length changes by ≥15% | The page rendered different content (e.g. more results, an error page) |
| A login-success word appears (`welcome`, `dashboard`, `logout`, …) that wasn't in the baseline | The payload likely bypassed authentication |
| Directory error text appears in the body | The backend's LDAP library leaked an error, confirming the input reached a real filter |

A payload is marked **vulnerable** if a login-success marker appears,
or if both the status code and length changed together. It's
**possibly vulnerable** if only one of those changed, or if directory
error text showed up on its own. Otherwise it's **clean**.

This mirrors how a human tester would eyeball the difference between
two browser tabs — just automated and consistent across every payload.

## Project layout

```
ldapprobe/
  __init__.py
  __main__.py        # lets you run `python -m ldapprobe`
  cli.py              # argparse CLI, ties every step together (Steps 1, 6, 7)
  http_client.py      # sends the baseline/payload requests (Step 1)
  payloads.py         # the payload table (Steps 2, 4)
  comparator.py       # baseline-vs-response comparison (Step 3)
  error_patterns.py   # directory error text detection (Step 5)
  reporter.py         # builds and saves the report (Step 6)
tests/
  test_comparator.py
  test_error_patterns.py
  test_payloads_and_reporter.py
sample_report.txt      # a real run against a local toy lab stand-in (below)
sample_report.json
requirements.txt
README.md
```

## Installation

```bash
python3 -m venv venv
source venv/bin/activate        # on Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Running it

Against your own lab application:

```bash
python -m ldapprobe --url "http://localhost:8080/login" --param username --method GET
```

Options:

| Flag | Meaning | Default |
|---|---|---|
| `--url` | Target lab URL (required) | — |
| `--param` | Parameter name to test (required) | — |
| `--method` | `GET` or `POST` | `GET` |
| `--baseline-value` | Harmless value for the baseline request | `baseline_user` |
| `--output` | Report path, no extension | `ldapprobe_report` |
| `--timeout` | Per-request timeout in seconds | `10` |

This prints a live payload-by-payload verdict as it runs, then the
full report, then saves `<output>.txt` and `<output>.json`.

For a POST login form with a JSON-rendered error page, for example:

```bash
python -m ldapprobe --url "http://localhost:8080/api/login" --param username --method POST --output reports/login_test
```

## Testing

Every build step has its own tests, run against prepared responses —
no live server needed:

```bash
python -m unittest discover -s tests -v
```

All 16 tests should pass. These cover: the comparator's three
verdicts (Step 3), the error-pattern matcher (Step 5), the payload
table's shape (Step 4), and report building/saving (Step 6).

## Demo: a real end-to-end run

`sample_report.txt` / `sample_report.json` in this folder are **not**
fabricated — they're the actual output of running LDAPProbe against a
small local stand-in server built only to prove the tool end-to-end
offline (it fakes a naive, string-concatenated LDAP bind filter,
exactly the flaw the project is about). It correctly:

- Flagged `wildcard-basic` (`*`), both parenthesis-injection payloads,
  and the combined payload as **vulnerable** — each produced a
  `welcome`/`dashboard` login-success marker plus a length change.
- Flagged the hex-escaped backslash and the lone null byte as
  **possibly vulnerable** — the toy backend returned HTTP 500 with
  `LDAPException: Invalid DN syntax`, caught by the error-pattern
  check.
- Correctly marked a lone `)` and a bare `\` as **clean** — they
  didn't change anything in this particular toy backend.

Run `python -m unittest discover -s tests -v` yourself to see the step
tests pass, and point `--url` at your own CEH/MCSA-style lab VM for a
real demo against directory-backed infrastructure.

## One defensive lesson: escaping filter input

The flaw LDAPProbe looks for comes from building an LDAP filter with
string concatenation, e.g. `f"(uid={username})"`. If `username` can
contain `)`, `(`, `*`, `\`, or a null byte, it can rewrite the filter's
structure rather than just fill in a value.

The fix (RFC 4515) is to escape those five characters in any value
before it goes into a filter:

| Character | Escape |
|---|---|
| `*` | `\2a` |
| `(` | `\28` |
| `)` | `\29` |
| `\` | `\5c` |
| NUL | `\00` |

Most LDAP client libraries (e.g. Python's `ldap3`, via
`ldap3.utils.conv.escape_filter_chars`) do this for you — the
dangerous pattern is building the filter string by hand instead of
through the library's own filter/query builder.

## Stretch ideas (not required for the core rubric)

- Blind boolean inference: payloads like `*)(uid=*)(uid=*` vs a
  deliberately-false equivalent, inferring true/false from which
  response matches the baseline.
- POST body/JSON parameter support (the `http_client.send_request`
  function already separates GET/POST, so adding a `--body-format
  json` option is a small, contained change).
- Blind attribute enumeration against your own lab directory data
  only — never against data you don't control.
