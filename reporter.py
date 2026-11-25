"""Builds and saves the LDAPProbe report.

Step 6 of the build plan: the report names the vulnerable parameter,
shows the evidence per payload, and ends with a remediation note.
"""
import json
from datetime import datetime, timezone

REMEDIATION_NOTE = (
    "Escape LDAP filter metacharacters in all user-supplied input before "
    "building a filter string: '(', ')', '*', '\\', and the null byte each "
    "need their own escape sequence (see RFC 4515) -- or better, use a "
    "library/binding that builds filters from parts instead of string "
    "concatenation. Never trust a login or search parameter as safe just "
    "because it came from a form your own app renders."
)


def build_report(target_url, param_name, method, results):
    """results is a list of dicts: payload_id, category, payload_value,
    verdict, evidence, error_pattern.

    Returns a dict with the full report and one overall verdict, taking
    the most severe verdict across all payloads tried.
    """
    vulnerable_hits = [r for r in results if r["verdict"] == "vulnerable"]
    possible_hits = [r for r in results if r["verdict"] == "possibly vulnerable"]

    if vulnerable_hits:
        overall = "vulnerable"
    elif possible_hits:
        overall = "possibly vulnerable"
    else:
        overall = "clean"

    return {
        "tool": "LDAPProbe",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_url": target_url,
        "parameter": param_name,
        "method": method.upper(),
        "overall_verdict": overall,
        "results": results,
        "remediation_note": REMEDIATION_NOTE if overall != "clean" else None,
    }


def format_report_text(report):
    """Render the report dict as the human-readable text that gets saved and printed."""
    lines = []
    lines.append("LDAPProbe Report")
    lines.append("=" * 40)
    lines.append(f"Generated:  {report['generated_at']}")
    lines.append(f"Target URL: {report['target_url']}")
    lines.append(f"Parameter:  {report['parameter']}")
    lines.append(f"Method:     {report['method']}")
    lines.append(f"Verdict:    {report['overall_verdict'].upper()}")
    lines.append("")
    lines.append("Payload results:")
    lines.append("-" * 40)
    for r in report["results"]:
        lines.append(f"[{r['verdict'].upper():<18}] {r['payload_id']} ({r['category']})")
        lines.append(f"    value: {r['payload_value']!r}")
        if r.get("error_pattern"):
            lines.append(f"    directory error text found: '{r['error_pattern']}'")
        for e in r["evidence"]:
            lines.append(f"    evidence: {e}")
        lines.append("")
    if report["remediation_note"]:
        lines.append("Remediation")
        lines.append("-" * 40)
        lines.append(report["remediation_note"])
    return "\n".join(lines)


def save_report(report, path):
    """Save both a human-readable .txt and a machine-readable .json report.

    path is given without extension (e.g. 'ldapprobe_report'); both
    files are written next to each other.
    """
    text_path = path if path.endswith(".txt") else path + ".txt"
    json_path = text_path[:-4] + ".json"

    with open(text_path, "w", encoding="utf-8") as f:
        f.write(format_report_text(report))

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return text_path, json_path
