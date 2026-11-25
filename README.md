# LDAPProbe - LDAP Injection Tester

A simple Python tool to test websites for LDAP Injection vulnerability.
Made for Final Project - PNT Trainings.

## Author
Muneeb Ali

## Features
- Tests multiple LDAP payloads
- Supports GET and POST methods
- Detects possible LDAP Injection
- Simple CLI interface

## Usage

```bash
python3 ldap_probe.py --url http://127.0.0.1:5000/login --param username

