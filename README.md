# LDAPProbe - LDAP Injection Tester

## Project Overview
LDAPProbe is a security testing tool for detecting LDAP Injection vulnerabilities in login forms. It is made for lab testing only.

## Features
- Tests 5 LDAP Injection payloads
- Detects Vulnerable vs Clean login
- Compares Vulnerable and Safe implementation
- Generates English report

## How to Run Lab
python3 app.py

## How to Test Vulnerable Login
python3 ldapprobe.py --url http://127.0.0.1:5000/login --param username --method POST --output report.txt

## How to Test Safe Login
python3 ldapprobe.py --url http://127.0.0.1:5000/safe-login --param username --method POST --output report-safe.txt

## Expected Result
- /login = VULNERABLE
- /safe-login = CLEAN

## Author
Muneeb Ali - PNY Trainings Final Project
