#!/usr/bin/env python3
"""
python Session_Auth.py --login-url http://localhost:8080/login.php


Customized for:
Fields: username, password
Default credential tested: admin:password

Outputs:
    week5_auth_session_results.csv
"""

import argparse
import csv
import json
import os
import random
import re
import time
from urllib.parse import urljoin, urlparse

import requests

# -------------------------------------------------------------------
# CONFIGURATION
# -------------------------------------------------------------------
DEFAULT_LOGIN_URL = "http://localhost/login.php"
DEFAULT_INPUTS = {"username": "", "password": "", "Login": "Login"}

DEFAULT_WORDLIST = [
    "admin:password",
    "admin:admin",
    "root:root",
    "user:user"
]

DEFAULT_BRUTE_PASSWORDS = [
    "password",
    "123456",
    "admin",
    "dvwa",
    "password1"
]

HEADERS = {"User-Agent": "WebScanPro-AuthTester/1.0"}
DEFAULT_TIMEOUT = 10

DEFAULT_PROTECTED_PATHS = [
    "/index.php",
    "/dvwa/index.php",
    "/dvwa/vulnerabilities/sqli/"
]

REPORT_FIELDS = [
    "test_type", "target", "endpoint",
    "username", "password",
    "status_code", "evidence", "notes",
    "cookie_name", "cookie_value", "cookie_flags"
]


# -------------------------------------------------------------------
# Helper Functions
# -------------------------------------------------------------------

def cookie_entropy_heuristic(val):
    """Check predictability of session IDs."""
    if not val:
        return 0
    score = len(val)
    charset = 0
    if re.search(r"[a-z]", val): charset += 1
    if re.search(r"[A-Z]", val): charset += 1
    if re.search(r"[0-9]", val): charset += 1
    if re.search(r"[^A-Za-z0-9]", val): charset += 1
    return score * charset


def parse_cookie_flags(set_cookie_header):
    flags = {}
    if not set_cookie_header:
        return flags

    parts = [p.strip() for p in set_cookie_header.split(";")]

    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            flags[k.lower()] = v
        else:
            flags[p.lower()] = True

    return flags


def attempt_request(session, endpoint, method, data):
    try:
        if method.lower() == "get":
            return session.get(endpoint, params=data, headers=HEADERS, timeout=DEFAULT_TIMEOUT)
        else:
            return session.post(endpoint, data=data, headers=HEADERS, timeout=DEFAULT_TIMEOUT)
    except Exception:
        return None


def guess_login_point(login_url):
    return {
        "page_url": login_url,
        "action": login_url,
        "method": "post",
        "inputs": dict(DEFAULT_INPUTS)
    }


# -------------------------------------------------------------------
# Test: Cookie Flag Analysis
# -------------------------------------------------------------------

def test_cookie_flags(session, point, writer, target):
    endpoint = point["page_url"]

    try:
        r = session.get(endpoint, headers=HEADERS, timeout=DEFAULT_TIMEOUT)
    except Exception:
        r = None

    cookies = []

    if r:
        raw_sc = []
        for k, v in r.headers.items():
            if k.lower() == "set-cookie":
                raw_sc.append(v)

        if raw_sc:
            for sc in raw_sc:
                nv = sc.split(";", 1)[0]
                if "=" in nv:
                    n, v = nv.split("=", 1)
                else:
                    n, v = nv, ""
                cookies.append((n.strip(), v.strip(), parse_cookie_flags(sc)))
        else:
            for c in r.cookies:
                cookies.append((c.name, c.value, {}))

    for name, val, flags in cookies:
        flag_str = ",".join([
            f"{k}={v}" if v is not True else k
            for k, v in flags.items()
        ]) if flags else ""

        issues = []

        if "httponly" not in flags:
            issues.append("missing_HttpOnly")
        if "secure" not in flags:
            issues.append("missing_Secure")
        if "samesite" not in flags:
            issues.append("missing_SameSite")

        if cookie_entropy_heuristic(val) < 100:
            issues.append("low_entropy_session_id")

        writer.writerow({
            "test_type": "cookie_analysis",
            "target": target,
            "endpoint": endpoint,
            "username": "",
            "password": "",
            "status_code": r.status_code if r else None,
            "evidence": ";".join(issues),
            "notes": "",
            "cookie_name": name,
            "cookie_value": val,
            "cookie_flags": flag_str
        })


# -------------------------------------------------------------------
# Test: Weak / Default Credentials
# -------------------------------------------------------------------

def test_weak_credentials(session, point, combos, writer, target):
    endpoint = point["action"]
    method = point["method"]

    for combo in combos:
        user, pwd = combo.split(":", 1)

        data = dict(point["inputs"])
        data["username"] = user
        data["password"] = pwd

        r = attempt_request(session, endpoint, method, data)

        status = r.status_code if r else None
        evidence = []
        notes = ""

        if r:
            body = r.text.lower()
            if "logout" in body or "welcome" in body or r.history:
                evidence.append("login_success")
                notes = "Login appeared successful"
            elif "incorrect" in body or "invalid" in body:
                notes = "Login failed"
            else:
                notes = "Unclear response"
        else:
            notes = "Request failed"

        writer.writerow({
            "test_type": "weak_credential",
            "target": target,
            "endpoint": endpoint,
            "username": user,
            "password": pwd,
            "status_code": status,
            "evidence": ";".join(evidence),
            "notes": notes,
            "cookie_name": "",
            "cookie_value": "",
            "cookie_flags": ""
        })

        time.sleep(0.4)


# -------------------------------------------------------------------
# Test: Brute Force
# -------------------------------------------------------------------

def test_bruteforce(session, point, usernames, passwords, writer, target):
    endpoint = point["action"]

    for user in usernames:
        for pwd in passwords:
            data = dict(point["inputs"])
            data["username"] = user
            data["password"] = pwd

            r = attempt_request(session, endpoint, "post", data)

            status = r.status_code if r else None
            evidence = []
            notes = ""

            if r:
                body = r.text.lower()
                if "logout" in body or r.history:
                    evidence.append("login_success")
                    notes = "Bruteforce success"
                elif "incorrect" in body:
                    notes = "Invalid attempt"
                else:
                    notes = "Unclear response"
            else:
                notes = "Request failed"

            writer.writerow({
                "test_type": "bruteforce",
                "target": target,
                "endpoint": endpoint,
                "username": user,
                "password": pwd,
                "status_code": status,
                "evidence": ";".join(evidence),
                "notes": notes,
                "cookie_name": "",
                "cookie_value": "",
                "cookie_flags": ""
            })

            time.sleep(0.3)


# -------------------------------------------------------------------
# Test: Session Fixation (Fixed Version)
# -------------------------------------------------------------------

def test_session_fixation(point, writer, target):
    endpoint = point["action"]
    method = point["method"]

    candidate_cookie_names = ["PHPSESSID", "session", "SID"]

    fixed_value = "fixed_" + str(random.randint(1000, 9999))

    for cname in candidate_cookie_names:
        s = requests.Session()

        parsed = urlparse(target)
        host = parsed.hostname

        s.cookies.set(cname, fixed_value, domain=host, path="/")

        data = dict(point["inputs"])
        data["username"] = "nonexistent"
        data["password"] = "badpwd"

        r = attempt_request(s, endpoint, method, data)

        # --- FIXED CODE: SAFELY HANDLE MULTIPLE COOKIES ---
        cookie_values = [c.value for c in s.cookies if c.name == cname]

        accepted = False
        reason = ""

        if fixed_value in cookie_values:
            accepted = True
            reason = "Server preserved supplied session cookie"
        else:
            sc = r.headers.get("Set-Cookie", "") if r else ""
            if fixed_value in sc:
                accepted = True
                reason = "Server accepted user-defined session ID"

        writer.writerow({
            "test_type": "session_fixation",
            "target": target,
            "endpoint": endpoint,
            "username": "",
            "password": "",
            "status_code": r.status_code if r else None,
            "evidence": "vulnerable" if accepted else "not_vulnerable",
            "notes": reason,
            "cookie_name": cname,
            "cookie_value": fixed_value,
            "cookie_flags": ""
        })


# -------------------------------------------------------------------
# Test: Session Hijacking
# -------------------------------------------------------------------

def test_session_hijack(point, writer, target):
    endpoint = point["action"]

    valid_pairs = [("admin", "password")]

    captured = {}
    success = False

    for u, p in valid_pairs:
        s = requests.Session()

        data = dict(point["inputs"])
        data["username"] = u
        data["password"] = p

        r = attempt_request(s, endpoint, "post", data)

        if r and ("logout" in r.text.lower() or r.history):
            for c in s.cookies:
                captured[c.name] = c.value
            success = True
            break

    if not success:
        writer.writerow({
            "test_type": "session_hijack",
            "target": target,
            "endpoint": "",
            "username": "",
            "password": "",
            "status_code": None,
            "evidence": "",
            "notes": "Login unsuccessful, cannot test hijack",
            "cookie_name": "",
            "cookie_value": "",
            "cookie_flags": ""
        })
        return

    new_s = requests.Session()

    parsed = urlparse(target)
    host = parsed.hostname

    for k, v in captured.items():
        new_s.cookies.set(k, v, domain=host, path="/")

    accessed = False

    for path in DEFAULT_PROTECTED_PATHS:
        url = urljoin(target + "/", path.lstrip("/"))
        try:
            r2 = new_s.get(url, headers=HEADERS, timeout=DEFAULT_TIMEOUT)
            if r2.status_code == 200 and "login" not in r2.text.lower():
                accessed = True
                accessed_page = url
                break
        except:
            continue

    writer.writerow({
        "test_type": "session_hijack",
        "target": target,
        "endpoint": accessed_page if accessed else "",
        "username": "",
        "password": "",
        "status_code": r2.status_code if accessed else None,
        "evidence": "access_with_reused_cookies" if accessed else "denied",
        "notes": "Hijack successful" if accessed else "Hijack failed",
        "cookie_name": ";".join(captured.keys()),
        "cookie_value": ";".join(captured.values()),
        "cookie_flags": ""
    })


# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Week 5 Authentication & Session Testing Module")
    parser.add_argument("--login-url", default=DEFAULT_LOGIN_URL)
    parser.add_argument("--out", default="week5_auth_session_results.csv")
    args = parser.parse_args()

    login_url = args.login_url
    out_csv = args.out

    point = guess_login_point(login_url)

    session = requests.Session()

    os.makedirs(os.path.dirname(out_csv) or ".", exist_ok=True)

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=REPORT_FIELDS)
        writer.writeheader()

        print("[1] Cookie flag analysis…")
        test_cookie_flags(session, point, writer, login_url)

        print("[2] Weak/default credential testing…")
        test_weak_credentials(session, point, DEFAULT_WORDLIST, writer, login_url)

        print("[3] Brute-force simulation…")
        test_bruteforce(session, point, ["admin"], DEFAULT_BRUTE_PASSWORDS, writer, login_url)

        print("[4] Session fixation testing…")
        test_session_fixation(point, writer, login_url)

        print("[5] Session hijacking testing…")
        test_session_hijack(point, writer, login_url)

    print(f"\n[DONE] Report saved to {out_csv}")


if __name__ == "__main__":
    main()
