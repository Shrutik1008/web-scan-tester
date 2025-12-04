#!/usr/bin/env python3
"""
AccessControl.py - Week 6: Access Control & IDOR Testing (DVWA)

- Target: DVWA (e.g. http://localhost:8080/)
- Logs in using CSRF token (admin / password)
- Horizontal tests: ID parameter tampering (IDOR-style)
- Vertical tests: compare anonymous vs authenticated access to sensitive endpoints
- Output: week6_access_control_idor_results.csv

Usage:
    python AccessControl.py --target http://localhost:8080 --username admin --password password
"""

import argparse
import csv
import os
import time
import hashlib
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup

HEADERS = {"User-Agent": "WebScanPro-AccessControl/1.0"}
DEFAULT_OUT = "week6_access_control_idor_results.csv"
REQUEST_DELAY = 0.3
ID_RANGE = 3  # how far around original ID to test for IDOR

# Known DVWA endpoints that take ID-like parameters
KNOWN_ID_TARGETS = [
    "vulnerabilities/sqli/?id=1&Submit=Submit",
    "vulnerabilities/sqli_blind/?id=1&Submit=Submit",
    "vulnerabilities/weak_id/",
]

# Sensitive / admin-ish endpoints (for vertical access control)
ADMIN_ENDPOINTS = [
    "security.php",
    "vulnerabilities/fi/?page=file1.php",
    "vulnerabilities/exec/?ip=8.8.8.8&Submit=Submit",
    "vulnerabilities/sqli/?id=1&Submit=Submit",
]

REPORT_COLUMNS = [
    "test_type", "tested_url", "method",
    "param_or_path", "original_value", "tested_value",
    "status_code", "evidence", "notes",
]


# ---------------- Helpers ----------------

def safe_get(session, url):
    try:
        return session.get(url, headers=HEADERS, timeout=10)
    except Exception:
        return None


def safe_post(session, url, data):
    try:
        return session.post(url, data=data, headers=HEADERS, timeout=10)
    except Exception:
        return None


def fingerprint(r):
    """Fingerprint responses by status + hash of first part of body."""
    if not r or not r.text:
        return ("none", "none")
    snippet = r.text[:600]
    return r.status_code, hashlib.sha256(snippet.encode("utf-8", errors="ignore")).hexdigest()


# ---------------- DVWA Login (same style as working SQL tester) ----------------

def extract_token(html):
    soup = BeautifulSoup(html, "lxml")
    tok = soup.find("input", {"name": "user_token"})
    return tok.get("value") if tok else None


def dvwa_login(session, base_url, username="admin", password="password"):
    login_url = urljoin(base_url, "login.php")
    print(f"[i] Opening login page: {login_url}")
    r1 = safe_get(session, login_url)
    if not r1:
        print("[ERROR] Cannot fetch login.php")
        return False

    token = extract_token(r1.text)
    if not token:
        print("[ERROR] Could not find user_token on login page.")
        # print(r1.text[:500])  # uncomment to debug
        return False

    payload = {
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": token,
    }

    print("[i] Logging in with admin/password...")
    r2 = safe_post(session, login_url, payload)
    if not r2:
        print("[ERROR] Login POST failed.")
        return False

    # DVWA usually redirects to index.php on success
    if "index.php" in r2.url or "logout" in r2.text.lower():
        print("[+] Login successful.")
        return True

    # Some builds need explicit index.php check
    r3 = safe_get(session, urljoin(base_url, "index.php"))
    if r3 and "logout" in r3.text.lower():
        print("[+] Login successful (verified via index.php).")
        return True

    print("[ERROR] Login failed (check credentials / DVWA).")
    return False


# ---------------- Build ID Targets ----------------

def build_id_targets(base):
    """Return list of (url, orig_id or None) for horizontal tampering."""
    targets = []
    for path in KNOWN_ID_TARGETS:
        full = urljoin(base, path)
        parsed = urlparse(full)
        qs = parse_qs(parsed.query)

        if "id" in qs:
            try:
                orig_id = int(qs["id"][0])
            except Exception:
                orig_id = 1
            targets.append((full, orig_id))
        else:
            targets.append((full, None))
    return targets


# ---------------- Horizontal IDOR Tests (IMPROVED LOGGING) ----------------

def horizontal_tests(session_auth, writer, base):
    """
    Attempt horizontal privilege escalation by tampering ID parameters.
    Authenticated session is used so DVWA modules load correctly.

    IMPROVEMENT:
    - Log EVERY ID tampering attempt as horizontal_idor_attempt
    - evidence:
        - 'content_changed'           → possible IDOR
        - 'no_change_or_denied'       → no difference / blocked
    """
    print("[*] Running horizontal access / IDOR tests...")

    targets = build_id_targets(base)
    for url, orig_id in targets:
        print(f"  [*] Base URL: {url} (orig_id={orig_id})")

        base_resp = safe_get(session_auth, url)
        fp_base = fingerprint(base_resp)

        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        base_path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if orig_id is not None and "id" in qs:
            # Try nearby ID values
            for d in range(-ID_RANGE, ID_RANGE + 1):
                if d == 0:
                    continue
                new_id = orig_id + d
                if new_id <= 0:
                    continue

                new_qs = qs.copy()
                new_qs["id"] = [str(new_id)]
                new_url = base_path + "?" + urlencode(new_qs, doseq=True)

                r = safe_get(session_auth, new_url)
                fp_new = fingerprint(r)

                if r:
                    status = r.status_code
                    if fp_new != fp_base and status == 200:
                        evidence = "content_changed"
                        notes = "ID tampering produced different content (possible IDOR)"
                    else:
                        evidence = "no_change_or_denied"
                        notes = "ID tampering attempt; response similar or not authorized"
                else:
                    status = None
                    evidence = "request_failed"
                    notes = "ID tampering request failed (network/timeout)"

                writer.writerow({
                    "test_type": "horizontal_idor_attempt",
                    "tested_url": new_url,
                    "method": "GET",
                    "param_or_path": "id",
                    "original_value": orig_id,
                    "tested_value": new_id,
                    "status_code": status,
                    "evidence": evidence,
                    "notes": notes
                })

                time.sleep(REQUEST_DELAY)

        else:
            # e.g., /weak_id/ has no explicit id parameter in URL
            if base_resp:
                writer.writerow({
                    "test_type": "horizontal_info",
                    "tested_url": url,
                    "method": "GET",
                    "param_or_path": "(none)",
                    "original_value": "",
                    "tested_value": "",
                    "status_code": base_resp.status_code,
                    "evidence": "no_id_param",
                    "notes": "Endpoint scanned but no explicit 'id' param was present"
                })
            time.sleep(REQUEST_DELAY)


# ---------------- Vertical Access Control Tests ----------------

def vertical_tests(session_anon, session_auth, writer, base):
    """
    Vertical privilege escalation:
    Compare anonymous vs authenticated access to sensitive endpoints.
    """
    print("[*] Running vertical access control tests (anonymous vs authenticated)...")

    for ep in ADMIN_ENDPOINTS:
        url = urljoin(base, ep)
        print(f"  [*] Checking: {url}")

        r_admin = safe_get(session_auth, url)
        r_anon = safe_get(session_anon, url)

        if r_admin and r_admin.status_code == 200:
            # If anonymous user also gets 200 and not clearly a login page => problem
            anon_ok = r_anon and r_anon.status_code == 200
            if anon_ok and "login" not in r_anon.text.lower():
                writer.writerow({
                    "test_type": "vertical_access",
                    "tested_url": url,
                    "method": "GET",
                    "param_or_path": ep,
                    "original_value": "",
                    "tested_value": "",
                    "status_code": r_anon.status_code,
                    "evidence": "anonymous_access_to_priv_resource",
                    "notes": "Unauthenticated user could access a page intended for authenticated/privileged users"
                })
        time.sleep(REQUEST_DELAY)


# ---------------- MAIN ----------------

def main():
    parser = argparse.ArgumentParser(description="Week 6: Access Control & IDOR Testing (DVWA)")
    parser.add_argument("--target", required=True, help="Base URL (e.g., http://localhost:8080)")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="password")
    parser.add_argument("--out", default=DEFAULT_OUT)
    args = parser.parse_args()

    base = args.target.rstrip("/") + "/"

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=REPORT_COLUMNS)
        writer.writeheader()

        # Authenticated session
        session_auth = requests.Session()
        if not dvwa_login(session_auth, base, args.username, args.password):
            print("[ERROR] Authenticated login failed. Exiting.")
            return

        # Anonymous (unauthenticated) session
        session_anon = requests.Session()

        # Horizontal IDOR-style tests
        horizontal_tests(session_auth, writer, base)

        # Vertical access control tests
        vertical_tests(session_anon, session_auth, writer, base)

    print(f"\n[DONE] Week 6 results saved to: {args.out}")



if __name__ == "__main__":
    main()
