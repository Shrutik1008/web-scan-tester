# xss_tester_from_scan.py
"""
XSS tester that loads scan results (CSV or JSON) from your crawler,
logs into DVWA, injects JavaScript-based XSS payloads into form fields
and URLs, detects reflected / stored XSS via response analysis or
optional DOM inspection, and records vulnerable endpoints.

Usage:
    python xss_tester_from_scan.py scan_results.json

"""

import os
import sys
import csv
import json
import time
import argparse
import requests
from urllib.parse import urljoin, urlparse
from collections import defaultdict

# Optional Selenium setup (only used if --use-selenium provided)
SELENIUM_AVAILABLE = False
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_AVAILABLE = True
except Exception:
    SELENIUM_AVAILABLE = False

# ---- CONFIG ----
BASE_DIR_DEFAULT = "DVWA"
DEFAULT_BASE_URL = "http://localhost:8080/"
CANDIDATES = [
    os.path.join(BASE_DIR_DEFAULT, "scan_results.csv"),
    os.path.join(BASE_DIR_DEFAULT, "scan_results.json"),
    "scan_results.csv",
    "scan_results.json",
]
OUTPUT_CSV_DEFAULT = os.path.join(BASE_DIR_DEFAULT, "week4_xss_results.csv")
HEADERS = {"User-Agent": "WebScanPro/1.0"}
REQUEST_TIMEOUT = 15
MIN_MATCH_LEN = 8  # minimum chunk length for reflection heuristic

# XSS payloads (JavaScript-based)
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "'\"><img src=x onerror=alert(1)>",
    "<iframe srcdoc=\"<script>alert('XSS')</script>\"></iframe>",
    "%3Cscript%3Ealert('XSS')%3C%2Fscript%3E"  # URL-encoded variant
]

# ---------------- DVWA LOGIN HELPERS ----------------

def extract_token(html):
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "lxml")
    tok = soup.find("input", {"name": "user_token"})
    return tok.get("value") if tok else None

def dvwa_login(session, base_url):
    """Login to DVWA (admin/password)."""
    from bs4 import BeautifulSoup

    login_url = urljoin(base_url, "login.php")
    print(f"[i] Opening login page: {login_url}")
    r = session.get(login_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
    token = extract_token(r.text)

    if not token:
        print("[!] Could not find login CSRF token. Login may fail.")
    payload = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
    }
    if token:
        payload["user_token"] = token

    print("[i] Logging in as admin/password...")
    r2 = session.post(login_url, data=payload, headers=HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    if "index.php" in r2.url or "Welcome" in r2.text:
        print("[+] DVWA login successful.")
        return True
    print("[!] DVWA login failed. Continuing unauthenticated (results may be limited).")
    return False

def set_dvwa_security_low(session, base_url):
    """Attempt to set DVWA security level to LOW."""
    security_url = urljoin(base_url, "security.php")
    print(f"[i] Setting DVWA security level to LOW ({security_url})")

    r = session.get(security_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
    token = extract_token(r.text)
    if not token:
        print("[!] Could not find security token; Docker builds often ignore this. Continuing.")
        return

    payload = {
        "security": "low",
        "seclev_submit": "Submit",
        "user_token": token
    }
    r2 = session.post(security_url, data=payload, headers=HEADERS, timeout=REQUEST_TIMEOUT)
    if "low" in r2.text.lower():
        print("[+] Security level set to LOW.")
    else:
        print("[!] Could not verify security level; continuing anyway.")

# ---------------- FILE DISCOVERY ----------------

def find_scan_file(cli_arg, base_dir):
    if cli_arg:
        if os.path.exists(cli_arg):
            return cli_arg
        candidate = os.path.join(base_dir, cli_arg)
        if os.path.exists(candidate):
            return candidate
        return None
    for fn in CANDIDATES:
        try_fn = fn.replace(BASE_DIR_DEFAULT, base_dir)
        if os.path.exists(try_fn):
            return try_fn
    return None

# ---------------- SCAN RESULTS LOADING ----------------

def load_scan_points_from_csv(path):
    grouped = defaultdict(lambda: {"page_url": None, "action": None, "method": "get", "inputs": {}})
    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                page = row.get("page") or row.get("page_url")
                action = row.get("action") or row.get("endpoint") or ""
                method = (row.get("method") or "get").lower()
                input_name = row.get("input_name") or row.get("name")
                input_value = row.get("input_value") or row.get("value") or "1"
                key = (page, action, method)
                g = grouped[key]
                g["page_url"] = page
                g["action"] = action if action else page
                g["method"] = method
                if input_name:
                    g["inputs"].setdefault(input_name, input_value)
                else:
                    g["inputs"].setdefault("id", input_value)
    except Exception as e:
        print(f"[ERROR] Failed to read CSV {path}: {e}")
        return []
    return list(grouped.values())

def load_scan_points_from_json(path):
    points = []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load JSON {path}: {e}")
        return points

    for entry in data:
        page = entry.get("page") or entry.get("page_url")
        forms = entry.get("forms", [])
        if isinstance(forms, dict):
            forms = [forms]
        for form in forms:
            action = form.get("action") or page
            method = (form.get("method") or "get").lower()
            inputs_list = form.get("inputs", [])
            inputs = {}
            if isinstance(inputs_list, dict):
                inputs = inputs_list
            else:
                for inp in inputs_list:
                    if not inp:
                        continue
                    if isinstance(inp, dict):
                        name = inp.get("name")
                        value = inp.get("value") if inp.get("value") is not None else "1"
                        if name:
                            inputs.setdefault(name, value)
                    else:
                        inputs.setdefault(str(inp), "1")
            points.append({"page_url": page, "action": action, "method": method, "inputs": inputs})
    return points

def load_scan_points(path):
    if not path:
        return []
    if path.lower().endswith(".json"):
        return load_scan_points_from_json(path)
    elif path.lower().endswith(".csv"):
        return load_scan_points_from_csv(path)
    else:
        pts = load_scan_points_from_json(path)
        if pts:
            return pts
        return load_scan_points_from_csv(path)

# ---------------- XSS DETECTION LOGIC ----------------

def baseline_request(session, endpoint, params, method):
    try:
        if method == "get":
            r = session.get(endpoint, params=params, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        else:
            r = session.post(endpoint, data=params, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        return r.status_code, r.text
    except Exception:
        return None, ""

def contains_reflection(body, payload):
    if not body:
        return False
    if payload in body:
        return True
    # try middle chunk
    if len(payload) >= MIN_MATCH_LEN:
        mid = len(payload) // 2
        chunk = payload[max(0, mid - MIN_MATCH_LEN//2): mid + MIN_MATCH_LEN//2]
        if chunk and chunk in body:
            return True
    return False

def test_point(session, endpoint, base_params, method):
    """
    Injects XSS payloads into each parameter and checks if they are reflected in response.
    """
    results = []
    baseline_status, baseline_body = baseline_request(session, endpoint, base_params, method)

    for payload in XSS_PAYLOADS:
        for param in list(base_params.keys()):
            test_params = dict(base_params)
            test_params[param] = str(test_params.get(param, "")) + payload

            try:
                if method == "get":
                    r = session.get(endpoint, params=test_params, headers=HEADERS, timeout=REQUEST_TIMEOUT)
                else:
                    r = session.post(endpoint, data=test_params, headers=HEADERS, timeout=REQUEST_TIMEOUT)
                status = r.status_code
                body = r.text or ""
            except Exception:
                status = None
                body = ""

            reflected = contains_reflection(body, payload)
            evidence = []
            if reflected:
                evidence.append("reflected_payload")

            if baseline_body and body and abs(len(body) - len(baseline_body)) > max(50, 0.05 * len(baseline_body)):
                evidence.append("content_length_change")

            results.append({
                "page_url": endpoint,
                "param_tested": param,
                "method": method.upper(),
                "payload": payload,
                "status": status,
                "reflected": reflected,
                "evidence": "|".join(evidence),
                "baseline_len": len(baseline_body) if baseline_body else None,
                "response_len": len(body)
            })
    return results

def run_stored_check(session, base_pages, injected_payload):
    """
    Simple stored XSS heuristic:
    After injecting payloads, re-visit pages in base_pages
    and look for payload string anywhere.
    """
    stored_matches = []
    for page in base_pages:
        if not page:
            continue
        try:
            r = session.get(page, headers=HEADERS, timeout=REQUEST_TIMEOUT)
            if injected_payload in (r.text or ""):
                stored_matches.append(page)
        except Exception:
            continue
    return stored_matches

# ---------------- SELENIUM DOM HELPERS ----------------

def setup_selenium_driver():
    if not SELENIUM_AVAILABLE:
        raise RuntimeError("Selenium not installed / available. Install selenium and webdriver-manager.")
    options = webdriver.ChromeOptions()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    return driver

def selenium_dom_check(driver, page_url, marker):
    """
    Load page and check if marker appears in DOM outerHTML.
    """
    try:
        driver.get(page_url)
        time.sleep(0.5)
        outer = driver.execute_script("return document.documentElement.outerHTML;")
        return marker in (outer or "")
    except Exception:
        return False

# ---------------- MAIN ----------------

def main():
    parser = argparse.ArgumentParser(description="XSS testing module - run after crawler")
    parser.add_argument("scan_file", nargs="?", help="Scan results file (CSV or JSON)")
    parser.add_argument("--base-dir", default=BASE_DIR_DEFAULT, help="Base directory for scan results (default: DVWA)")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Base URL of target (default: http://localhost:8080/)")
    parser.add_argument("--out", default=OUTPUT_CSV_DEFAULT, help="Output CSV path")
    parser.add_argument("--use-selenium", action="store_true", help="Render pages with Selenium and inspect DOM")
    parser.add_argument("--max-sample-pages", type=int, default=50, help="When checking stored XSS, max pages to re-check")
    args = parser.parse_args()

    scan_file = find_scan_file(args.scan_file, args.base_dir)
    if not scan_file:
        print("[ERROR] No scan results file found. Run crawler first or pass path. Tried default locations.")
        return

    print(f"[i] Using scan file: {scan_file}")
    points = load_scan_points(scan_file)
    if not points:
        print("[i] No form/input points found in scan results.")
        return

    session = requests.Session()
    session.headers.update(HEADERS)

    # ---- Login + security LOW (DVWA) ----
    dvwa_login(session, args.base_url)
    set_dvwa_security_low(session, args.base_url)

    # Filter only endpoints on same host as base_url
    base_host = urlparse(args.base_url).netloc
    filtered_points = []
    for p in points:
        page_url = p.get("page_url") or ""
        action = p.get("action") or ""
        full = action if action.startswith("http") else urljoin(page_url or args.base_url, action or "")
        if urlparse(full).netloc == base_host:
            filtered_points.append({
                "page_url": page_url or args.base_url,
                "action": full,
                "method": p.get("method") or "get",
                "inputs": p.get("inputs") or {}
            })

    if not filtered_points:
        print("[i] No points in scan results match base URL domain; nothing to test.")
        return

    print(f"[i] Loaded {len(filtered_points)} endpoints from scan results (same domain).")

    pages_to_check_for_stored = list({p["page_url"] for p in filtered_points if p.get("page_url")})[:args.max_sample_pages]

    driver = None
    if args.use_selenium:
        try:
            driver = setup_selenium_driver()
            print("[i] Selenium driver ready.")
        except Exception as e:
            print(f"[WARN] Selenium not available/failed to start: {e}")
            driver = None

    all_results = []
    try:
        for p in filtered_points:
            endpoint = p["action"] or p["page_url"]
            method = (p.get("method") or "get").lower()
            inputs = p.get("inputs") or {}
            if not inputs:
                inputs = {"q": "test"}  # fallback
            print(f"[*] Testing XSS on {endpoint} ({method.upper()}) with params: {list(inputs.keys())}")

            try:
                res = test_point(session, endpoint, inputs, method)
                for r in res:
                    r_copy = dict(r)
                    if r.get("reflected"):
                        marker = r.get("payload")
                        r_copy["dom_rendered"] = False
                        r_copy["stored_candidate_pages"] = ""
                        if driver:
                            try:
                                r_copy["dom_rendered"] = selenium_dom_check(driver, endpoint, marker)
                            except Exception:
                                r_copy["dom_rendered"] = False
                        stored_pages = run_stored_check(session, pages_to_check_for_stored, marker)
                        if stored_pages:
                            r_copy["stored_candidate_pages"] = ";".join(stored_pages)
                    else:
                        r_copy["dom_rendered"] = False
                        r_copy["stored_candidate_pages"] = ""
                    all_results.append(r_copy)
            except Exception as e:
                print(f"[WARN] Error testing {endpoint}: {e}")
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass

    # write CSV
    fieldnames = [
        "page_url", "param_tested", "method", "payload", "status",
        "reflected", "dom_rendered", "stored_candidate_pages",
        "evidence", "baseline_len", "response_len"
    ]
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()
        for r in all_results:
            writer.writerow({k: r.get(k, "") for k in fieldnames})

    print(f"[DONE] XSS test results saved to {args.out}")


if __name__ == "__main__":
    main()
