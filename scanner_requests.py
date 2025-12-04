# scanner_requests.py
"""
WebScanPro - Authenticated DVWA Scanner

USAGE: python scanner_requests.py --target http://localhost:8080 --max-depth 2

Supports:
- DVWA Auto Login
- Token extraction
- Session-based crawling
- Crawls vulnerability modules after login
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urldefrag
import time
import json
import csv
import argparse
from tqdm import tqdm
import sys
import re

DEFAULT_USER_AGENT = "WebScanPro/1.0 (+https://example.local)"
REQUEST_TIMEOUT = 6
SLEEP_BETWEEN_REQUESTS = 0.25


# -------------------- Helpers --------------------
def normalize_link(base, link):
    joined = urljoin(base, link)
    cleaned, _ = urldefrag(joined)
    return cleaned

def same_domain(a, b):
    return urlparse(a).netloc == urlparse(b).netloc


# -------------------- Authentication --------------------
def dvwa_login(base_url, session):
    """
    Auto-login to DVWA using session cookies.
    Handles dynamic CSRF token.
    """

    login_url = urljoin(base_url, "login.php")
    index_url = urljoin(base_url, "index.php")

    print("[i] Fetching login page:", login_url)

    r = session.get(login_url)
    if r.status_code != 200:
        print("[!] Could not load login.php")
        return False

    soup = BeautifulSoup(r.text, "lxml")

    # Extract CSRF token
    token_tag = soup.find("input", {"name": "user_token"})
    if not token_tag:
        print("[!] No CSRF token found on login page.")
        return False

    token = token_tag.get("value")
    print("[i] Extracted CSRF token:", token)

    # Prepare login payload
    payload = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token
    }

    print("[i] Attempting login...")

    r2 = session.post(login_url, data=payload)
    if "index.php" in r2.url or "Welcome" in r2.text:
        print("[+] Login successful!")
        return True
    else:
        print("[!] Login failed.")
        return False


# -------------------- HTML Parsing --------------------
def extract_links_and_forms(base_url, html_text):
    soup = BeautifulSoup(html_text, "lxml")

    links = set()
    forms = []

    # Extract links
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href:
            full = normalize_link(base_url, href)
            links.add(full)

    # Extract forms
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "get").upper()
        inputs = []

        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            typ = inp.get("type") if inp.name == "input" else inp.name
            value = inp.get("value")
            if not name:
                fallback = inp.get("id") or inp.get("placeholder")
                name = fallback if fallback else None

            inputs.append({
                "name": name,
                "type": typ,
                "value": value
            })

        forms.append({
            "action": normalize_link(base_url, action) if action else base_url,
            "method": method,
            "inputs": inputs
        })

    return list(links), forms


# -------------------- Authenticated Crawler --------------------
def crawl(start_url, max_depth=2, max_pages=1000):
    """
    Authenticated DVWA crawler
    """

    session = requests.Session()
    session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

    base_url = start_url if start_url.endswith("/") else start_url + "/"

    # Perform login
    if not dvwa_login(base_url, session):
        print("[!] Cannot start crawl without login.")
        sys.exit(1)

    print("[i] Login verified. Starting crawl from:", base_url)

    visited = set()
    queue = [(urljoin(base_url, "index.php"), 0)]  # Authenticated dashboard
    results = []

    pbar = tqdm(total=max_pages, desc="Pages processed", unit="page")

    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)

        if url in visited:
            continue
        if depth > max_depth:
            continue

        visited.add(url)

        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT)
            status, html = r.status_code, r.text
        except Exception as e:
            results.append({
                "page": url,
                "status": None,
                "error": str(e),
                "forms": [],
                "links": []
            })
            pbar.update(1)
            continue

        links, forms = extract_links_and_forms(url, html)

        # Filter same domain
        same_domain_links = []
        for link in links:
            if same_domain(url, link):
                same_domain_links.append(link)
                if link not in visited and (depth + 1) <= max_depth:
                    queue.append((link, depth + 1))

        results.append({
            "page": url,
            "status": status,
            "forms": forms,
            "links": same_domain_links
        })

        pbar.update(1)
        time.sleep(SLEEP_BETWEEN_REQUESTS)

    pbar.close()
    return results


# -------------------- Output Writers --------------------
def save_json(filename, data):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[+] Saved JSON -> {filename}")

def save_csv(filename, data):
    rows = []

    for entry in data:
        page = entry.get("page")
        links = entry.get("links", [])
        forms = entry.get("forms", [])

        if forms:
            for form in forms:
                action = form.get("action")
                method = form.get("method")
                inputs = form.get("inputs", [])
                if inputs:
                    for inp in inputs:
                        rows.append({
                            "page": page,
                            "action": action,
                            "method": method,
                            "input_name": inp.get("name"),
                            "input_type": inp.get("type"),
                            "input_value": inp.get("value"),
                            "link_count": len(links),
                        })
                else:
                    rows.append({
                        "page": page,
                        "action": action,
                        "method": method,
                        "input_name": None,
                        "input_type": None,
                        "input_value": None,
                        "link_count": len(links),
                    })
        else:
            rows.append({
                "page": page,
                "action": None,
                "method": None,
                "input_name": None,
                "input_type": None,
                "input_value": None,
                "link_count": len(links),
            })

    with open(filename, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["page", "action", "method", "input_name", "input_type", "input_value", "link_count"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    print(f"[+] Saved CSV -> {filename}")


# -------------------- CLI --------------------
def main():
    parser = argparse.ArgumentParser(description="WebScanPro Authenticated DVWA Scanner")
    parser.add_argument("--target", "-t", required=True, help="Base target URL, e.g. http://localhost:8080/")
    parser.add_argument("--max-depth", "-d", type=int, default=2)
    parser.add_argument("--max-pages", type=int, default=500)
    parser.add_argument("--out-json", default="scan_results.json")
    parser.add_argument("--out-csv", default="scan_results.csv")
    args = parser.parse_args()

    target = args.target
    if not (target.startswith("http://") or target.startswith("https://")):
        print("[!] Target must start with http:// or https://")
        sys.exit(1)

    print(f"[i] Starting authenticated crawl for {target} (depth={args.max_depth})")

    results = crawl(start_url=target, max_depth=args.max_depth, max_pages=args.max_pages)

    save_json(args.out_json, results)
    save_csv(args.out_csv, results)

    print("[i] Authenticated crawl completed.")


if __name__ == "__main__":
    main()
