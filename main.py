#!/usr/bin/env python3
"""
main.py - Run ALL WebScanPro modules in correct order
-----------------------------------------------------

Usage:
    python main.py --target http://localhost:8080
"""

import argparse
import subprocess
import os
import sys
import time

# -------------------------------------------------------------
# Helper function to run scripts
# -------------------------------------------------------------
def run_script(label, command):
    print(f"\n===== Running {label} =====")
    print(f"[CMD] {command}")

    try:
        result = subprocess.run(command, shell=True)
        if result.returncode == 0:
            print(f"[OK] {label} completed successfully.")
        else:
            print(f"[ERROR] {label} failed with exit code {result.returncode}.")
    except Exception as e:
        print(f"[EXCEPTION] Failed to run {label}: {e}")

    time.sleep(1)


# -------------------------------------------------------------
# Main Automation
# -------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Run all WebScanPro modules")
    parser.add_argument("--target", required=True,
                        help="DVWA base URL (Example: http://localhost:8080)")
    args = parser.parse_args()

    target = args.target.rstrip("/")

    # ---------------------------
    # 1. Crawl Website (Week 1)
    # ---------------------------
    run_script(
        "Web Crawler",
        f"python scanner_requests.py --target {target} --max-depth 2"
    )

    # ---------------------------
    # 2. SQL Injection Tests (Week 3)
    # ---------------------------
    run_script(
        "SQL Injection Testing",
        "python sql_tester_from_scan.py"
    )

    # ---------------------------
    # 3. XSS Testing (Week 4)
    # ---------------------------
    run_script(
        "XSS Testing",
        "python xss_tester_from_scan.py scan_results.json"
    )

    # ---------------------------
    # 4. Authentication & Session Tests (Week 5)
    # ---------------------------
    run_script(
        "Authentication & Session Testing",
        f"python Session_Auth.py --login-url {target}/login.php"
    )

    # ---------------------------
    # 5. Access Control / IDOR (Week 6)
    # ---------------------------
    run_script(
        "Access Control & IDOR Testing",
        f"python AccessControl.py --target {target} --username admin --password password"
    )

    # ---------------------------
    # 6. Security Report (Week 7)
    # ---------------------------
    run_script(
        "Security Report Generation",
        "python generate_security_report.py"
    )

    print("\n\n===============================")
    print("🎉  ALL TASKS COMPLETED!")
    print("📄  Final report: security_report.html")
    print("===============================")


# -------------------------------------------------------------
if __name__ == "__main__":
    main()
