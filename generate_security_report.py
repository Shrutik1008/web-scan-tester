import os
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

REPORT_HTML = "security_report.html"

# ---------- Helper: Safe CSV loader ----------

def load_csv_if_exists(path, encoding="utf-8"):
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding=encoding) as f:
        reader = csv.DictReader(f)
        return list(reader)


# ---------- 1. Load & normalize vulnerabilities ----------

def load_sql_vulns(path="sql_testing_results.csv"):
    rows = load_csv_if_exists(path)
    vulns = []
    for r in rows:
        evidence = r.get("evidence", "") or ""
        endpoint = r.get("page_url") or ""
        payload = r.get("payload") or ""
        base_len = r.get("baseline_length") or r.get("baseline_len")
        sev = "Low"

        if "sql_error_in_body" in evidence or "time_delay" in evidence:
            sev = "High"
        elif "content_length_change" in evidence:
            sev = "Medium"

        if sev == "Low":
            # If nothing suspicious, skip to avoid noise
            continue

        vulns.append({
            "type": "SQL Injection",
            "endpoint": endpoint,
            "severity": sev,
            "evidence": f"Evidence: {evidence} | Payload: {payload}",
            "source": path
        })
    return vulns


def load_xss_vulns(path="week4_xss_results.csv"):
    rows = load_csv_if_exists(path)
    vulns = []
    for r in rows:
        endpoint = r.get("page_url") or ""
        evidence = r.get("evidence", "") or ""
        payload = r.get("payload", "") or ""
        reflected = (r.get("reflected", "") in ["True", "true", "1"])
        dom_rendered = (r.get("dom_rendered", "") in ["True", "true", "1"])
        stored_pages = r.get("stored_candidate_pages", "") or ""

        if not reflected and not stored_pages:
            # Basic heuristic: skip weak/noisy cases
            continue

        # Severity
        if stored_pages or dom_rendered:
            sev = "High"
        elif reflected:
            sev = "Medium"
        else:
            sev = "Low"

        vulns.append({
            "type": "Cross-Site Scripting (XSS)",
            "endpoint": endpoint,
            "severity": sev,
            "evidence": f"Reflected={reflected}, DOM={dom_rendered}, StoredPages={stored_pages}, Evidence={evidence}, Payload={payload}",
            "source": path
        })
    return vulns


def load_auth_vulns(path="week5_auth_session_results.csv"):
    rows = load_csv_if_exists(path)
    vulns = []
    for r in rows:
        t = r.get("test_type", "")
        endpoint = r.get("endpoint") or r.get("target") or ""
        evidence = r.get("evidence", "") or ""
        notes = r.get("notes", "") or ""
        username = r.get("username") or ""
        cookie_name = r.get("cookie_name") or ""
        cookie_flags = r.get("cookie_flags") or ""

        sev = None
        vtype = "Authentication / Session"

        if t == "weak_credential" and "login_success" in evidence:
            sev = "High"
            vtype = "Weak / Default Credentials"
        elif t == "bruteforce" and "login_success" in evidence:
            sev = "High"
            vtype = "Brute-force Vulnerability"
        elif t == "session_hijack" and "Hijack successful" in notes:
            sev = "High"
            vtype = "Session Hijacking"
        elif t == "cookie_analysis":
            issues = evidence.split(";") if evidence else []
            if any("low_entropy" in i for i in issues):
                sev = "Medium"
            elif "missing_Secure" in issues or "missing_HttpOnly" in issues:
                sev = "Low"
            else:
                continue  # nothing interesting

        if not sev:
            continue

        vulns.append({
            "type": vtype,
            "endpoint": endpoint,
            "severity": sev,
            "evidence": f"Test={t}, Evidence={evidence}, Notes={notes}, User={username}, Cookie={cookie_name} ({cookie_flags})",
            "source": path
        })
    return vulns


def load_access_vulns(path="week6_access_control_idor_results.csv"):
    rows = load_csv_if_exists(path)
    vulns = []
    for r in rows:
        t = r.get("test_type", "")
        url = r.get("tested_url") or ""
        evidence = r.get("evidence", "") or ""
        notes = r.get("notes", "") or ""
        param = r.get("param_or_path", "")
        orig = r.get("original_value", "")
        new = r.get("tested_value", "")

        if not t:
            continue

        if t in ["horizontal", "vertical"]:
            sev = "High"
        elif t == "horizontal_info":
            sev = "Low"
        else:
            sev = "Medium"

        vname = "Access Control / IDOR"
        if t == "vertical":
            vname = "Vertical Privilege Escalation"
        elif t == "horizontal":
            vname = "Horizontal IDOR"

        vulns.append({
            "type": vname,
            "endpoint": url,
            "severity": sev,
            "evidence": f"Param={param}, Original={orig}, Tested={new}, Evidence={evidence}, Notes={notes}",
            "source": path
        })
    return vulns


def load_all_vulns():
    all_v = []
    all_v.extend(load_sql_vulns())
    all_v.extend(load_xss_vulns())
    all_v.extend(load_auth_vulns())
    all_v.extend(load_access_vulns())
    return all_v


# ---------- 2. Mitigation Texts ----------

MITIGATIONS = {
    "SQL Injection": (
        "Use prepared statements and parameterized queries; avoid string concatenation in SQL. "
        "Apply server-side input validation and least-privilege DB accounts. "
        "Consider using ORM frameworks to abstract raw SQL access."
    ),
    "Cross-Site Scripting (XSS)": (
        "Apply output encoding (HTML, JS, URL) before rendering user data. "
        "Validate and sanitize inputs on the server. "
        "Set HttpOnly and Secure flags on cookies and implement Content Security Policy (CSP)."
    ),
    "Weak / Default Credentials": (
        "Force strong password policy and prevent use of known weak/default passwords. "
        "Disable default accounts or require password change on first login. "
        "Implement account lockout or CAPTCHA after several failed attempts."
    ),
    "Brute-force Vulnerability": (
        "Add rate limiting, account lockouts, and CAPTCHAs for repeated login attempts. "
        "Log and monitor failed login patterns for potential attacks."
    ),
    "Session Hijacking": (
        "Use secure, random session IDs over HTTPS only. "
        "Set HttpOnly, Secure, and SameSite flags on session cookies. "
        "Regenerate session IDs on login and logout; invalidate sessions on server side."
    ),
    "Authentication / Session": (
        "Harden authentication with multi-factor where possible, ensure secure cookie attributes, "
        "and protect session IDs from exposure in URLs, logs, and client-side scripts."
    ),
    "Access Control / IDOR": (
        "Enforce object-level authorization checks on the server for every request. "
        "Never rely solely on IDs from the client; verify that the current user is allowed to access the requested resource."
    ),
    "Horizontal IDOR": (
        "Validate that the authenticated user owns or is permitted to access the resource referenced by the ID. "
        "Use opaque or indirect references instead of predictable numeric IDs when possible."
    ),
    "Vertical Privilege Escalation": (
        "Implement role-based access control (RBAC) and verify user role/permissions for each sensitive action. "
        "Do not expose admin endpoints to unprivileged users; enforce checks server-side, not just in the UI."
    ),
}


def get_mitigation(vtype: str) -> str:
    # Try exact match, then fall back on broader category
    if vtype in MITIGATIONS:
        return MITIGATIONS[vtype]
    if "XSS" in vtype:
        return MITIGATIONS["Cross-Site Scripting (XSS)"]
    if "SQL" in vtype:
        return MITIGATIONS["SQL Injection"]
    if "IDOR" in vtype or "Access Control" in vtype:
        return MITIGATIONS["Access Control / IDOR"]
    if "Session" in vtype or "Auth" in vtype:
        return MITIGATIONS["Authentication / Session"]
    return "Review and apply appropriate security best practices (least privilege, input validation, output encoding, proper authorization checks)."


# ---------- 3. HTML Report Generation ----------

def generate_html_report(vulns, outfile=REPORT_HTML):
    total = len(vulns)
    by_severity = Counter(v["severity"] for v in vulns)
    by_type = Counter(v["type"] for v in vulns)

    # Convert counts to JSON-ish strings for Chart.js
    sev_labels = list(by_severity.keys())
    sev_values = [by_severity[s] for s in sev_labels]

    type_labels = list(by_type.keys())
    type_values = [by_type[t] for t in type_labels]

    # Basic HTML template with inline Chart.js (via CDN)
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>WebScanPro Security Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #222; }}
        .summary-box {{
            border: 1px solid #ccc; padding: 10px; margin-bottom: 20px;
            border-radius: 8px; background: #f9f9f9;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin-top: 20px;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 6px 8px;
            font-size: 13px;
        }}
        th {{
            background-color: #f0f0f0;
        }}
        .sev-High {{ color: #b30000; font-weight: bold; }}
        .sev-Medium {{ color: #cc7a00; font-weight: bold; }}
        .sev-Low {{ color: #006600; font-weight: bold; }}
        .tiny {{ font-size: 11px; color: #555; }}
        .section {{ margin-top: 30px; }}
    </style>
</head>
<body>
    <h1>WebScanPro - Security Report</h1>
    <div class="summary-box">
        <p><strong>Total vulnerabilities:</strong> {total}</p>
        <p><strong>By Severity:</strong> {dict(by_severity)}</p>
        <p><strong>By Type:</strong> {dict(by_type)}</p>
    </div>

    <div class="section">
        <h2>Visual Summary</h2>
        <div style="display:flex; gap:40px; flex-wrap:wrap;">
            <div>
                <h3>Vulnerabilities by Severity</h3>
                <canvas id="severityChart" width="350" height="250"></canvas>
            </div>
            <div>
                <h3>Vulnerabilities by Type</h3>
                <canvas id="typeChart" width="350" height="250"></canvas>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Detailed Vulnerability List</h2>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Vulnerability Type</th>
                    <th>Affected Endpoint</th>
                    <th>Severity</th>
                    <th>Evidence / Notes</th>
                    <th>Suggested Mitigation</th>
                </tr>
            </thead>
            <tbody>
    """

    # Detailed rows
    for i, v in enumerate(vulns, 1):
        mit = get_mitigation(v["type"])
        sev = v["severity"]
        css_sev = f"sev-{sev}"
        html += f"""
                <tr>
                    <td>{i}</td>
                    <td>{v['type']}</td>
                    <td>{v['endpoint']}</td>
                    <td class="{css_sev}">{sev}</td>
                    <td class="tiny">{v['evidence']}</td>
                    <td class="tiny">{mit}</td>
                </tr>
        """

    html += """
            </tbody>
        </table>
    </div>

    <script>
        const sevCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(sevCtx, {
            type: 'bar',
            data: {
                labels: """ + json.dumps(sev_labels) + """,
                datasets: [{
                    label: 'Count by Severity',
                    data: """ + json.dumps(sev_values) + """,
                }]
            }
        });

        const typeCtx = document.getElementById('typeChart').getContext('2d');
        new Chart(typeCtx, {
            type: 'bar',
            data: {
                labels: """ + json.dumps(type_labels) + """,
                datasets: [{
                    label: 'Count by Type',
                    data: """ + json.dumps(type_values) + """,
                }]
            }
        });
    </script>
</body>
</html>
"""

    with open(outfile, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] HTML report written to {outfile}")
    print("    Open it in a browser and use 'Print → Save as PDF' to export as PDF.")


def main():
    vulns = load_all_vulns()
    if not vulns:
        print("[!] No vulnerabilities loaded. Make sure your CSV files exist and have data.")
    else:
        generate_html_report(vulns, REPORT_HTML)


if __name__ == "__main__":
    main()
