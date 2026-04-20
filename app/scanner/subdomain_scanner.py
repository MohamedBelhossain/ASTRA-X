import requests
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from app.scanner.payloads import SUBDOMAINS, SUBDOMAIN_HIGH_RISK as high_risk
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
})


def _check_subdomain(subdomain, domain, scheme):
    hostname = f"{subdomain}.{domain}"
    url = f"{scheme}://{hostname}"

    # first check DNS resolves
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

    # then check HTTP response
    try:
        r = session.get(url, timeout=5, allow_redirects=True)
        return {
            "subdomain": hostname,
            "url": url,
            "ip": ip,
            "status": r.status_code,
            "title": _extract_title(r.text),
            "severity": _get_severity(subdomain, r.status_code),
        }
    except requests.exceptions.RequestException:
        # DNS resolved but HTTP failed — still worth reporting
        return {
            "subdomain": hostname,
            "url": url,
            "ip": ip,
            "status": "no response",
            "title": "",
            "severity": "low",
        }


def _extract_title(html):
    try:
        start = html.lower().index("<title>") + 7
        end = html.lower().index("</title>")
        return html[start:end].strip()[:60]
    except ValueError:
        return ""


def _get_severity(subdomain, status_code):
    if subdomain in high_risk and status_code == 200:
        return "high"
    elif status_code == 200:
        return "medium"
    else:
        return "low"


def scan_subdomains(base_url, max_workers=20):
    print(f"\n[SUBDOMAIN] Scanning: {base_url}")

    parsed = urlparse(base_url)
    scheme = parsed.scheme
    hostname = parsed.netloc

    # strip www if present
    domain = hostname.replace("www.", "")
    candidates = sorted(set(SUBDOMAINS))

    findings = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_check_subdomain, sub, domain, scheme): sub
            for sub in candidates
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                print(f"  [FOUND] {result['subdomain']} → {result['ip']} ({result['status']})")
                findings.append(result)

    # sort by severity then subdomain name
    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda x: (order.get(x["severity"], 3), x["subdomain"]))

    print(f"  [SUBDOMAIN] Found {len(findings)} subdomain(s).")
    return findings
