
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from app.scanner.payloads import SENSITIVE_PATHS, FILE_FALSE_POSITIVE_KEYWORDS as keywords

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0"
})
def is_false_positive(response):
    """Detect fake 200 responses"""
    text = response.text.lower()
    
    if any(k in text for k in keywords):
        return True

    if len(response.text.strip()) < 30:
        return True

    return False


def _check_sensitive_path(base, path):
    url = urljoin(base, path)

    try:
        r = session.get(url, timeout=3, allow_redirects=True)

        if r.status_code not in [200, 301, 302, 401, 403]:
            return None

        if r.status_code == 200 and is_false_positive(r):
            return None

        severity = "high"

        if r.status_code in [401, 403]:
            severity = "low"

        if path in ["/robots.txt", "/sitemap.xml", "/README.md", "/LICENSE"]:
            severity = "info"

        return {
            "url": url,
            "status": r.status_code,
            "severity": severity,
            "size": len(r.text),
        }
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] {url} → {e}")
        return None


def scan_file_exposure(base_url):
    print(f"\n[FILE] Scanning: {base_url}")

    findings = []

    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {
            executor.submit(_check_sensitive_path, base, path): path
            for path in SENSITIVE_PATHS
        }
        for future in as_completed(futures):
            result = future.result()
            if not result:
                continue
            print(f"[FOUND] {result['url']} → {result['status']}")
            findings.append(result)

    print(f"[FILE] Found {len(findings)} result(s)")
    return findings
