
import requests
from urllib.parse import urljoin, urlparse

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.backup",
    "/config.php", "/config.yml", "/config.json",
    "/settings.py", "/settings.php",
    "/database.yml", "/db.php",

    "/admin", "/admin/", "/admin.php",
    "/administrator", "/phpmyadmin", "/wp-admin",

    "/backup.zip", "/backup.sql", "/backup.tar.gz",

    "/.git/config", "/.git/HEAD",
    "/.htaccess", "/.htpasswd",

    "/error.log", "/debug.log", "/php_errors.log",
    "/phpinfo.php", "/info.php",

    "/robots.txt", "/sitemap.xml",
    "/README.md", "/LICENSE",
]

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0"
})


def is_false_positive(response):
    """Detect fake 200 responses"""
    text = response.text.lower()

    keywords = [
        "not found",
        "404",
        "page not found",
        "error 404",
        "does not exist"
    ]

    if any(k in text for k in keywords):
        return True

    if len(response.text.strip()) < 30:
        return True

    return False


def scan_file_exposure(base_url):
    print(f"\n[FILE] Scanning: {base_url}")

    findings = []

    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path in SENSITIVE_PATHS:
        url = urljoin(base, path)

        try:
            r = session.get(url, timeout=5, allow_redirects=True)

            # accept more statuses
            if r.status_code in [200, 301, 302, 401, 403]:

                # skip fake pages
                if r.status_code == 200 and is_false_positive(r):
                    continue

                severity = "high"

                if r.status_code in [401, 403]:
                    severity = "low"

                if path in ["/robots.txt", "/sitemap.xml", "/README.md", "/LICENSE"]:
                    severity = "info"

                print(f"[FOUND] {url} → {r.status_code}")

                findings.append({
                    "url": url,
                    "status": r.status_code,
                    "severity": severity,
                    "size": len(r.text),
                })

        except requests.exceptions.RequestException as e:
            print(f"[ERROR] {url} → {e}")
            continue

    print(f"[FILE] Found {len(findings)} result(s)")
    return findings