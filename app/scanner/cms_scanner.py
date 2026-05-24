import re
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from app.scanner.common import response_excerpt, session_headers, should_stop_scan
from app.scanner.http_client import safe_scanner_session

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_CVE_RESULTS = 8

nvd_session = requests.Session()
nvd_session.headers.update(session_headers())


CMS_SIGNATURES = {
    "WordPress": {
        "patterns": [
            r"wp-content/",
            r"wp-includes/",
            r"wordpress",
            r"/wp-json",
        ],
        "version_patterns": [
            r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']WordPress\s+([0-9][^\"'<\s]*)",
            r"wp-(?:content|includes)/[^\"']+[?&]ver=([0-9][0-9A-Za-z._-]*)",
            r"wordpress\s+([0-9][0-9A-Za-z._-]*)",
        ],
    },
    "Joomla": {
        "patterns": [
            r"joomla",
            r"/media/system/",
            r"com_content",
            r"content=\"Joomla!",
        ],
        "version_patterns": [
            r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Joomla![^0-9]*([0-9][^\"'<\s]*)",
            r"joomla!?\s*([0-9][0-9A-Za-z._-]*)",
        ],
    },
    "Drupal": {
        "patterns": [
            r"drupal",
            r"/sites/default/",
            r"Drupal\.settings",
            r"/core/misc/drupal",
        ],
        "version_patterns": [
            r"<meta[^>]+name=[\"']Generator[\"'][^>]+content=[\"']Drupal\s+([0-9][^\"'<\s]*)",
            r"drupal\s+([0-9][0-9A-Za-z._-]*)",
        ],
    },
    "Magento": {
        "patterns": [
            r"Magento",
            r"Mage\.Cookies",
            r"/static/frontend/",
            r"X-Magento",
        ],
        "version_patterns": [
            r"magento\s+([0-9][0-9A-Za-z._-]*)",
        ],
    },
    "Shopify": {
        "patterns": [
            r"cdn\.shopify\.com",
            r"Shopify\.theme",
            r"myshopify\.com",
        ],
        "version_patterns": [],
    },
}


def _base_url(url):
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _clean_version(version):
    if not version:
        return None
    cleaned = re.sub(r"[^0-9A-Za-z._-].*$", "", version.strip())
    return cleaned.strip(".-_") or None


def _generator_meta(html):
    soup = BeautifulSoup(html or "", "html.parser")
    generator = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
    if generator and generator.get("content"):
        return generator["content"].strip()
    return None


def _score_cms(cms_name, config, haystack):
    matches = []
    for pattern in config["patterns"]:
        if re.search(pattern, haystack, re.I):
            matches.append(pattern)
    confidence = "low"
    if len(matches) >= 3:
        confidence = "high"
    elif len(matches) >= 2:
        confidence = "medium"
    return matches, confidence


def detect_cms(base_url, should_stop=None):
    if should_stop_scan(should_stop):
        return {
            "detected": False,
            "name": None,
            "version": None,
            "confidence": "none",
            "evidence": [],
            "checked_urls": [],
            "error": None,
        }

    root = _base_url(base_url)
    client = safe_scanner_session(timeout=6)
    checked_urls = [root, urljoin(root, "/")]
    html_parts = []
    headers_text = ""
    error = None

    for url in dict.fromkeys(checked_urls):
        if should_stop_scan(should_stop):
            break
        try:
            response = client.get(url, timeout=6, allow_redirects=True)
            headers_text += " ".join(f"{key}: {value}" for key, value in response.headers.items())
            if response.text:
                html_parts.append(response.text[:250000])
        except requests.exceptions.RequestException as exc:
            error = str(exc)

    html = "\n".join(html_parts)
    generator = _generator_meta(html)
    haystack = "\n".join([html, headers_text, generator or ""])

    best = None
    for cms_name, config in CMS_SIGNATURES.items():
        matches, confidence = _score_cms(cms_name, config, haystack)
        if not matches:
            continue
        version = None
        for pattern in config["version_patterns"]:
            found = re.search(pattern, haystack, re.I)
            if found:
                version = _clean_version(found.group(1))
                break
        candidate = {
            "detected": True,
            "name": cms_name,
            "version": version,
            "confidence": confidence,
            "evidence": matches[:4],
            "generator": generator,
            "checked_urls": checked_urls,
            "error": error,
        }
        if not best or len(matches) > len(best["evidence"]):
            best = candidate

    if best:
        return best

    return {
        "detected": False,
        "name": None,
        "version": None,
        "confidence": "none",
        "evidence": [],
        "generator": generator,
        "checked_urls": checked_urls,
        "error": error,
    }


def _cvss_from_metrics(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if not values:
            continue
        data = values[0].get("cvssData", {})
        return {
            "score": data.get("baseScore"),
            "severity": values[0].get("cvssData", {}).get("baseSeverity") or values[0].get("baseSeverity"),
            "vector": data.get("vectorString"),
        }
    return {"score": None, "severity": "UNKNOWN", "vector": None}


def _description(cve):
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return response_excerpt(desc.get("value", ""), limit=260)
    descriptions = cve.get("descriptions", [])
    return response_excerpt(descriptions[0].get("value", ""), limit=260) if descriptions else ""


def _normalize_severity(severity):
    normalized = (severity or "info").lower()
    if normalized in {"critical", "high", "medium", "low"}:
        return normalized
    return "info"


def lookup_cves(cms_name, version=None, should_stop=None):
    if should_stop_scan(should_stop) or not cms_name:
        return []

    keyword = f"{cms_name} {version}" if version else f"{cms_name} CMS"
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": MAX_CVE_RESULTS,
    }

    try:
        response = nvd_session.get(NVD_API_URL, params=params, timeout=8)
        response.raise_for_status()
        payload = response.json()
    except (ValueError, requests.exceptions.RequestException):
        return []

    findings = []
    for item in payload.get("vulnerabilities", [])[:MAX_CVE_RESULTS]:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        cvss = _cvss_from_metrics(cve.get("metrics", {}))
        findings.append(
            {
                "id": cve_id,
                "source": "NVD",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "severity": _normalize_severity(cvss.get("severity")),
                "score": cvss.get("score"),
                "vector": cvss.get("vector"),
                "description": _description(cve),
                "match_basis": keyword,
                "confidence": "candidate",
            }
        )
    return findings


def scan_cms(base_url, should_stop=None):
    print(f"\n[CMS] Fingerprinting: {base_url}")
    detected = detect_cms(base_url, should_stop=should_stop)
    cves = []
    if detected.get("detected") and not should_stop_scan(should_stop):
        cves = lookup_cves(detected.get("name"), detected.get("version"), should_stop=should_stop)
    print(f"[CMS] Detected={detected.get('name') or 'none'} CVEs={len(cves)}")
    return {
        "detected": detected,
        "cves": cves,
        "cve_source": "NVD",
        "cve_lookup": "keyword",
    }
