from bs4 import BeautifulSoup
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from app.form_parser import get_forms
from app.scanner.common import should_stop_scan
from app.scanner.http_client import safe_scanner_session

STATIC_SUFFIXES = (".jpg", ".jpeg", ".png", ".css", ".js", ".pdf", ".ico", ".svg", ".woff", ".woff2")
BLOCKING_STATUS_CODES = {401, 403, 406, 415, 429, 503}
CHALLENGE_MARKERS = (
    "unsupported media type",
    "access denied",
    "captcha",
    "attention required",
    "verify you are human",
    "cloudflare",
    "cf-chl",
)


def normalize(url):
    parsed = urlparse(url)
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    cleaned = parsed._replace(fragment="", query=query)
    return urlunparse(cleaned)


def is_valid_link(href):
    if not href:
        return False
    lowered = href.lower()
    return not (
        lowered.startswith("#")
        or lowered.startswith("javascript:")
        or lowered.startswith("mailto:")
        or lowered.startswith("tel:")
    )


def _same_host(url_a, url_b):
    return urlparse(url_a).netloc == urlparse(url_b).netloc


def _new_diagnostics():
    return {
        "status_counts": {},
        "blocked_urls": [],
        "timeout_urls": [],
        "error_urls": [],
        "challenge_urls": [],
        "pages_fetched": 0,
        "pages_parsed": 0,
        "sitemap_urls": 0,
        "anti_bot_detected": False,
        "anti_bot_reasons": [],
    }


def _record_status(diagnostics, status_code):
    key = str(status_code)
    diagnostics["status_counts"][key] = diagnostics["status_counts"].get(key, 0) + 1


def _flag_anti_bot(diagnostics, reason):
    diagnostics["anti_bot_detected"] = True
    if reason not in diagnostics["anti_bot_reasons"]:
        diagnostics["anti_bot_reasons"].append(reason)


def _request_page(client, url, diagnostics, timeout=12):
    try:
        response = client.get(url, timeout=timeout, allow_redirects=True)
    except requests.exceptions.Timeout:
        diagnostics["timeout_urls"].append(url)
        _flag_anti_bot(diagnostics, "Timed out while fetching crawl target")
        return None
    except requests.exceptions.RequestException as exc:
        diagnostics["error_urls"].append({"url": url, "error": str(exc)})
        return None

    diagnostics["pages_fetched"] += 1
    _record_status(diagnostics, response.status_code)

    lowered = (response.text or "").lower()
    if response.status_code in BLOCKING_STATUS_CODES:
        diagnostics["blocked_urls"].append({"url": response.url, "status": response.status_code})
        _flag_anti_bot(diagnostics, f"Received blocking status {response.status_code} during crawl")
    if any(marker in lowered for marker in CHALLENGE_MARKERS):
        diagnostics["challenge_urls"].append({"url": response.url, "status": response.status_code})
        _flag_anti_bot(diagnostics, "Challenge or anti-bot response detected during crawl")

    return response


def _discover_sitemap_urls(client, base_url, diagnostics):
    urls = set()
    sitemap_url = urljoin(base_url, "/sitemap.xml")
    response = _request_page(client, sitemap_url, diagnostics, timeout=8)
    if not response or response.status_code != 200 or "<urlset" not in response.text:
        return urls

    soup = BeautifulSoup(response.text, "xml")
    for loc in soup.find_all("loc"):
        if loc.text:
            urls.add(normalize(loc.text.strip()))

    diagnostics["sitemap_urls"] = len(urls)
    return urls


def get_links(url, diagnostics=None, client=None):
    links = set()
    diagnostics = diagnostics or _new_diagnostics()
    client = client or safe_scanner_session(timeout=12)
    response = _request_page(client, url, diagnostics)
    if not response:
        return links, diagnostics

    if response.status_code != 200:
        return links, diagnostics

    content_type = (response.headers.get("content-type") or "").lower()
    if "html" not in content_type and "xml" not in content_type:
        return links, diagnostics

    soup = BeautifulSoup(response.text, "html.parser")
    diagnostics["pages_parsed"] += 1

    for anchor in soup.find_all("a"):
        href = anchor.get("href")
        if not is_valid_link(href):
            continue
        full_url = normalize(urljoin(response.url, href))
        if _same_host(full_url, response.url):
            links.add(full_url)

    for form in get_forms(response.url, client=client):
        action = normalize(form.get("action") or response.url)
        if _same_host(action, response.url):
            links.add(action)

    return links, diagnostics


def _is_static_url(url):
    return urlparse(url).path.lower().endswith(STATIC_SUFFIXES)


def crawl(target, max_pages=40, should_stop=None, return_diagnostics=False, on_page=None):
    client = safe_scanner_session(timeout=12)
    visited_urls = set()
    to_visit = [normalize(target)]
    discovered = set()
    diagnostics = _new_diagnostics()
    to_visit.extend(sorted(_discover_sitemap_urls(client, target, diagnostics)))

    while to_visit and len(discovered) < max_pages:
        if should_stop_scan(should_stop):
            break

        url = to_visit.pop(0)
        if url in visited_urls:
            continue

        visited_urls.add(url)
        discovered.add(url)
        page_count = len([page for page in discovered if not _is_static_url(page)])
        if on_page and not _is_static_url(url):
            on_page(url, page_count)

        links, diagnostics = get_links(url, diagnostics=diagnostics, client=client)
        for link in sorted(links):
            if should_stop_scan(should_stop):
                break
            if link not in visited_urls and link not in to_visit:
                to_visit.append(link)

    pages = [
        page
        for page in discovered
        if not _is_static_url(page)
    ]
    pages = sorted(pages)
    if return_diagnostics:
        diagnostics["visited_urls"] = len(visited_urls)
        diagnostics["discovered_pages"] = len(pages)
        return {"pages": pages, "diagnostics": diagnostics}
    return pages
