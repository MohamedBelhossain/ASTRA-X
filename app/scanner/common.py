import re
from urllib.parse import urlparse


def session_headers():
    return {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.5",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    }


def normalize_endpoint(url):
    parsed = urlparse(url or "")
    if parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return parsed.path or url


def response_excerpt(text, needle=None, limit=180):
    content = re.sub(r"\s+", " ", (text or "")).strip()
    if not content:
        return ""
    if needle:
        lower = content.lower()
        target = needle.lower()
        index = lower.find(target)
        if index >= 0:
            start = max(0, index - 50)
            end = min(len(content), index + len(needle) + 80)
            return content[start:end]
    return content[:limit]


def should_stop_scan(callback):
    return bool(callback and callback())


def score_confidence(level):
    order = {"low": 1, "medium": 2, "high": 3, "confirmed": 4}
    return order.get(level, 0)
