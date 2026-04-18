import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

session = requests.Session()


def normalize(url):
    parsed = urlparse(url)
    return parsed.scheme + "://" + parsed.netloc + parsed.path + (
        "?" + parsed.query if parsed.query else ""
    )


def is_valid_link(href):
    if not href:
        return False
    if href.startswith("#"):
        return False
    if href.startswith("javascript"):
        return False
    if href.startswith("mailto"):
        return False
    return True


def get_links(url):
    links = set()

    try:
        response = session.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        for a in soup.find_all("a"):
            href = a.get("href")

            if not is_valid_link(href):
                continue

            full_url = normalize(urljoin(url, href))

            if urlparse(full_url).netloc == urlparse(url).netloc:
                links.add(full_url)

    except Exception as e:
        print("Crawler error:", e)

    return links


def crawl(target, max_pages=30):
    visited_urls = set()
    to_visit = [target]
    discovered = set()

    while to_visit and len(discovered) < max_pages:
        url = to_visit.pop()

        if url not in visited_urls:
            visited_urls.add(url)
            discovered.add(url)

            links = get_links(url)

            for link in links:
                if link not in visited_urls:
                    to_visit.append(link)

    pages = list(discovered)

    # filter static files
    pages = [
        p for p in pages
        if not p.endswith(('.jpg', '.png', '.css', '.js', '.pdf', '.ico', '.svg'))
    ]

    return pages