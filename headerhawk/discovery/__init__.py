"""Finding the endpoints a scan should cover.

A product is not one URL. Header posture varies by route - the login page, the
API and the static assets rarely carry the same policy - so assessing only the
URL that was typed answers a narrower question than the one being asked.

Discovery is opt-in and bounded. It reads what the target publishes about
itself, collapses URLs that are the same endpoint, and keeps a fixed number of
them. The target that was asked for always comes first and is never dropped.
"""

from collections import namedtuple

from .shape import deduplicate, endpoint_shape, segment_shape
from .sources import (from_links, from_openapi, from_robots, from_sitemap,
                      same_origin)

DEFAULT_LIMIT = 20

Discovery = namedtuple("Discovery", "urls sources considered")

__all__ = ["DEFAULT_LIMIT", "Discovery", "deduplicate", "discover",
           "endpoint_shape", "same_origin", "segment_shape"]


def discover(session, base_url, timeout, limit=DEFAULT_LIMIT, openapi_url=None):
    """Collect endpoints to scan, best-effort and bounded.

    Returns the URLs to scan, which sources contributed, and how many distinct
    endpoints were seen before the limit was applied - so a report can say that
    a product was larger than the scan covered rather than implying it was not.
    """
    found = {}

    robots_urls, sitemaps = from_robots(session, base_url, timeout)
    for name, urls in (
        ("OpenAPI", from_openapi(session, base_url, timeout, openapi_url)),
        ("sitemap", from_sitemap(session, base_url, timeout, sitemaps)),
        ("robots.txt", robots_urls),
        ("links", from_links(session, base_url, timeout)),
    ):
        for url in urls:
            if same_origin(url, base_url):
                found.setdefault(url, name)

    # The requested target leads and is never displaced by anything discovered.
    ordered = [base_url] + [url for url in found if url != base_url]
    unique = deduplicate(ordered)
    kept = unique[:max(1, limit)]
    sources = sorted({found[url] for url in kept if url in found})
    return Discovery(urls=kept, sources=sources, considered=len(unique))
