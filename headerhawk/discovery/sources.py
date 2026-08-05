"""Where a product tells you what its endpoints are.

Everything here reads what the target already publishes - a sitemap, a robots
file, an API description, the links on its own front page. Nothing is guessed or
brute-forced: this is about covering the product, not finding hidden corners,
and a scan that invents paths would spend its budget on 404s.

Every source is best-effort. A missing or malformed sitemap is normal and yields
nothing rather than an error.
"""

import json
import re
from urllib.parse import urljoin, urlparse

import requests

# Response bytes read from any one source. A sitemap can be enormous, and the
# first slice of one is plenty for a scan that will keep a couple of dozen URLs.
MAX_BODY = 512_000

OPENAPI_PATHS = ["/openapi.json", "/swagger.json", "/v3/api-docs",
                 "/api/openapi.json", "/api-docs"]

_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
_HREF = re.compile(r"""\b(?:href|src)\s*=\s*["']([^"'#\s>]+)""", re.I)
_TEMPLATE = re.compile(r"\{[^/{}]*\}")


def _fetch(session, url, timeout):
    try:
        response = session.request("GET", url, timeout=timeout,
                                   allow_redirects=True)
    except requests.RequestException:
        return None
    if response.status_code >= 400:
        return None
    return response


def _body(response):
    return (response.text or "")[:MAX_BODY]


def same_origin(candidate, base):
    """True when a URL belongs to the origin being scanned."""
    a, b = urlparse(candidate), urlparse(base)
    return a.scheme in ("http", "https") and (a.scheme, a.netloc) == (b.scheme,
                                                                     b.netloc)


def origin_of(url):
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def from_robots(session, base, timeout):
    """Paths a robots file names, and any sitemaps it points at."""
    response = _fetch(session, urljoin(origin_of(base) + "/", "robots.txt"),
                      timeout)
    if response is None:
        return [], []
    urls, sitemaps = [], []
    for line in _body(response).splitlines():
        name, _, value = line.partition(":")
        name, value = name.strip().lower(), value.strip()
        if not value:
            continue
        if name == "sitemap":
            sitemaps.append(value)
        elif name in ("disallow", "allow") and value.startswith("/"):
            # A path the site chose to name is a path the site has.
            urls.append(urljoin(origin_of(base) + "/", value.split("*")[0]))
    return urls, sitemaps


def from_sitemap(session, base, timeout, extra_sitemaps=()):
    """URLs listed in the sitemap, following a sitemap index one level."""
    found = []
    queue = list(extra_sitemaps) or []
    queue.append(urljoin(origin_of(base) + "/", "sitemap.xml"))
    seen_sitemaps = set()
    # One level of indirection: a sitemap index points at sitemaps, and that is
    # as deep as this needs to go.
    for _ in range(2):
        next_queue = []
        for sitemap_url in queue:
            if sitemap_url in seen_sitemaps:
                continue
            seen_sitemaps.add(sitemap_url)
            response = _fetch(session, sitemap_url, timeout)
            if response is None:
                continue
            body = _body(response)
            locations = _LOC.findall(body)
            if "<sitemapindex" in body.lower():
                next_queue.extend(locations)
            else:
                found.extend(locations)
        queue = next_queue
        if not queue:
            break
    return [url for url in found if same_origin(url, base)]


def _fill_template(path):
    """Replace OpenAPI path parameters with a benign placeholder value.

    A description declares `/users/{id}`, which is a route rather than a URL -
    requesting it verbatim asks for a path that percent-encodes to `%7Bid%7D`
    and exists nowhere. Substituting `1` makes the request a realistic read of
    that route, and the result shapes to the same endpoint as any other
    identifier seen elsewhere, so the two do not both take up a slot.
    """
    return _TEMPLATE.sub("1", path)


def _openapi_urls(spec, base):
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    prefix = ""
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        prefix = str(servers[0].get("url") or "").rstrip("/")
    elif spec.get("basePath"):
        prefix = str(spec["basePath"]).rstrip("/")
    urls = []
    for path in paths:
        if not isinstance(path, str) or not path.startswith("/"):
            continue
        path = _fill_template(path)
        joined = f"{prefix}{path}" if prefix else path
        urls.append(joined if joined.startswith("http")
                    else urljoin(origin_of(base) + "/", joined.lstrip("/")))
    return urls


def from_openapi(session, base, timeout, explicit_url=None):
    """Endpoints an OpenAPI or Swagger description declares."""
    candidates = ([explicit_url] if explicit_url else
                  [urljoin(origin_of(base) + "/", path.lstrip("/"))
                   for path in OPENAPI_PATHS])
    for url in candidates:
        response = _fetch(session, url, timeout)
        if response is None:
            continue
        try:
            spec = json.loads(_body(response))
        except ValueError:
            continue
        if not isinstance(spec, dict):
            continue
        urls = _openapi_urls(spec, base)
        if urls:
            return urls
    return []


def from_links(session, base, timeout):
    """Same-origin links on the target's own page, one level deep."""
    response = _fetch(session, base, timeout)
    if response is None:
        return []
    urls = []
    for href in _HREF.findall(_body(response)):
        if href.lower().startswith(("mailto:", "javascript:", "data:", "tel:")):
            continue
        candidate = urljoin(base, href)
        if same_origin(candidate, base):
            urls.append(candidate.split("#")[0])
    return urls
