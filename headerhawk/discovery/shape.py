"""Reducing URLs to the endpoint they represent.

A site hands out `/order/1041`, `/order/1042`, `/order/1043` - three URLs, one
endpoint, one set of response headers, one place a fix would go. Scanning all
three spends the budget three times and puts three copies of every finding in
the report.

So URLs are collapsed to a shape: identifier-looking path segments become
placeholders, and a query string is reduced to its parameter names, because
`/search?q=a` and `/search?q=b` are the same endpoint asked twice.
"""

import re
from urllib.parse import parse_qs, urlparse

_NUMERIC = re.compile(r"^\d+$")
_HEXISH = re.compile(r"^[0-9a-f]{8,}$", re.I)
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
# A long segment mixing digits and letters is almost always a slug or a token.
_TOKENISH = re.compile(r"^(?=.*\d)(?=.*[a-z])[0-9a-z_-]{12,}$", re.I)


def segment_shape(segment):
    """Replace an identifier-looking path segment with a placeholder."""
    if _NUMERIC.match(segment):
        return "{n}"
    if _UUID.match(segment) or _HEXISH.match(segment) or _TOKENISH.match(segment):
        return "{id}"
    return segment


def endpoint_shape(url):
    """The shape two URLs share when they are the same endpoint.

    Includes the origin, so the same path on two hosts stays two endpoints.
    """
    parsed = urlparse(url)
    segments = [segment_shape(part) for part in parsed.path.split("/")]
    path = "/".join(segments) or "/"
    params = sorted(parse_qs(parsed.query))
    query = f"?{'&'.join(params)}" if params else ""
    return f"{parsed.scheme}://{parsed.netloc}{path}{query}"


def deduplicate(urls):
    """Keep the first URL of each distinct shape, in the order given."""
    seen = set()
    kept = []
    for url in urls:
        shape = endpoint_shape(url)
        if shape in seen:
            continue
        seen.add(shape)
        kept.append(url)
    return kept
