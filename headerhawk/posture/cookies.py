"""Parsing of Set-Cookie header fields, and the rules that assess them."""

import re
from collections import namedtuple

from .model import Issue, PostureRule

# ASVS 5.0 3.3.5: name and value combined must not exceed 4096 bytes.
MAX_COOKIE_BYTES = 4096

# Cookie names that suggest a session token or another sensitive value. ASVS
# 3.3.4 scopes HttpOnly to exactly those, so guessing is better than either
# flagging every cookie (an analytics cookie legitimately needs script access)
# or flagging none.
#
# Matched as substrings, because these names are overwhelmingly run together -
# "sessionid", "PHPSESSID", "authtoken". Requiring a separator around the word
# would miss the most common session cookie names there are.
_SENSITIVE_SUBSTRINGS = ("sess", "auth", "token", "jwt", "login", "remember",
                         "credential", "password", "passwd", "secret")
# "sid" is too short to match loosely - it appears inside ordinary words - so it
# only counts when it stands on its own (e.g. "connect.sid").
_SENSITIVE_BOUNDED = re.compile(r"(^|[-_.])sid([-_.]|$)", re.I)

# Several Set-Cookie fields may arrive folded into one comma-joined string. A
# plain split on "," would tear apart "Expires=Wed, 21 Oct 2015 ...", so only
# split where the next thing really is another "name=" pair.
_FOLD_SPLIT = re.compile(r",\s*(?=[^=;,\s]+=)")

Cookie = namedtuple("Cookie", "name value attributes raw")


def split_set_cookie(raw):
    """Split a possibly comma-folded Set-Cookie value into individual cookies."""
    if not raw:
        return []
    return [part.strip() for part in _FOLD_SPLIT.split(raw) if part.strip()]


def set_cookie_values(response):
    """Return every Set-Cookie field on a response, unfolded.

    Prefers the structured sources, because a server may legitimately send
    several Set-Cookie fields and joining them loses the boundaries. Falls back
    to unfolding the joined value when only that is available.
    """
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    for accessor in ("getlist", "get_all"):
        method = getattr(raw_headers, accessor, None)
        if callable(method):
            values = method("Set-Cookie")
            if values:
                return [value.strip() for value in values if value.strip()]
    headers = getattr(response, "headers", {}) or {}
    getter = getattr(headers, "get_all", None)
    if callable(getter):
        values = getter("Set-Cookie") or []
        if values:
            return [value.strip() for value in values if value.strip()]
    joined = ""
    for name, value in dict(headers).items():
        if name.lower() == "set-cookie":
            joined = value
            break
    return split_set_cookie(joined)


def parse_set_cookie(raw):
    """Parse one Set-Cookie value into a ``Cookie``, or None if unparseable."""
    if not raw or "=" not in raw.split(";", 1)[0]:
        return None
    pairs = raw.split(";")
    name, _, value = pairs[0].partition("=")
    attributes = {}
    for part in pairs[1:]:
        attr_name, sep, attr_value = part.strip().partition("=")
        if not attr_name:
            continue
        attributes[attr_name.strip().lower()] = attr_value.strip() if sep else True
    return Cookie(name.strip(), value.strip(), attributes, raw)


def _is_sensitive(cookie):
    lowered = cookie.name.lower()
    if any(token in lowered for token in _SENSITIVE_SUBSTRINGS):
        return True
    return bool(_SENSITIVE_BOUNDED.search(cookie.name))


def _secure_attribute(facts):
    # Over plaintext a Secure cookie would never be sent back, so advising it
    # there would be advising a broken site.
    if facts.scheme != "https":
        return []
    return [Issue("Missing",
                  f"Cookie '{cookie.name}' has no 'Secure' attribute, so a "
                  f"browser will also send it over plaintext HTTP.",
                  f"Set-Cookie: {cookie.name}")
            for cookie in facts.cookies
            if "secure" not in cookie.attributes]


def _http_only_attribute(facts):
    issues = []
    for cookie in facts.cookies:
        if "httponly" in cookie.attributes or not _is_sensitive(cookie):
            continue
        issues.append(Issue(
            "Missing",
            f"Cookie '{cookie.name}' looks like a session or otherwise "
            f"sensitive value but has no 'HttpOnly' attribute, so page script "
            f"can read it.",
            f"Set-Cookie: {cookie.name}"))
    return issues


def _same_site_attribute(facts):
    return [Issue("Missing",
                  f"Cookie '{cookie.name}' has no 'SameSite' attribute.",
                  f"Set-Cookie: {cookie.name}")
            for cookie in facts.cookies
            if "samesite" not in cookie.attributes]


def _name_prefix(facts):
    return [Issue("Missing",
                  f"Cookie '{cookie.name}' uses neither the '__Secure-' nor "
                  f"the '__Host-' name prefix, so a browser does not enforce "
                  f"its Secure/host scoping.",
                  f"Set-Cookie: {cookie.name}")
            for cookie in facts.cookies
            if not cookie.name.startswith(("__Secure-", "__Host-"))]


def _size(facts):
    issues = []
    for cookie in facts.cookies:
        size = len(f"{cookie.name}{cookie.value}".encode("utf-8", "ignore"))
        if size > MAX_COOKIE_BYTES:
            issues.append(Issue(
                "Oversized",
                f"Cookie '{cookie.name}' name and value total {size} bytes, "
                f"above the {MAX_COOKIE_BYTES}-byte limit.",
                f"Set-Cookie: {cookie.name}"))
    return issues


COOKIE_RULES = [
    PostureRule("Cookie HttpOnly Attribute", "Medium", _http_only_attribute),
    PostureRule("Cookie Secure Attribute", "Medium", _secure_attribute),
    PostureRule("Cookie SameSite Attribute", "Low", _same_site_attribute),
    PostureRule("Cookie Name Prefix", "Low", _name_prefix),
    PostureRule("Cookie Size", "Low", _size),
]
