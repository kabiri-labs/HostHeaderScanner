"""Rules that assess a response's security header posture.

Each rule inspects the response headers and returns either ``None`` (the control
is in place) or a ``(test_result, analysis)`` pair describing what is wrong.
Rules are deliberately narrow: they report what the cited requirement actually
asks for, and stay quiet otherwise. A posture report that cries wolf gets
ignored, which costs more than the finding was worth.
"""

import re
from collections import namedtuple

# ASVS 5.0 3.4.1 asks for a maximum age of at least one year.
ONE_YEAR_SECONDS = 31536000

PostureRule = namedtuple("PostureRule", "test_type severity assess")

# Headers that routinely carry a product version, which 13.4.6 asks not to
# expose. A bare product name (e.g. "cloudflare") is not a finding.
_BANNER_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version",
                   "X-AspNetMvc-Version", "X-Generator"]
_VERSION = re.compile(r"\d+\.\d+")


def directives(policy):
    """Parse a CSP into ``{directive: [lower-cased values]}``."""
    parsed = {}
    for part in (policy or "").split(";"):
        tokens = part.split()
        if tokens:
            parsed[tokens[0].lower()] = [token.lower() for token in tokens[1:]]
    return parsed


def _hsts(headers, scheme):
    # Over plaintext the header is meaningless and a browser would ignore it,
    # so reporting it missing on an http:// target would be noise.
    if scheme != "https":
        return None
    value = headers.get("strict-transport-security")
    if not value:
        return ("Missing",
                "No 'Strict-Transport-Security' response header field, so a "
                "browser has nothing telling it to stay on HTTPS for this host.")
    problems = []
    match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
    if not match:
        problems.append("no 'max-age' directive")
    elif int(match.group(1)) < ONE_YEAR_SECONDS:
        problems.append(f"'max-age={match.group(1)}' is below the required "
                        f"one year ({ONE_YEAR_SECONDS})")
    if "includesubdomains" not in value.lower():
        problems.append("'includeSubDomains' is not set")
    if problems:
        return ("Weak", f"'Strict-Transport-Security: {value}' - "
                        f"{'; '.join(problems)}.")
    return None


def _csp(headers, scheme):
    value = headers.get("content-security-policy")
    if not value:
        return ("Missing",
                "No 'Content-Security-Policy' response header field.")
    parsed = directives(value)
    problems = []
    # object-src falls back to default-src, so 'default-src none' satisfies it;
    # base-uri has no fallback and must be set explicitly.
    default_src_none = parsed.get("default-src") == ["'none'"]
    if parsed.get("object-src") != ["'none'"] and not default_src_none:
        problems.append("no \"object-src 'none'\" (and no \"default-src 'none'\" "
                        "to fall back to)")
    if parsed.get("base-uri") != ["'none'"]:
        problems.append("no \"base-uri 'none'\"")
    if problems:
        return ("Weak", f"Content-Security-Policy is set but {' and '.join(problems)}.")
    return None


def _content_type_options(headers, scheme):
    value = headers.get("x-content-type-options")
    if not value:
        return ("Missing",
                "No 'X-Content-Type-Options' response header field, so a "
                "browser may MIME-sniff the response.")
    if value.strip().lower() != "nosniff":
        return ("Weak", f"'X-Content-Type-Options: {value}' is not 'nosniff'.")
    return None


def _referrer_policy(headers, scheme):
    value = headers.get("referrer-policy")
    if not value:
        return ("Missing", "No 'Referrer-Policy' response header field.")
    if "unsafe-url" in value.lower():
        return ("Weak", f"'Referrer-Policy: {value}' sends the full URL to "
                        f"third-party origins.")
    return None


def _frame_protection(headers, scheme):
    policy = headers.get("content-security-policy") or ""
    if "frame-ancestors" in directives(policy):
        return None
    xfo = (headers.get("x-frame-options") or "").strip().lower()
    if xfo in ("deny", "sameorigin"):
        return ("Weak",
                f"Embedding is restricted only by 'X-Frame-Options: {xfo}'; the "
                f"'frame-ancestors' Content-Security-Policy directive, which "
                f"supersedes it, is not set.")
    return ("Missing",
            "Neither a 'frame-ancestors' Content-Security-Policy directive nor "
            "a usable 'X-Frame-Options' header field restricts embedding.")


def _coop(headers, scheme):
    value = headers.get("cross-origin-opener-policy")
    if not value:
        return ("Missing", "No 'Cross-Origin-Opener-Policy' response header field.")
    if value.strip().lower() != "same-origin":
        return ("Weak", f"'Cross-Origin-Opener-Policy: {value}' is not 'same-origin'.")
    return None


def _permissions_policy(headers, scheme):
    if not headers.get("permissions-policy"):
        return ("Missing",
                "No 'Permissions-Policy' response header field, so powerful "
                "browser features are not restricted for this document.")
    return None


def _version_disclosure(headers, scheme):
    exposed = []
    for name in _BANNER_HEADERS:
        value = headers.get(name.lower())
        if value and _VERSION.search(value):
            exposed.append(f"{name}: {value}")
    if exposed:
        return ("Exposed",
                f"Response header field(s) expose a component version: "
                f"{'; '.join(exposed)}.")
    return None


RULES = [
    PostureRule("Strict-Transport-Security", "Medium", _hsts),
    PostureRule("Content-Security-Policy", "Medium", _csp),
    PostureRule("Frame Protection", "Medium", _frame_protection),
    PostureRule("X-Content-Type-Options", "Low", _content_type_options),
    PostureRule("Referrer-Policy", "Low", _referrer_policy),
    PostureRule("Cross-Origin-Opener-Policy", "Low", _coop),
    PostureRule("Permissions-Policy", "Low", _permissions_policy),
    PostureRule("Version Disclosure", "Low", _version_disclosure),
]
