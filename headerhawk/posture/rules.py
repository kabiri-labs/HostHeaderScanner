"""Rules that assess a response's security header posture.

Each rule inspects a ``ResponseFacts`` and returns the problems it found, or an
empty list when the control is in place. Rules are deliberately narrow: they
report what the cited requirement actually asks for, and stay quiet otherwise.
A posture report that cries wolf gets ignored, which costs more than the finding
was worth.
"""

import re

from .cookies import COOKIE_RULES
from .model import Issue, PostureRule

# ASVS 5.0 3.4.1 asks for a maximum age of at least one year.
ONE_YEAR_SECONDS = 31536000

# Headers that routinely carry a product version, which 13.4.6 asks not to
# expose. A bare product name (e.g. "cloudflare") is not a finding.
_BANNER_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version",
                   "X-AspNetMvc-Version", "X-Generator"]
_VERSION = re.compile(r"\d+\.\d+")

# Script sources that place no meaningful restriction on where code comes from.
# A scoped wildcard such as "*.example.com" is ordinary practice and is not
# included.
_BROAD_SOURCES = {"*", "http:", "https:", "data:"}
_HASH_PREFIXES = ("'sha256-", "'sha384-", "'sha512-")


def directives(policy):
    """Parse a CSP into ``{directive: [lower-cased values]}``."""
    parsed = {}
    for part in (policy or "").split(";"):
        tokens = part.split()
        if tokens:
            parsed[tokens[0].lower()] = [token.lower() for token in tokens[1:]]
    return parsed


def _one(test_result, analysis, subject):
    return [Issue(test_result, analysis, subject)]


def _hsts(facts):
    # Over plaintext the header is meaningless and a browser would ignore it,
    # so reporting it missing on an http:// target would be noise.
    if facts.scheme != "https":
        return []
    subject = "Strict-Transport-Security"
    value = facts.header(subject)
    if not value:
        return _one("Missing",
                    "No 'Strict-Transport-Security' response header field, so a "
                    "browser has nothing telling it to stay on HTTPS for this "
                    "host.", subject)
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
        return _one("Weak",
                    f"'Strict-Transport-Security: {value}' - "
                    f"{'; '.join(problems)}.", subject)
    return []


def _csp(facts):
    subject = "Content-Security-Policy"
    value = facts.header(subject)
    if not value:
        return _one("Missing",
                    "No 'Content-Security-Policy' response header field.", subject)
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
        return _one("Weak",
                    f"Content-Security-Policy is set but "
                    f"{' and '.join(problems)}.", subject)
    return []


def _csp_script_sources(facts):
    """Assess whether the policy actually constrains where script comes from."""
    policy = facts.header("content-security-policy")
    if not policy:
        return []  # already reported by the presence rule; do not say it twice
    subject = "Content-Security-Policy: script-src"
    parsed = directives(policy)
    sources = parsed.get("script-src")
    if sources is None:
        sources = parsed.get("default-src")
        if sources is None:
            return _one("Weak",
                        "Neither a 'script-src' nor a 'default-src' directive is "
                        "set, so the policy does not restrict where script may "
                        "be loaded from.", subject)

    has_nonce = any(source.startswith("'nonce-") for source in sources)
    has_hash = any(source.startswith(_HASH_PREFIXES) for source in sources)
    strict_dynamic = "'strict-dynamic'" in sources

    problems = []
    # A browser ignores 'unsafe-inline' when a nonce or hash is also present, so
    # reporting it in that case would be wrong, not merely noisy.
    if "'unsafe-inline'" in sources and not (has_nonce or has_hash):
        problems.append("\"'unsafe-inline'\" is in effect (no nonce or hash "
                        "present to override it)")
    if "'unsafe-eval'" in sources:
        problems.append("\"'unsafe-eval'\" permits string-to-code evaluation")
    # 'strict-dynamic' makes a browser ignore host and scheme allowlists, so a
    # broad source alongside it is not the hole it looks like.
    if not strict_dynamic:
        broad = sorted(source for source in sources if source in _BROAD_SOURCES)
        if broad:
            problems.append(f"{', '.join(broad)} allows script from effectively "
                            f"anywhere")
    if problems:
        return _one("Weak",
                    f"Script sources are not effectively restricted: "
                    f"{'; '.join(problems)}.", subject)
    return []


def _csp_reporting(facts):
    policy = facts.header("content-security-policy")
    if not policy:
        return []
    parsed = directives(policy)
    if "report-uri" in parsed or "report-to" in parsed:
        return []
    return _one("Missing",
                "Content-Security-Policy specifies no violation reporting "
                "location ('report-uri' or 'report-to'), so policy breaches go "
                "unseen.", "Content-Security-Policy: report-to")


def _content_type_options(facts):
    subject = "X-Content-Type-Options"
    value = facts.header(subject)
    if not value:
        return _one("Missing",
                    "No 'X-Content-Type-Options' response header field, so a "
                    "browser may MIME-sniff the response.", subject)
    if value.strip().lower() != "nosniff":
        return _one("Weak",
                    f"'X-Content-Type-Options: {value}' is not 'nosniff'.", subject)
    return []


def _referrer_policy(facts):
    subject = "Referrer-Policy"
    value = facts.header(subject)
    if not value:
        return _one("Missing", "No 'Referrer-Policy' response header field.", subject)
    if "unsafe-url" in value.lower():
        return _one("Weak",
                    f"'Referrer-Policy: {value}' sends the full URL to "
                    f"third-party origins.", subject)
    return []


def _frame_protection(facts):
    subject = "Frame Protection"
    policy = facts.header("content-security-policy") or ""
    if "frame-ancestors" in directives(policy):
        return []
    xfo = (facts.header("x-frame-options") or "").strip().lower()
    if xfo in ("deny", "sameorigin"):
        return _one("Weak",
                    f"Embedding is restricted only by 'X-Frame-Options: {xfo}'; "
                    f"the 'frame-ancestors' Content-Security-Policy directive, "
                    f"which supersedes it, is not set.", subject)
    return _one("Missing",
                "Neither a 'frame-ancestors' Content-Security-Policy directive "
                "nor a usable 'X-Frame-Options' header field restricts "
                "embedding.", subject)


def _coop(facts):
    subject = "Cross-Origin-Opener-Policy"
    value = facts.header(subject)
    if not value:
        return _one("Missing",
                    "No 'Cross-Origin-Opener-Policy' response header field.",
                    subject)
    if value.strip().lower() != "same-origin":
        return _one("Weak",
                    f"'Cross-Origin-Opener-Policy: {value}' is not 'same-origin'.",
                    subject)
    return []


def _permissions_policy(facts):
    subject = "Permissions-Policy"
    if not facts.header(subject):
        return _one("Missing",
                    "No 'Permissions-Policy' response header field, so powerful "
                    "browser features are not restricted for this document.",
                    subject)
    return []


def _version_disclosure(facts):
    exposed = []
    for name in _BANNER_HEADERS:
        value = facts.header(name)
        if value and _VERSION.search(value):
            exposed.append(f"{name}: {value}")
    if exposed:
        return _one("Exposed",
                    f"Response header field(s) expose a component version: "
                    f"{'; '.join(exposed)}.", "Version Disclosure")
    return []


HEADER_RULES = [
    PostureRule("Strict-Transport-Security", "Medium", _hsts),
    PostureRule("Content-Security-Policy", "Medium", _csp),
    PostureRule("CSP Script Sources", "Medium", _csp_script_sources),
    PostureRule("Frame Protection", "Medium", _frame_protection),
    PostureRule("X-Content-Type-Options", "Low", _content_type_options),
    PostureRule("Referrer-Policy", "Low", _referrer_policy),
    PostureRule("Cross-Origin-Opener-Policy", "Low", _coop),
    PostureRule("Permissions-Policy", "Low", _permissions_policy),
    PostureRule("CSP Violation Reporting", "Low", _csp_reporting),
    PostureRule("Version Disclosure", "Low", _version_disclosure),
]

RULES = HEADER_RULES + COOKIE_RULES
