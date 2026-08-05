"""Scanning as a logged-in user, and knowing whether that actually worked.

Pointing an unauthenticated scan at an authenticated product is the quietest
way to get a worthless report. Every request comes back as the login page, so
the scanner assesses the login page's headers and reports them as the product's.
Nothing errors; the evidence report just describes the wrong page.

So the credentials are only half of this module. The other half is establishing
whether they took effect - before the scan, so a run that was never authenticated
says so instead of pretending, and again afterwards, because a scan that walks a
site can log itself out partway through.
"""

import os
from collections import namedtuple

import requests

# Whether the scan ran as a logged-in user, and how confident we are of that.
VERIFIED = "authenticated"
UNVERIFIED = "authentication unverified"
FAILED = "authentication failed"
NOT_CONFIGURED = "unauthenticated"

AuthConfig = namedtuple(
    "AuthConfig", "cookie login_url login_data login_method verify_text "
                  "verify_absent")

AuthResult = namedtuple("AuthResult", "state detail")

# Two responses count as indistinguishable when the status matches and the
# bodies are within this fraction of each other - enough to spot "the
# credentials changed nothing" without tripping on a timestamp or a nonce.
_LENGTH_TOLERANCE = 0.02


def resolve_secret(value):
    """Read a value, or the environment variable it names.

    ``env:NAME`` keeps a credential out of the command line and out of shell
    history, which matters more in CI than the small amount of syntax costs.
    """
    if value and value.startswith("env:"):
        return os.environ.get(value[4:], "")
    return value


def parse_cookie(raw):
    """Parse a ``a=1; b=2`` cookie string into a mapping."""
    cookies = {}
    for part in (raw or "").split(";"):
        name, sep, value = part.strip().partition("=")
        if sep and name:
            cookies[name] = value
    return cookies


def parse_form_data(raw):
    """Parse ``user=a&pass=b`` into a mapping."""
    data = {}
    for part in (raw or "").split("&"):
        name, sep, value = part.partition("=")
        if sep and name:
            data[name] = value
    return data


def is_configured(config):
    return bool(config and (config.cookie or config.login_url))


def apply_credentials(session, config):
    """Put any statically supplied credentials on the session."""
    if not config or not config.cookie:
        return
    session.cookies.update(parse_cookie(resolve_secret(config.cookie)))


def log_in(session, config, timeout):
    """Submit the login form, keeping whatever cookies come back.

    Redirects are followed, because a login almost always answers with one and
    the session cookie frequently arrives on the hop.
    """
    if not config or not config.login_url:
        return AuthResult(NOT_CONFIGURED, "no login form was configured")
    data = parse_form_data(resolve_secret(config.login_data))
    if not data:
        return AuthResult(FAILED, "--auth-login-data was empty or unparseable")
    try:
        response = session.request(config.login_method or "POST",
                                   config.login_url, data=data,
                                   timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        return AuthResult(FAILED, f"the login request failed: "
                                  f"{type(exc).__name__}")
    if response.status_code >= 400:
        return AuthResult(FAILED, f"the login endpoint answered "
                                  f"{response.status_code}")
    if not session.cookies:
        return AuthResult(UNVERIFIED,
                          "the login request succeeded but set no cookie, so "
                          "the session may not be carried")
    return AuthResult(VERIFIED, f"logged in via {config.login_url}")


def _fetch(session, url, timeout, **kwargs):
    try:
        return session.request("GET", url, timeout=timeout, **kwargs)
    except requests.RequestException:
        return None


def verify(session, target_url, config, timeout, session_factory=None):
    """Decide whether the scan is really running as a logged-in user.

    An explicit expectation is checked when one was given. Otherwise the
    authenticated response is compared with a clean one: credentials that change
    nothing are not necessarily wrong, but the scan is then not assessing the
    authenticated surface, and the report should not imply that it is.
    """
    if not is_configured(config):
        return AuthResult(NOT_CONFIGURED, "no credentials were supplied")

    response = _fetch(session, target_url, timeout, allow_redirects=True)
    if response is None:
        return AuthResult(FAILED, "the target did not answer the check request")
    body = response.text or ""

    if config.verify_text:
        if config.verify_text in body:
            return AuthResult(VERIFIED, f"'{config.verify_text}' was present in "
                                        f"the response")
        return AuthResult(FAILED, f"'{config.verify_text}' was not in the "
                                  f"response, so the session is not logged in")

    if config.verify_absent:
        if config.verify_absent not in body:
            return AuthResult(VERIFIED, f"'{config.verify_absent}' was absent "
                                        f"from the response")
        return AuthResult(FAILED, f"'{config.verify_absent}' was still in the "
                                  f"response, so the session is not logged in")

    # No expectation given: fall back to asking whether the credentials made any
    # difference at all.
    if session_factory is None:
        return AuthResult(UNVERIFIED, "no expectation was given to check against")
    clean = session_factory()
    anonymous = _fetch(clean, target_url, timeout, allow_redirects=True)
    if anonymous is None:
        return AuthResult(UNVERIFIED,
                          "the anonymous comparison request failed, so the "
                          "credentials could not be shown to take effect")
    if _indistinguishable(response, anonymous):
        return AuthResult(UNVERIFIED,
                          "the response is the same with and without the "
                          "supplied credentials, so this scan may not be "
                          "assessing the authenticated surface (use "
                          "--auth-verify-text to state what a logged-in page "
                          "contains)")
    return AuthResult(VERIFIED,
                      "the response differs from the anonymous one, so the "
                      "credentials are taking effect")


def _indistinguishable(first, second):
    if first.status_code != second.status_code:
        return False
    a, b = len(first.content or b""), len(second.content or b"")
    longest = max(a, b) or 1
    return abs(a - b) / longest <= _LENGTH_TOLERANCE
