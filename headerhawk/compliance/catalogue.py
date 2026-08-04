"""Catalogue of the security controls that findings are mapped onto.

Every entry here is transcribed from the published standard it cites, and the
``url`` points at the chapter it came from so a reader can check it. That
discipline is the point of the module: a report that claims to be compliance
evidence is read as evidence, so a control id that does not exist in the cited
standard is worse than no mapping at all. Nothing is added here that has not
been read in the source text.
"""

from collections import namedtuple

Control = namedtuple("Control", "id framework section title url")

ASVS = "OWASP ASVS 5.0"
_ASVS_CHAPTER = "https://github.com/OWASP/ASVS/blob/master/5.0/en/{file}"
_V3 = _ASVS_CHAPTER.format(file="0x12-V3-Web-Frontend-Security.md")
_V4 = _ASVS_CHAPTER.format(file="0x13-V4-API-and-Web-Service.md")
_V8 = _ASVS_CHAPTER.format(file="0x17-V8-Authorization.md")
_V13 = _ASVS_CHAPTER.format(file="0x22-V13-Configuration.md")

_ENTRIES = [
    Control(
        "ASVS-5.0:3.7.2", ASVS, "3.7.2",
        "Redirects to a different hostname are only made to allowlisted "
        "destinations.",
        _V3),
    Control(
        "ASVS-5.0:3.4.1", ASVS, "3.4.1",
        "A Strict-Transport-Security header field is included on all responses, "
        "with a maximum age of at least one year.",
        _V3),
    Control(
        "ASVS-5.0:3.4.3", ASVS, "3.4.3",
        "A Content-Security-Policy response header field is set, including the "
        "directives object-src 'none' and base-uri 'none'.",
        _V3),
    Control(
        "ASVS-5.0:3.4.4", ASVS, "3.4.4",
        "All responses contain an X-Content-Type-Options: nosniff header field.",
        _V3),
    Control(
        "ASVS-5.0:3.4.5", ASVS, "3.4.5",
        "A Referrer-Policy header field prevents sensitive URL data leaking to "
        "third-party services.",
        _V3),
    Control(
        "ASVS-5.0:3.4.6", ASVS, "3.4.6",
        "The frame-ancestors directive of the Content-Security-Policy header "
        "field prevents unauthorized embedding.",
        _V3),
    Control(
        "ASVS-5.0:3.4.8", ASVS, "3.4.8",
        "Responses include a Cross-Origin-Opener-Policy header field with the "
        "same-origin directive.",
        _V3),
    Control(
        "ASVS-5.0:4.1.3", ASVS, "4.1.3",
        "An HTTP header field set by an intermediary layer - a load balancer, "
        "web proxy or backend-for-frontend - cannot be overridden by the end "
        "user.",
        _V4),
    Control(
        "ASVS-5.0:8.3.1", ASVS, "8.3.1",
        "Authorization rules are enforced at a trusted service layer and do "
        "not rely on controls an untrusted consumer could manipulate.",
        _V8),
    Control(
        "ASVS-5.0:13.2.4", ASVS, "13.2.4",
        "An allowlist defines the external resources or systems the "
        "application is permitted to communicate with.",
        _V13),
    Control(
        "ASVS-5.0:13.2.5", ASVS, "13.2.5",
        "The web or application server is configured with an allowlist of "
        "systems it may send requests to or load data from.",
        _V13),
    Control(
        "ASVS-5.0:13.4.6", ASVS, "13.4.6",
        "The application does not expose detailed version information of "
        "backend components.",
        _V13),
    Control(
        "ASVS-5.0:13.4.5", ASVS, "13.4.5",
        "Documentation and monitoring endpoints are not exposed unless "
        "explicitly intended.",
        _V13),
]

CONTROLS = {control.id: control for control in _ENTRIES}


def describe(control_id):
    """Return the ``Control`` for an id, or None when it is not catalogued.

    Callers render whatever they can and fall back to the bare id, so an
    unknown id degrades to a less useful report rather than a crash.
    """
    return CONTROLS.get(control_id)
