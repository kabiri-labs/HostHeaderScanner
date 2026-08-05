"""Whether a check belongs to a host or to an individual endpoint.

Discovery makes this distinction matter. Header posture, CORS policy and access
control differ from route to route, so those checks earn their keep on every
endpoint. A front-end that mis-parses the Host header, or that desyncs from its
back-end, does so for the whole host at once - running those per endpoint would
repeat identical requests and file identical findings.
"""

SCOPE_ENDPOINT = "endpoint"
SCOPE_HOST = "host"


def runs_on(check, is_primary_target):
    """Whether a check should run against this particular URL.

    Host-scoped checks run only against the target that was asked for; every
    other URL in the scan is another route on the same host.
    """
    return is_primary_target or getattr(check, "scope", SCOPE_ENDPOINT) != SCOPE_HOST
