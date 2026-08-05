"""Driving a scan from a saved HTTP request.

Real requests are rarely a bare URL. They carry a session cookie, a bearer
token, a content type, a body, and a dozen headers a proxy or a single-page app
added along the way - and a scan that drops all of that is testing a different
request from the one that matters. Saving the request from a browser or an
intercepting proxy and handing the file over keeps it intact.

What the file provides is the *starting point*. Every check still sets the
header it is testing: where the file already carries that header the check's
value replaces it, and where it does not the header is added. That is what
``requests`` does when a per-request header meets a session header of the same
name, so the behaviour falls out of using the file as the session's base rather
than being special-cased anywhere.

A few header fields are deliberately not carried over. ``Host`` decides the
target rather than travelling as a header, and leaving it pinned would defeat
every Host-manipulation check in the scanner. ``Content-Length`` and the
connection-management fields describe one particular transmission, so re-sending
them verbatim would contradict the request actually being made.
"""

from collections import namedtuple
from urllib.parse import urlsplit, urlunsplit

# Not carried into the session. Host selects the target and is re-derived per
# request - pinning it would neutralise the Host-header checks entirely - and
# the rest describe a single transmission that is not the one being made.
EXCLUDED_HEADERS = frozenset({
    "host", "content-length", "transfer-encoding", "connection",
    "keep-alive", "upgrade", "proxy-connection", "expect",
})

DEFAULT_SCHEME = "https"

# Header fields whose value is a credential. They travel on the scan because
# that is the point of supplying a request, but they are kept out of the
# reproduction commands: a report goes to an assessor, a ticket or a code
# scanning dashboard, and a live session cookie does not belong in any of them.
CREDENTIAL_HEADERS = frozenset({
    "cookie", "authorization", "proxy-authorization",
})

# Custom auth headers have no registry, so they are recognised by convention.
# Over-redacting costs a reader one lookup in their own file; under-redacting
# publishes a live credential, so the doubt is resolved towards redaction.
CREDENTIAL_MARKERS = ("token", "secret", "auth", "session", "credential",
                      "api-key", "apikey", "api_key", "passwd", "password")

REDACTED = "<redacted - see the request file>"


def is_credential_header(name):
    """Whether a header field's value should be kept out of a report."""
    lowered = name.strip().lower()
    return (lowered in CREDENTIAL_HEADERS
            or any(marker in lowered for marker in CREDENTIAL_MARKERS))

RequestSpec = namedtuple("RequestSpec", "method url headers body host source")


class RequestFileError(ValueError):
    """The file could not be read as an HTTP request."""


def _split_head_and_body(text):
    for separator in ("\r\n\r\n", "\n\n"):
        head, found, body = text.partition(separator)
        if found:
            return head, body
    return text, ""


def _trim_body(body, headers):
    """The body the saved request actually had.

    ``Content-Length`` is authoritative where the file declares it: a file
    saved by an editor or a proxy usually ends with a newline that was never
    part of the message, and sending it would make the body one byte longer
    than the one being reproduced. Without a declared length there is nothing
    to check against, so only a single trailing line break is dropped.
    """
    declared = next((value for name, value in headers.items()
                     if name.lower() == "content-length"), "")
    if declared.strip().isdigit():
        return body.encode("utf-8", "replace")[:int(declared)].decode(
            "utf-8", "replace")
    for ending in ("\r\n", "\n"):
        if body.endswith(ending):
            return body[:-len(ending)]
    return body


def _scheme_for(host_header, explicit):
    if explicit:
        return explicit
    # A port in the Host header is the only hint a saved request carries.
    if host_header.endswith(":80"):
        return "http"
    if host_header.endswith(":443"):
        return "https"
    return DEFAULT_SCHEME


def parse_request(text, scheme=None, source=None):
    """Parse a raw HTTP/1.x request into the pieces a scan needs.

    An absolute-URI request line is honoured when present; otherwise the URL is
    built from the ``Host`` header and the path. The scheme is taken from
    ``--request-scheme`` when given, then from a port in ``Host``, and defaults
    to HTTPS - guessing plaintext for a request that carried a session cookie
    would be the more dangerous default.
    """
    head, body = _split_head_and_body(text.lstrip("\r\n"))
    lines = [line for line in head.replace("\r\n", "\n").split("\n") if line.strip()]
    if not lines:
        raise RequestFileError("the file is empty")

    parts = lines[0].split()
    if len(parts) < 2:
        raise RequestFileError(
            f"the first line is not a request line: {lines[0]!r}")
    method, target = parts[0].upper(), parts[1]

    headers = {}
    for line in lines[1:]:
        if line[:1] in (" ", "\t") and headers:
            # Obsolete line folding: append to the previous field.
            name = list(headers)[-1]
            headers[name] += " " + line.strip()
            continue
        name, separator, value = line.partition(":")
        if not separator:
            raise RequestFileError(f"header line has no colon: {line!r}")
        headers[name.strip()] = value.strip()

    host_header = next((value for name, value in headers.items()
                        if name.lower() == "host"), "")

    if target.lower().startswith(("http://", "https://")):
        split = urlsplit(target)
        url = target
        host = split.netloc
    else:
        if not target.startswith("/"):
            # Rejected rather than patched up: an origin-form request line
            # always starts with '/', so anything else here means the line was
            # not what it looked like - and building a URL from it anyway would
            # scan an address the file never mentioned.
            raise RequestFileError(
                f"the request target is neither an absolute URL nor a path "
                f"beginning with '/': {target!r}")
        if not host_header:
            raise RequestFileError(
                "the request has no Host header and no absolute URL, so there "
                "is nothing to say which host to scan")
        host = host_header
        split = urlsplit(f"//{host}{target}", scheme=_scheme_for(host, scheme))
        url = urlunsplit((split.scheme, split.netloc, split.path or "/",
                          split.query, ""))

    carried = {name: value for name, value in headers.items()
               if name.lower() not in EXCLUDED_HEADERS}
    body = _trim_body(body, headers)
    return RequestSpec(method=method, url=url, headers=carried,
                       body=body if body.strip() else None, host=host,
                       source=source)


def load_request(path, scheme=None):
    """Read and parse a request file, raising RequestFileError on any problem."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError as exc:
        raise RequestFileError(f"could not read '{path}': {exc}") from exc
    return parse_request(text, scheme=scheme, source=path)


def header_lines(spec, host_value):
    """The file's headers as wire-format lines, for the raw-socket checks.

    ``Host`` is supplied by the caller because those checks are manipulating it;
    everything else is the request as it was saved.
    """
    lines = [f"Host: {host_value}"]
    lines += [f"{name}: {value}" for name, value in spec.headers.items()]
    lines.append("Connection: close")
    return lines


def redact_credentials(text):
    """Blank out credential header values in a block of wire-format headers.

    Used on the reproduction commands. Without a request file a scan's own
    credentials never reach a report - they live on the session and the repro
    is rebuilt from the finding - so a request file must not be the one input
    that changes that.
    """
    out = []
    for line in text.split("\n"):
        # Line endings are preserved: the caller is holding a wire-format
        # request, and dropping a CR would change the message it describes.
        body = line.rstrip("\r")
        ending = line[len(body):]
        name, separator, _ = body.partition(":")
        if separator and is_credential_header(name):
            out.append(f"{name}: {REDACTED}{ending}")
        else:
            out.append(line)
    return "\n".join(out)
