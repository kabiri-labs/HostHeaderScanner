"""Copy-pasteable reproduction commands for findings."""

from urllib.parse import urlparse

from ..core.findings import CLASS_POSTURE, finding_class_of
from ..core.request_file import is_credential_header, redact_credentials


def _shell_quote(value):
    return "'" + str(value).replace("'", "'\\''") + "'"


def _saved_request_note(request_spec):
    """What a reader has to add back to make the command reproduce.

    A scan driven from a request file sends credentials that are deliberately
    left out of the command, so the command has to say so rather than look
    complete and quietly fetch the login page. Nothing is said when the file
    carried no credentials, because then nothing was left out.
    """
    if request_spec is None:
        return ""
    if not any(is_credential_header(name) for name in request_spec.headers):
        return ""
    where = f" from {request_spec.source}" if request_spec.source else ""
    return f"  # add the credentials{where}"


def build_reproduction(entry, target_url, insecure, request_spec=None):
    """Build a copy-pasteable command that reproduces a finding.

    Credentials are never inlined. Without a request file they live on the
    session and never reach a report at all; a report goes to an assessor, a
    ticket or a code-scanning dashboard, so a request file must not be the one
    input that puts a live session cookie there.
    """
    method = entry.get("method", "GET")
    url = entry.get("url") or target_url
    note = _saved_request_note(request_spec)

    # A request sent over a raw socket cannot be expressed with curl - that is
    # why it was sent that way - so emit a wire-level repro instead.
    if entry.get("raw_request"):
        parsed = urlparse(target_url)
        host, port = parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
        wire = redact_credentials(entry["raw_request"]).replace("\r\n", "\\r\\n")
        if parsed.scheme == "https":
            return (f"printf {_shell_quote(wire)} | "
                    f"openssl s_client -quiet -connect {host}:{port} "
                    f"-servername {host}{note}")
        return f"printf {_shell_quote(wire)} | ncat {host} {port}{note}"

    headers = dict(entry.get("headers") or {})
    # A posture finding's header_name is the thing being assessed - a response
    # header field, or a cookie - not something to send. Sending it back as a
    # request header would produce a command that reproduces nothing; fetching
    # the URL and reading the response is the reproduction.
    if (not headers
            and entry.get("header_name")
            and entry.get("param_name") is None
            and finding_class_of(entry) != CLASS_POSTURE):
        headers = {entry["header_name"]: entry.get("payload", "")}

    # The saved request's own headers, so the command asks the endpoint the
    # same question the scan did - a JSON API answers a request without its
    # Content-Type differently, and the repro would prove nothing. The
    # finding's own header wins where both name the same field, exactly as it
    # does during the scan.
    if request_spec is not None:
        carried = {name: value for name, value in request_spec.headers.items()
                   if not is_credential_header(name)}
        carried.update(headers)
        headers = carried

    parts = ["curl", "-sk" if insecure else "-s", "-i"]
    if method != "GET":
        parts += ["-X", method]
    for name, value in headers.items():
        parts += ["-H", _shell_quote(f"{name}: {value}")]
    if request_spec is not None and request_spec.body is not None \
            and method.upper() == request_spec.method:
        parts += ["--data", _shell_quote(request_spec.body)]
    parts.append(_shell_quote(url))
    return " ".join(parts) + note
