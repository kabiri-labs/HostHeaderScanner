"""Copy-pasteable reproduction commands for findings."""

from urllib.parse import urlparse

from ..core.findings import CLASS_POSTURE, finding_class_of


def _shell_quote(value):
    return "'" + str(value).replace("'", "'\\''") + "'"


def build_reproduction(entry, target_url, insecure):
    """Build a copy-pasteable command that reproduces a finding."""
    method = entry.get("method", "GET")
    url = entry.get("url") or target_url

    # A request sent over a raw socket cannot be expressed with curl - that is
    # why it was sent that way - so emit a wire-level repro instead.
    if entry.get("raw_request"):
        parsed = urlparse(target_url)
        host, port = parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
        wire = entry["raw_request"].replace("\r\n", "\\r\\n")
        if parsed.scheme == "https":
            return (f"printf {_shell_quote(wire)} | "
                    f"openssl s_client -quiet -connect {host}:{port} -servername {host}")
        return f"printf {_shell_quote(wire)} | ncat {host} {port}"

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

    parts = ["curl", "-sk" if insecure else "-s", "-i"]
    if method != "GET":
        parts += ["-X", method]
    for name, value in headers.items():
        parts += ["-H", _shell_quote(f"{name}: {value}")]
    parts.append(_shell_quote(url))
    return " ".join(parts)
