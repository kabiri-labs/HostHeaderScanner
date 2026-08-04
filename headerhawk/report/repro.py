"""Copy-pasteable reproduction commands for findings."""

from urllib.parse import urlparse

def _shell_quote(value):
    return "'" + str(value).replace("'", "'\\''") + "'"


def build_reproduction(entry, target_url, insecure):
    """Build a copy-pasteable command that reproduces a finding."""
    test_type = entry.get("test_type", "")
    method = entry.get("method", "GET")
    url = entry.get("url") or target_url

    # Raw-socket bypasses cannot be expressed with curl; emit a wire-level repro.
    if test_type == "Host Header Bypass" and entry.get("raw_request"):
        parsed = urlparse(target_url)
        host, port = parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
        wire = entry["raw_request"].replace("\r\n", "\\r\\n")
        if parsed.scheme == "https":
            return (f"printf {_shell_quote(wire)} | "
                    f"openssl s_client -quiet -connect {host}:{port} -servername {host}")
        return f"printf {_shell_quote(wire)} | ncat {host} {port}"

    headers = dict(entry.get("headers") or {})
    if not headers and entry.get("header_name") and entry.get("param_name") is None:
        headers = {entry["header_name"]: entry.get("payload", "")}

    parts = ["curl", "-sk" if insecure else "-s", "-i"]
    if method != "GET":
        parts += ["-X", method]
    for name, value in headers.items():
        parts += ["-H", _shell_quote(f"{name}: {value}")]
    parts.append(_shell_quote(url))
    return " ".join(parts)
