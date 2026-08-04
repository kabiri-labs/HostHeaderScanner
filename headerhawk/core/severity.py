"""Severity bands for findings and their reporting metadata."""

# Default severity per finding type, used for triage and for the SARIF
# `security-severity` score that code-scanning platforms consume.
SEVERITY_BY_TEST = {
    "Host Header Injection": "Medium",
    "Host Header Bypass": "High",
    "Web Cache Poisoning": "High",
    "Auth Bypass": "High",
    "Virtual Host Discovery": "Low",
    "SSRF": "High",
    "URL Parameter SSRF": "High",
    "Open Redirect": "Medium",
    "Blind SSRF (OOB)": "High",
}
DEFAULT_SEVERITY = "Medium"

# Maps a severity band onto (SARIF result level, GitHub security-severity score).
SEVERITY_META = {
    "Critical": ("error", "9.5"),
    "High": ("error", "8.0"),
    "Medium": ("warning", "5.0"),
    "Low": ("note", "3.0"),
    "Info": ("note", "1.0"),
}


def severity_for(test_type):
    """Return the default severity band for a finding type."""
    return SEVERITY_BY_TEST.get(test_type, DEFAULT_SEVERITY)
