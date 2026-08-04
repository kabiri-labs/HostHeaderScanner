"""SARIF 2.1.0 rendering of the collected findings."""

import hashlib
import re

from .._meta import __github_url__, __tool_name__, __version__
from ..core.severity import DEFAULT_SEVERITY, SEVERITY_META, severity_for

def _rule_id(test_type):
    """Turn a human test-type name into a stable SARIF rule id slug."""
    return re.sub(r"[^a-z0-9]+", "-", test_type.lower()).strip("-") or "finding"


def _fingerprint(*parts):
    """Stable fingerprint so a platform can de-duplicate recurring findings."""
    raw = "|".join(str(part) for part in parts)
    return hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()


def build_sarif(results, version=None):
    """Build a SARIF 2.1.0 log from the collected findings.

    The format is understood by GitHub code scanning and most security
    dashboards, letting the scanner plug into a product pipeline directly.
    """
    version = version or __version__
    rules = {}
    sarif_results = []
    for result in results:
        test_type = result.get("test_type", "Finding")
        rule_id = _rule_id(test_type)
        severity = result.get("severity") or severity_for(test_type)
        level, score = SEVERITY_META.get(severity, SEVERITY_META[DEFAULT_SEVERITY])
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": re.sub(r"\s+", "", test_type) or "Finding",
                "shortDescription": {"text": test_type},
                "properties": {"security-severity": score, "tags": ["security"]},
            }
        location = result.get("url") or ""
        header_or_param = result.get("header_name") or result.get("param_name") or ""
        entry = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": result.get("analysis") or test_type},
            "properties": {
                "security-severity": score,
                "severity": severity,
                "method": result.get("method", ""),
                "payload": result.get("payload", ""),
                "header_or_parameter": header_or_param,
                "status_code": result.get("status_code", ""),
            },
            "partialFingerprints": {
                "hostHeaderScanner/v1": _fingerprint(
                    test_type, header_or_param, result.get("payload", ""), location),
            },
        }
        if location:
            entry["locations"] = [{
                "physicalLocation": {"artifactLocation": {"uri": location}},
            }]
        sarif_results.append(entry)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": __tool_name__,
                "version": version,
                "informationUri": __github_url__,
                "rules": list(rules.values()),
            }},
            "results": sarif_results,
        }],
    }
