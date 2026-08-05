"""Finding classes and how they gate the process exit code.

Two very different things end up in a report. A *vulnerability* is something the
scanner proved it could do to the target. A *posture* finding is a control the
target does not have in place - real, and the reason an assessor reads the
report, but not an exploited weakness.

Keeping them apart is what lets posture checks ship without turning every
existing pipeline red: the exit code gates on vulnerabilities unless the caller
asks for more. ``--fail-on`` is that ask.
"""

CLASS_VULNERABILITY = "vulnerability"
CLASS_POSTURE = "posture"

DEFAULT_FINDING_CLASS = CLASS_VULNERABILITY

# What each --fail-on choice counts towards the exit code. "vuln" is the
# default because it is the behaviour every existing caller already relies on.
FAIL_ON_CLASSES = {
    "vuln": frozenset({CLASS_VULNERABILITY}),
    "posture": frozenset({CLASS_POSTURE}),
    "any": frozenset({CLASS_VULNERABILITY, CLASS_POSTURE}),
    "none": frozenset(),
}
DEFAULT_FAIL_ON = "vuln"


def finding_class_of(finding):
    """Return a finding's class, defaulting for entries that predate the field."""
    return finding.get("finding_class") or DEFAULT_FINDING_CLASS


def count_by_class(tests):
    """Tally findings per class across every test object."""
    counts = {CLASS_VULNERABILITY: 0, CLASS_POSTURE: 0}
    for test in tests:
        for finding in test.vulnerabilities_found:
            name = finding_class_of(finding)
            counts[name] = counts.get(name, 0) + 1
    return counts


def gated_finding_count(tests, fail_on=DEFAULT_FAIL_ON, only_identities=None,
                        identity_of=None):
    """Count only the findings the chosen --fail-on setting should gate on.

    ``only_identities`` narrows that further to a specific set - used by
    --fail-on-new to gate on regressions against a baseline rather than on the
    findings a team has already accepted.

    An unrecognised setting counts nothing rather than everything: failing a
    build on a typo would be the worse of the two mistakes.
    """
    wanted = FAIL_ON_CLASSES.get(fail_on, frozenset())
    if not wanted:
        return 0
    counted = 0
    for test in tests:
        for finding in test.vulnerabilities_found:
            if finding_class_of(finding) not in wanted:
                continue
            if only_identities is not None:
                if identity_of is None or identity_of(finding) not in only_identities:
                    continue
            counted += 1
    return counted
