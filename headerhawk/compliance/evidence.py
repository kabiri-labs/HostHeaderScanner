"""Turning a scan into per-control evidence.

A findings report answers "what did you break?". An assessor asks the other
question: "for each requirement, did this product meet it, and how do you know?"
This module answers that one.

The distinction that makes the answer worth anything is between a control that
was assessed and found clean, and one that was never assessed at all. A scan of
an unreachable host produces no findings; reporting that as full compliance
would be worse than producing no report. So a control is only ``Pass`` when a
check that covers it actually completed, and otherwise says why not.
"""

from collections import namedtuple
from datetime import datetime, timezone

from .catalogue import CONTROLS, describe
from .mapping import controls_for

STATUS_FAIL = "Fail"
STATUS_PASS = "Pass"
STATUS_NOT_ASSESSED = "Not assessed"

# Ordered worst-first, which is how the summary and the detail are sorted.
STATUS_ORDER = [STATUS_FAIL, STATUS_NOT_ASSESSED, STATUS_PASS]

ControlResult = namedtuple(
    "ControlResult", "control status findings assessed_by not_assessed_because")


def controls_covered_by(check):
    """The catalogued controls a check (class or instance) can speak to."""
    emitted = check.emitted_types() if hasattr(check, "emitted_types") else ()
    covered = set()
    for test_type in emitted:
        covered.update(controls_for(test_type))
    return covered


def build_evidence(tests, targets, stats=None, version=None, tool_name=None):
    """Build the per-control evidence for one scan.

    ``tests`` are the check instances that ran, in any order. Every catalogued
    control appears in the result, including ones this scan cannot speak to -
    an assessor needs to see the gaps, not just the answers.
    """
    findings_by_control = {}
    assessed_by = {}
    blocked_by = {}

    for test in tests:
        covered = controls_covered_by(test)
        if not covered:
            continue
        name = getattr(test, "test_type", type(test).__name__)
        if getattr(test, "assessed", False):
            for control_id in covered:
                assessed_by.setdefault(control_id, set()).add(name)
        else:
            reason = getattr(test, "skip_reason", None) or "the check did not run"
            for control_id in covered:
                blocked_by.setdefault(control_id, {})[name] = reason
        for finding in getattr(test, "vulnerabilities_found", []):
            for control_id in finding.get("controls") or ():
                findings_by_control.setdefault(control_id, []).append(finding)

    results = []
    for control_id in sorted(CONTROLS):
        findings = findings_by_control.get(control_id, [])
        assessors = sorted(assessed_by.get(control_id, ()))
        blocked = blocked_by.get(control_id, {})
        if findings:
            # Evidence of a failure stands on its own; it does not matter
            # whether some other check covering the same control was blocked.
            status = STATUS_FAIL
        elif assessors:
            status = STATUS_PASS
        else:
            status = STATUS_NOT_ASSESSED
        results.append(ControlResult(
            control=CONTROLS[control_id],
            status=status,
            findings=findings,
            assessed_by=assessors,
            not_assessed_because=(sorted(f"{name}: {reason}"
                                         for name, reason in blocked.items())
                                  if status == STATUS_NOT_ASSESSED else []),
        ))

    counts = {status: 0 for status in STATUS_ORDER}
    for result in results:
        counts[result.status] += 1

    return {
        "tool": tool_name,
        "version": version,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "targets": list(targets),
        "requests": ({"total": stats.total, "succeeded": stats.succeeded,
                      "failed": stats.failed} if stats is not None else None),
        "counts": counts,
        "controls": results,
    }


def unmapped_findings(tests):
    """Findings whose type maps to no catalogued control.

    Reported alongside the evidence so nothing the scan found is silently left
    out of it just because there is no requirement to hang it on.
    """
    orphans = []
    for test in tests:
        for finding in getattr(test, "vulnerabilities_found", []):
            control_ids = finding.get("controls")
            if control_ids is None:
                control_ids = controls_for(finding.get("test_type", ""))
            if not control_ids or not any(describe(c) for c in control_ids):
                orphans.append(finding)
    return orphans
