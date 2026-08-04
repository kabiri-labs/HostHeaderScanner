"""Process exit codes and the scan-outcome mapping."""

# Process exit codes, chosen so CI pipelines can gate on the outcome:
#   0 -> scan completed and nothing was found (safe to proceed)
#   1 -> scan completed and at least one finding was reported (fail the build)
#   2 -> the scan could not run meaningfully (bad input or unreachable target)
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

def determine_exit_code(total_findings, stats):
    """Map the scan outcome onto a process exit code (see EXIT_* constants)."""
    if stats is not None and stats.all_failed:
        return EXIT_ERROR
    return EXIT_FINDINGS if total_findings > 0 else EXIT_OK
