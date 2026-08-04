"""Console output: quiet-mode handling, status chatter and the run summary."""

from colorama import Fore, Style

# Suppresses progress/status chatter (set from --quiet / non-TTY detection).
# Findings and the final summary are never suppressed - only the noise around
# them - so piping the tool into a log stays useful.
_QUIET = False


def status(*args, **kwargs):
    """Print progress/status output unless the scan is running in quiet mode."""
    if not _QUIET:
        print(*args, **kwargs)


def resolve_quiet(quiet_flag, stdout_isatty):
    """Quiet mode is on when explicitly requested or when stdout is not a TTY."""
    return bool(quiet_flag or not stdout_isatty)


def set_quiet(value):
    """Set the process-wide quiet mode.

    The flag lives here rather than in the CLI so that ``status`` reads the same
    object the CLI writes; callers in other modules must not rebind their own
    copy of it.
    """
    global _QUIET
    _QUIET = bool(value)


def is_quiet():
    """Return the current quiet-mode setting."""
    return _QUIET


def print_summary(all_tests, targets, stats):
    """Print the aggregate summary and return the total finding count."""
    total_vulns = sum(len(test.vulnerabilities_found) for test in all_tests)
    scanned = len({test.target_url for test in all_tests})
    print(Fore.CYAN + Style.BRIGHT + "\n========== Test Summary ==========")
    print(Fore.CYAN + f"Targets scanned: {scanned}/{len(targets)}")
    print(Fore.CYAN + f"Requests: {stats.succeeded}/{stats.total} succeeded "
          f"({stats.failed} failed).")
    print(Fore.CYAN + f"Total findings: {total_vulns}")

    by_type = {}
    for test in all_tests:
        for vuln in test.vulnerabilities_found:
            by_type.setdefault(test.test_type, []).append(vuln)
    for test_type, vulns in by_type.items():
        print(Fore.MAGENTA + Style.BRIGHT + f"\n--- {test_type} ---")
        for vuln in vulns:
            print(Fore.RED + f"- [{vuln.get('severity', '')}] "
                  f"{vuln['method']} {vuln['url']}")
            print(f"  Header/Parameter: {vuln.get('header_name') or vuln.get('param_name')}")
            print(f"  Payload: {vuln['payload']}")
            print(Fore.YELLOW + f"  Analysis: {vuln['analysis']}")
            print(Fore.RED + "-" * 80)

    # An unreachable target must not be reported as a clean result: every issued
    # request failing means the findings list is empty for the wrong reason.
    if stats.all_failed:
        print(Fore.RED + Style.BRIGHT +
              "\n[!] Every request failed - the target(s) appear unreachable. "
              "Results are inconclusive, not a clean bill of health.")
    elif total_vulns == 0:
        print(Fore.GREEN + "No vulnerabilities were found.")
    print(Fore.CYAN + "=" * 35)
    return total_vulns
