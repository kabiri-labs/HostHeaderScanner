"""Request accounting shared by every check."""

import threading

class RequestStats:
    """Thread-safe tally of issued HTTP requests and how many failed.

    Lets the scanner distinguish "no vulnerabilities" from "the target never
    answered" - a distinction that matters a great deal for a security tool,
    where a silently unreachable host must not read as a clean bill of health.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.total = 0
        self.failed = 0

    def record(self, ok):
        with self._lock:
            self.total += 1
            if not ok:
                self.failed += 1

    @property
    def succeeded(self):
        return self.total - self.failed

    @property
    def all_failed(self):
        """True when requests were attempted and every one of them failed."""
        return self.total > 0 and self.failed == self.total
