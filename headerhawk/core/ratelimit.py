"""Global request pacing."""

import threading
import time

class RateLimiter:
    """Global, thread-safe request pacer to stay under a rate cap.

    A single instance is shared by every worker (and the raw HTTP client), so
    the whole scan emits at most ``rate`` requests per second regardless of the
    thread count - gentle enough to avoid tripping a WAF or rate-based blocking.
    A rate of 0 (or less) disables pacing entirely.
    """

    def __init__(self, rate):
        self.min_interval = 1.0 / rate if rate and rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next_time = 0.0

    def acquire(self):
        """Block just long enough that requests stay spaced by ``min_interval``."""
        if self.min_interval <= 0:
            return
        # Reserve this request's slot under the lock, then sleep outside it so
        # other threads can reserve their (later) slots without serialising.
        with self._lock:
            now = time.monotonic()
            scheduled = max(now, self._next_time)
            self._next_time = scheduled + self.min_interval
            wait = scheduled - now
        if wait > 0:
            time.sleep(wait)
