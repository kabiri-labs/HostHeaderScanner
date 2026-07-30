#!/usr/bin/env python3
"""Deprecated entry point - HostHeaderScanner was renamed to HeaderHawk.

The tool now covers the whole family of HTTP request headers (not just ``Host``),
so it lives in :mod:`headerhawk`. This shim keeps ``python host_header_scanner.py``
and ``import host_header_scanner`` working for existing users and will be removed
in a future release. Please switch to ``headerhawk``.
"""

# Re-export the public API so ``import host_header_scanner`` keeps working.
from headerhawk import *  # noqa: F401,F403
from headerhawk import (  # noqa: F401  explicit names that ``*`` does not pull in
    __github_url__,
    __tool_name__,
    __version__,
    main,
)

if __name__ == "__main__":
    main()
