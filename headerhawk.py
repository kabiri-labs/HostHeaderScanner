#!/usr/bin/env python3
"""Entry point for running HeaderHawk straight from a checkout.

The tool itself lives in the ``headerhawk`` package next to this file; this
script only forwards to it so ``python headerhawk.py <target>`` keeps working
exactly as before.
"""

import sys

from headerhawk.cli import main

if __name__ == "__main__":
    sys.exit(main())
