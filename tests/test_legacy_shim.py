"""The deprecated ``host_header_scanner`` shim must keep re-exporting HeaderHawk.

External users may still run ``python host_header_scanner.py`` or
``import host_header_scanner``; the shim is the backward-compatibility contract
that keeps those working after the rename to HeaderHawk.
"""

import unittest

import headerhawk
import host_header_scanner as legacy


class LegacyShimTests(unittest.TestCase):
    def test_entry_point_is_shared(self):
        self.assertIs(legacy.main, headerhawk.main)

    def test_metadata_matches_headerhawk(self):
        self.assertEqual(legacy.__version__, headerhawk.__version__)
        self.assertEqual(legacy.__tool_name__, headerhawk.__tool_name__)
        self.assertEqual(legacy.__github_url__, headerhawk.__github_url__)
        self.assertEqual(legacy.__tool_name__, "HeaderHawk")

    def test_public_api_is_re_exported(self):
        for name in ("SSRFTest", "HostInjectionTest", "build_sarif", "scan_target"):
            self.assertIs(getattr(legacy, name), getattr(headerhawk, name))


if __name__ == "__main__":
    unittest.main()
