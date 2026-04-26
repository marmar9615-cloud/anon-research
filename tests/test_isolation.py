"""Tests for SOCKS auth generation — the mechanism that gives each request its
own Tor circuit. If two calls produced the same auth, sites could correlate
those requests by exit IP."""
import re
import unittest

import anon


class TestSocksAuth(unittest.TestCase):
    PATTERN = re.compile(r"^[0-9a-f]{16}:x$")

    def test_format_matches_hex16_colon_x(self):
        for _ in range(50):
            auth = anon._fresh_socks_auth()
            self.assertRegex(auth, self.PATTERN, f"unexpected format: {auth!r}")

    def test_unique_across_many_calls(self):
        seen = set()
        n = 1000
        for _ in range(n):
            seen.add(anon._fresh_socks_auth())
        # 1000 calls of a 64-bit token should all be unique with overwhelming
        # probability. Any collision would indicate a real bug.
        self.assertEqual(len(seen), n,
                         "duplicate SOCKS auth detected in {} calls".format(n))


if __name__ == "__main__":
    unittest.main()
