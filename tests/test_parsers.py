"""Tests for the DDG result parser and the block-detection heuristics.

The parser is the single most fragile part of the search path: if DDG changes
their HTML, we'd silently return empty results. The block-detection heuristics
gate the fail-closed behaviour, so wrong answers there have a privacy impact.
"""
import os
import unittest

import anon


FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class TestDDGParser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(FIXTURES, "ddg_sample.html")) as f:
            cls.html = f.read()
        cls.results = anon._parse_ddg(cls.html)

    def test_parses_three_results(self):
        self.assertEqual(len(self.results), 3)

    def test_first_result_fields(self):
        r = self.results[0]
        self.assertEqual(r["title"], "First Result Title")
        self.assertEqual(r["url"], "https://example.org/one")
        self.assertIn("First snippet", r["snippet"])

    def test_unwraps_ddg_redirect(self):
        for r in self.results:
            self.assertNotIn(
                "duckduckgo.com/l/", r["url"],
                f"URL not unwrapped: {r['url']}",
            )

    def test_decodes_html_entities_in_title(self):
        # Third result has "Third &amp; Final" — should decode to "Third & Final"
        self.assertEqual(self.results[2]["title"], "Third & Final Result")

    def test_handles_div_snippet_variant(self):
        # Second result uses <div class="result__snippet">, not <a class=…>
        self.assertIn("Second snippet", self.results[1]["snippet"])

    def test_strips_inline_tags_from_snippet(self):
        # Third snippet has <b>bold</b> — should be plain text
        self.assertNotIn("<b>", self.results[2]["snippet"])
        self.assertIn("bold", self.results[2]["snippet"])


class TestBlockDetection(unittest.TestCase):
    def test_403_blocked(self):
        self.assertEqual(anon._detect_block(403, {}, b""), "HTTP 403")

    def test_429_blocked(self):
        self.assertEqual(anon._detect_block(429, {}, b""), "HTTP 429")

    def test_451_blocked(self):
        self.assertEqual(anon._detect_block(451, {}, b""), "HTTP 451")

    def test_401_blocked(self):
        self.assertEqual(anon._detect_block(401, {}, b""), "HTTP 401")

    def test_cloudflare_503_with_marker(self):
        body = b"<html><title>Just a moment</title>cf-browser-verification</html>"
        self.assertIsNotNone(anon._detect_block(503, {"server": "cloudflare"}, body))

    def test_cloudflare_200_with_challenge_body(self):
        body = b"<html>Just a moment, please...</html>"
        self.assertIsNotNone(anon._detect_block(200, {"server": "cloudflare"}, body))

    def test_attention_required_cloudflare_in_body(self):
        body = b"<title>Attention Required! | Cloudflare</title>"
        self.assertIsNotNone(anon._detect_block(200, {}, body))

    def test_access_denied_body_marker(self):
        body = b"<html><body>Access Denied</body></html>"
        self.assertIsNotNone(anon._detect_block(200, {}, body))

    def test_clean_200_not_blocked(self):
        body = b"<html><body><h1>Welcome to a normal page</h1></body></html>"
        self.assertIsNone(anon._detect_block(200, {"server": "nginx"}, body))

    def test_404_not_treated_as_block(self):
        # 404 means "not found", not "blocked" — should NOT match block detection
        self.assertIsNone(anon._detect_block(404, {}, b"<h1>Not Found</h1>"))


if __name__ == "__main__":
    unittest.main()
