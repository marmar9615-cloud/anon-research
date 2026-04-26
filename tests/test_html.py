"""Smoke tests for the HTML → text/markdown conversion in fetch."""
import unittest

import anon


SAMPLE_HTML = """
<html>
<head>
  <title>Page</title>
  <script>window.bad = function() { alert('xss') }</script>
  <style>body { color: red }</style>
</head>
<body>
<nav>top menu links</nav>
<h1>Heading One</h1>
<p>A paragraph with <strong>bold</strong> and <em>italic</em> text.</p>
<ul>
  <li>First item</li>
  <li>Second item</li>
</ul>
<a href="https://example.org">link text</a>
<footer>footer copyright</footer>
</body>
</html>
"""


class TestHtmlToText(unittest.TestCase):
    def setUp(self):
        self.text = anon._strip_to_text(SAMPLE_HTML)

    def test_drops_script_content(self):
        self.assertNotIn("alert('xss')", self.text)
        self.assertNotIn("window.bad", self.text)

    def test_drops_style_content(self):
        self.assertNotIn("color: red", self.text)

    def test_keeps_heading_text(self):
        self.assertIn("Heading One", self.text)

    def test_keeps_list_items(self):
        self.assertIn("First item", self.text)
        self.assertIn("Second item", self.text)


class TestHtmlToMarkdown(unittest.TestCase):
    def setUp(self):
        self.md = anon._to_markdown(SAMPLE_HTML)

    def test_h1_becomes_pound(self):
        self.assertIn("# Heading One", self.md)

    def test_strong_becomes_double_star(self):
        self.assertIn("**bold**", self.md)

    def test_em_becomes_single_star(self):
        self.assertIn("*italic*", self.md)

    def test_link_becomes_bracket_paren(self):
        self.assertIn("[link text](https://example.org)", self.md)

    def test_drops_nav(self):
        self.assertNotIn("top menu links", self.md)

    def test_drops_footer(self):
        self.assertNotIn("footer copyright", self.md)

    def test_drops_script(self):
        self.assertNotIn("window.bad", self.md)
        self.assertNotIn("alert", self.md)


if __name__ == "__main__":
    unittest.main()
