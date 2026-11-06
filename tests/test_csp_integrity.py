"""Regression gate for the self-contained Cube experience's static CSP.

This proves exact content hashes match current inline assets; it does not
prove lawful distribution, origin policy enforcement, or real browser UX.
"""
import base64
import hashlib
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "index.html"


class StaticCSPIntegrity(unittest.TestCase):
    def test_only_one_first_party_style_and_script_with_matching_hashes(self):
        text = HTML.read_text(encoding="utf-8")
        match = re.search(
            r'<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"\s*/?>',
            text, flags=re.I
        )
        self.assertIsNotNone(match, "Missing static content security policy")
        policy = match.group(1)
        self.assertNotIn("'unsafe-inline'", policy)
        self.assertNotIn("'unsafe-eval'", policy)
        self.assertIn("connect-src 'none'", policy)
        self.assertIn("object-src 'none'", policy)
        self.assertIn("form-action 'none'", policy)
        for tag, directive in (("style", "style-src"), ("script", "script-src")):
            blocks = re.findall(
                rf"<{tag}>(.*?)</{tag}>", text, flags=re.S | re.I
            )
            self.assertEqual(len(blocks), 1, f"Expected one local {tag} block")
            digest = base64.b64encode(
                hashlib.sha256(blocks[0].encode("utf-8")).digest()
            ).decode("ascii")
            self.assertIn(f"{directive} 'sha256-{digest}'", policy)
        self.assertNotRegex(text, r"(?i)<script\b[^>]+src\s*=")
        self.assertNotRegex(text, r"(?i)<link\b[^>]+(?:href|rel)\s*=.*stylesheet")
        self.assertNotRegex(text, r"(?i)\s+on(?:click|load|error|change|submit)\s*=")
        self.assertNotRegex(text, r"(?i)\sstyle\s*=")


if __name__ == "__main__":
    unittest.main()
