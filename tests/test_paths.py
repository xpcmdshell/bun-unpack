from __future__ import annotations

import unittest
from pathlib import Path

from bun_unpack.errors import UnsafePathError
from bun_unpack.paths import normalize_relative_path, safe_join


class TestPaths(unittest.TestCase):
    def test_normalize_relative_path_strips_scheme(self):
        self.assertEqual(
            normalize_relative_path("file:///Users/me/project/index.ts"),
            "Users/me/project/index.ts",
        )

    def test_normalize_relative_path_drops_dot_segments(self):
        self.assertEqual(normalize_relative_path("a/./b/../c.ts"), "a/c.ts")

    def test_normalize_relative_path_rejects_empty(self):
        with self.assertRaises(UnsafePathError):
            normalize_relative_path("")

    def test_safe_join_stays_within_base(self):
        base = Path("/tmp/out")
        out = safe_join(base, "a/b/c.txt")
        self.assertTrue(str(out).endswith("/tmp/out/a/b/c.txt"))

    def test_safe_join_prevents_escape(self):
        base = Path("/tmp/out")
        with self.assertRaises(UnsafePathError):
            safe_join(base, "../../etc/passwd")


if __name__ == "__main__":
    unittest.main()
