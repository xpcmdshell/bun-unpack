from __future__ import annotations

import unittest
from pathlib import Path

from bun_unpack.errors import UnsafePathError
from bun_unpack.paths import normalize_module_path, normalize_relative_path, safe_join


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

    def test_real_root_directory_is_not_a_virtual_prefix(self):
        self.assertEqual(normalize_relative_path("root/project/a.ts"), "root/project/a.ts")
        self.assertEqual(normalize_module_path("/$bunfs/root/root/a.ts"), "root/a.ts")

    def test_module_paths_cannot_escape_the_virtual_root(self):
        with self.assertRaises(UnsafePathError):
            normalize_module_path("/$bunfs/root/../outside.js")

    def test_safe_join_stays_within_base(self):
        base = Path("/tmp/out")
        out = safe_join(base, "a/b/c.txt")
        self.assertEqual(out.parts[-3:], ("a", "b", "c.txt"))
        self.assertTrue(out.is_relative_to(base))

    def test_safe_join_prevents_escape(self):
        base = Path("/tmp/out")
        with self.assertRaises(UnsafePathError):
            safe_join(base, "../../etc/passwd")


if __name__ == "__main__":
    unittest.main()
