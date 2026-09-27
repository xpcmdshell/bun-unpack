from __future__ import annotations

import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from tools.bun import isolated_environment, portable_bun, require_flags, sha256


class TestFixtureTools(unittest.TestCase):
    def test_historical_flag_declarations_and_values(self):
        for declaration in ("--sourcemap <STR>?", "--sourcemap=<val>", "--sourcemap"):
            with self.subTest(declaration=declaration):
                require_flags(f"  {declaration}\n", ("--sourcemap=external",))
        with self.assertRaisesRegex(ValueError, "--bytecode"):
            require_flags("  --bytecode-depth=<val>", ("--bytecode",))

    def test_environment_is_contained_without_mutating_process_environment(self):
        before = dict(os.environ)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = isolated_environment(root)
            for key in ("HOME", "BUN_INSTALL", "BUN_INSTALL_CACHE_DIR", "TMPDIR"):
                self.assertTrue(Path(environment[key]).is_relative_to(root))
            self.assertEqual(dict(os.environ), before)

    def test_imports_a_portable_compiler_without_downloading(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "imported/1.4.2/bun"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"portable compiler")
            with (
                patch("tools.bun.platform.system", return_value="Darwin"),
                patch("tools.bun.platform.machine", return_value="arm64"),
                patch("tools.bun.urllib.request.urlopen") as download,
            ):
                result = portable_bun("1.4.2", root / "workspace", root / "imported")
                again = portable_bun("1.4.2", root / "workspace")
            download.assert_not_called()
            self.assertEqual(result, again)
            self.assertEqual(sha256(source), sha256(result))

    def test_failed_download_does_not_publish_a_partial_compiler(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                patch("tools.bun.platform.system", return_value="Darwin"),
                patch("tools.bun.platform.machine", return_value="arm64"),
                patch("tools.bun.urllib.request.urlopen", return_value=io.BytesIO(b"not a zip")),
                self.assertRaises(zipfile.BadZipFile),
            ):
                portable_bun("1.4.2", root)
            self.assertFalse((root / "runtimes/1.4.2/bun").exists())
            self.assertEqual(list((root / "temporary").iterdir()), [])

    def test_version_cannot_escape_the_workspace(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(ValueError):
                portable_bun("../../escape", root)
            self.assertEqual(list(root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
