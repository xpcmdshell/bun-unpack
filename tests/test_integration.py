from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from bun_unpack.cli import main as bun_unpack_main


def _bun() -> str | None:
    return shutil.which("bun")


def _run(cmd: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd), check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _walk_files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file()]


def _read_textish(path: Path) -> str:
    # Bundled outputs may be extensionless (e.g. --outfile=sample).
    if path.stat().st_size > 5_000_000:
        return ""
    try:
        return path.read_bytes().decode("utf-8", errors="ignore")
    except Exception:
        return ""


class TestIntegration(unittest.TestCase):
    @unittest.skipIf(_bun() is None, "bun not installed")
    def test_can_extract_bundle_from_compiled_executable(self):
        bun = _bun()
        assert bun is not None

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)

            # Build a tiny Bun program with a dependency.
            (td_path / "dep.ts").write_text(
                "export function dep() { return 'DEP_MAGIC'; }\n",
                encoding="utf-8",
            )
            (td_path / "index.ts").write_text(
                "import { dep } from './dep';\n" "console.log('INDEX_MAGIC:' + dep());\n",
                encoding="utf-8",
            )

            outfile = td_path / "sample"

            # bun build --compile writes a native executable.
            _run([bun, "build", "--compile", "index.ts", "--outfile", str(outfile)], cwd=td_path)

            exe = outfile
            if not exe.exists() and os.name == "nt":
                exe = outfile.with_suffix(".exe")

            self.assertTrue(exe.exists(), f"compiled executable not found: {exe}")

            out_dir = td_path / "out"

            # Run our CLI entrypoint directly.
            code = bun_unpack_main([str(exe), "--bundle", "-o", str(out_dir)])
            self.assertEqual(code, 0)

            files = _walk_files(out_dir)
            combined = "\n".join(_read_textish(p) for p in files)

            self.assertIn("INDEX_MAGIC", combined)
            self.assertIn("DEP_MAGIC", combined)


if __name__ == "__main__":
    unittest.main()
