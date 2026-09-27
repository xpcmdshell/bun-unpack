from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import zstandard

from bun_unpack import BunUnpacker, BunUnpackError, Limits, UnsafePathError
from bun_unpack._model import Blob, FormatInfo, ModuleGraph, ModuleRecord


def source_unpacker(
    root: Path,
    sources: list[str],
    contents: list[str | None],
    *,
    source_root: str = "",
    limits: Limits | None = None,
) -> BunUnpacker:
    bundle = b'console.log("BUNDLE_MAGIC");'
    source_map = zstandard.ZstdCompressor().compress(
        json.dumps(
            {
                "version": 3,
                "sources": sources,
                "sourcesContent": contents,
                "sourceRoot": source_root,
                "mappings": "",
                "names": [],
            }
        ).encode("utf-8")
    )
    binary = root / "executable"
    binary.write_bytes(bundle + source_map)
    module = ModuleRecord(
        "compiled://root/app",
        Blob(binary, 0, len(bundle)),
        Blob(binary, len(bundle), len(source_map)),
        None,
        "utf8",
        "js",
        "esm",
        "server",
        True,
    )
    graph = ModuleGraph((module,), FormatInfo("macho", 32, 24, "1.0.0"))
    with patch("bun_unpack.api.load_graph", return_value=graph):
        return BunUnpacker(binary, limits=limits)


class TestRecoverySafety(unittest.TestCase):
    def test_source_root_and_empty_sources_are_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unpacker = source_unpacker(
                root, ["src/empty.ts", "src/unicode.ts"], ["", "日本語\r\n"], source_root="project"
            )
            result = unpacker.unpack(root / "output")
            self.assertEqual((root / "output/project/src/empty.ts").read_bytes(), b"")
            self.assertEqual(
                (root / "output/project/src/unicode.ts").read_bytes(), "日本語\r\n".encode()
            )
            self.assertEqual(result.source_count, 2)
            self.assertEqual(result.bundle_count, 1)
            self.assertEqual(
                (root / "output/_bundles/app").read_bytes(), b'console.log("BUNDLE_MAGIC");'
            )

    def test_unavailable_content_is_reported_with_bundle_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = source_unpacker(root, ["missing.ts"], [None]).unpack(root / "output")
            self.assertEqual(result.source_count, 0)
            self.assertEqual(result.bundle_count, 1)
            self.assertIn("No sourcesContent for missing.ts", result.warnings[0])

    def test_identical_sources_are_deduplicated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = source_unpacker(root, ["a.ts", "a.ts"], ["same", "same"]).unpack(
                root / "output"
            )
            self.assertEqual(result.source_count, 1)

    def test_conflicting_sources_leave_no_partial_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unpacker = source_unpacker(root, ["a.ts", "a.ts"], ["first", "different"])
            with self.assertRaisesRegex(BunUnpackError, "Conflicting"):
                unpacker.unpack(root / "output")
            self.assertFalse((root / "output").exists())

    def test_unsafe_paths_leave_no_partial_output(self):
        for path in ("../..", "null\x00.ts", "http://[invalid/a.ts", "file:///null%00.ts"):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                unpacker = source_unpacker(root, ["good.ts", path], ["good", "bad"])
                with self.assertRaises(UnsafePathError):
                    unpacker.unpack(root / "output")
                self.assertFalse((root / "output").exists())

    def test_parent_source_references_never_escape_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = source_unpacker(root, ["../../packages/lib/a.ts"], ["original"]).unpack(
                root / "output"
            )
            self.assertEqual(result.source_count, 1)
            self.assertEqual((root / "output/packages/lib/a.ts").read_bytes(), b"original")
            self.assertFalse((root / "packages").exists())

    def test_different_source_roots_do_not_collapse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = source_unpacker(root, ["../a.ts", "a.ts"], ["outer", "inner"]).unpack(
                root / "output"
            )
            sources = [file for file in result.files if file.kind == "source"]
            self.assertEqual(len(sources), 2)
            self.assertEqual({file.path.read_bytes() for file in sources}, {b"outer", b"inner"})
            self.assertEqual(len({file.path for file in sources}), 2)
            self.assertTrue(all(file.relative_path.parts[0] == "_source_roots" for file in sources))
            self.assertTrue(result.warnings)

    def test_existing_different_file_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir()
            (output / "b.ts").write_bytes(b"user data")
            unpacker = source_unpacker(root, ["a.ts", "b.ts"], ["new", "different"])
            with self.assertRaisesRegex(BunUnpackError, "overwrite"):
                unpacker.unpack(output)
            self.assertEqual((output / "b.ts").read_bytes(), b"user data")
            self.assertFalse((output / "a.ts").exists())
            self.assertFalse((output / "_bundles").exists())

    def test_parent_file_conflict_is_detected_before_publishing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir()
            (output / "src").write_bytes(b"not a directory")
            unpacker = source_unpacker(root, ["a.ts", "src/b.ts"], ["a", "b"])
            with self.assertRaises(BunUnpackError):
                unpacker.unpack(output)
            self.assertFalse((output / "a.ts").exists())
            self.assertFalse((output / "_bundles").exists())
            self.assertEqual((output / "src").read_bytes(), b"not a directory")

    def test_symlinks_cannot_redirect_extraction_outside_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, outside = root / "output", root / "outside"
            output.mkdir()
            outside.mkdir()
            try:
                (output / "src").symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("Symlink creation not permitted on this host")
            unpacker = source_unpacker(root, ["src/a.ts"], ["data"])
            with self.assertRaises(UnsafePathError):
                unpacker.unpack(output)
            self.assertFalse((outside / "a.ts").exists())

    def test_dry_run_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = source_unpacker(root, ["a.ts"], ["content"]).unpack(
                root / "absent/output", dry_run=True
            )
            self.assertTrue(result.dry_run)
            self.assertEqual(result.source_count, 1)
            self.assertFalse((root / "absent").exists())

    def test_changed_executable_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unpacker = source_unpacker(root, ["a.ts"], ["content"])
            with unpacker.executable.open("ab") as stream:
                stream.write(b"changed")
            with self.assertRaisesRegex(BunUnpackError, "changed"):
                unpacker.unpack(root / "output")
            self.assertFalse((root / "output").exists())

    def test_limits_fail_before_publishing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unpacker = source_unpacker(root, ["a.ts"], ["x" * 100], limits=Limits(max_file_bytes=8))
            with self.assertRaises(BunUnpackError):
                unpacker.unpack(root / "output")
            self.assertFalse((root / "output").exists())

    def test_text_encodings_restore_what_was_packed(self):
        text = 'console.log("café 日本語");'
        packed = text.encode("utf-8")
        cases = (
            ("latin1", packed, packed),  # Latin-1-labelled bytes are already the file
            ("binary", packed, packed),  # opaque bytes are already the file
            ("utf16", text.encode("utf-16-le"), packed),  # only this is a JS string form
        )
        for encoding, embedded, expected in cases:
            with self.subTest(encoding=encoding), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                binary = root / "binary"
                binary.write_bytes(embedded)
                module = ModuleRecord(
                    "/$bunfs/root/app",
                    Blob(binary, 0, len(embedded)),
                    None,
                    None,
                    encoding,
                    "text",
                    "none",
                    "server",
                    True,
                )
                graph = ModuleGraph((module,), FormatInfo("macho", 52, 32))
                with patch("bun_unpack.api.load_graph", return_value=graph):
                    unpacker = BunUnpacker(binary)
                result = unpacker.unpack(root / "output", mode="bundle")
                self.assertEqual((root / "output/app").read_bytes(), expected)
                self.assertEqual(len(result.files), 1)

    def test_latin1_labelled_utf8_is_never_transcoded(self):
        # Regression: decoding these as Latin-1 and re-encoding produced mojibake
        # (caf\u00e9 became caf\u00c3\u00a9).
        embedded = b'console.log("caf\xc3\xa9");'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "binary"
            binary.write_bytes(embedded)
            module = ModuleRecord(
                "/$bunfs/root/app",
                Blob(binary, 0, len(embedded)),
                None,
                None,
                "latin1",
                "js",
                "esm",
                "server",
                True,
            )
            graph = ModuleGraph((module,), FormatInfo("macho", 52, 32))
            with patch("bun_unpack.api.load_graph", return_value=graph):
                unpacker = BunUnpacker(binary)
            unpacker.unpack(root / "output", mode="bundle")
            self.assertEqual((root / "output/app").read_bytes(), embedded)
            self.assertIn("café", (root / "output/app").read_text(encoding="utf-8"))

    def test_bytecode_without_a_sourcemap_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "binary"
            code, bytecode = b'console.log("ok");', b"\xffBYTECODE\x00"
            binary.write_bytes(code + bytecode)
            module = ModuleRecord(
                "/$bunfs/root/app",
                Blob(binary, 0, len(code)),
                None,
                Blob(binary, len(code), len(bytecode)),
                "utf8",
                "js",
                "cjs",
                "server",
                True,
            )
            graph = ModuleGraph((module,), FormatInfo("macho", 52, 32))
            with patch("bun_unpack.api.load_graph", return_value=graph):
                unpacker = BunUnpacker(binary)
            unpacker.unpack(root / "output", mode="bundle")
            self.assertEqual((root / "output/app.bytecode").read_bytes(), bytecode)

    def test_binary_assets_keep_empty_contents_and_trailing_nuls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "binary"
            original = b"\xffPNG\x00\x00\x00"
            binary.write_bytes(original)
            modules = tuple(
                ModuleRecord(
                    f"/$bunfs/root/{name}",
                    Blob(binary, 0, size),
                    None,
                    None,
                    "binary",
                    "file",
                    "none",
                    "server",
                    index == 0,
                )
                for index, (name, size) in enumerate(
                    (("data.bin", len(original)), ("empty.bin", 0))
                )
            )
            graph = ModuleGraph(modules, FormatInfo("macho", 52, 32))
            with patch("bun_unpack.api.load_graph", return_value=graph):
                unpacker = BunUnpacker(binary)
            result = unpacker.unpack(root / "output")
            self.assertEqual(result.asset_count, 2)
            self.assertEqual((root / "output/data.bin").read_bytes(), original)
            self.assertEqual((root / "output/empty.bin").read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
