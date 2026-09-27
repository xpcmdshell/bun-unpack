"""Historical graph profiles and bounded executable container readers."""

from __future__ import annotations

import os
import platform
import struct
import tempfile
import unittest
from pathlib import Path

from bun_unpack._model import Limits
from bun_unpack.errors import BunUnpackError
from bun_unpack.formats import load_graph

FIXTURES = Path(os.environ.get("BUN_UNPACK_FIXTURES", "build/compatibility/fixtures"))
NATIVE_CONTAINER = {"Darwin": "macho", "Linux": "elf", "Windows": "pe"}[platform.system()]
EXECUTABLE = "sample.exe" if platform.system() == "Windows" else "sample"
CROSS = FIXTURES.parent / "cross"
RELEASES = (
    ("0.6.0", 32, 24),
    ("1.0.0", 32, 24),
    ("1.1.0", 32, 24),
    ("1.1.22", 28, 24),
    ("1.1.29", 28, 24),
    ("1.1.30", 36, 24),
    ("1.2.0", 36, 24),
    ("1.2.4", 36, 24),
    ("1.3.0", 36, 32),
    ("1.3.4", 36, 32),
    ("1.3.9", 52, 32),
    ("1.3.14", 52, 32),
    ("1.4.2", 52, 32),
)
CROSS_RELEASES = (
    ("1.1.22", "bun-windows-x64", "pe", 28, 24),
    ("1.1.22", "bun-linux-x64", "elf", 28, 24),
    ("1.4.2", "bun-windows-x64", "pe", 52, 32),
    ("1.4.2", "bun-linux-x64", "elf", 52, 32),
)


def _appended_elf(
    record: bytes,
    data: bytes,
    *,
    entry: int = 0,
    count: int | None = None,
    runtime_marker: bytes = b"",
) -> bytes:
    # Compact synthetic ELF envelope: the append reader needs only the ELF header.
    prefix = b"\x7fELF\x02\x01" + b"\x00" * 62 + runtime_marker
    table = data + record
    table_length = len(record) if count is None else count
    footer = struct.pack("<QIII", len(table), len(data), table_length, entry) + b"\0" * 4
    body = prefix + table + footer + b"\n---- Bun! ----\n"
    return body + struct.pack("<Q", len(body) + 8)


def _modern_elf(optional: bytes, flags: int) -> bytes:
    name = b"compiled://root/app.js\0"
    source = b"hello"
    record = struct.pack(
        "<IIIIIIIIIIII", 0, len(name), len(name), len(source), 0, 0, 0, 0, 0, 0, 0, 0
    ) + bytes([1, 1, 1, 0])
    graph = name + source + record + optional
    footer = struct.pack("<QIIIIII", len(graph), len(name) + len(source), 52, 0, 0, 0, flags)
    body = (
        b"\x7fELF\x02\x01"
        + b"\0" * 62
        + b"1.4.2+abcdef123"
        + graph
        + footer
        + b"\n---- Bun! ----\n"
    )
    return body + struct.pack("<Q", len(body) + 8)


class TestFormats(unittest.TestCase):
    def test_real_native_graphs(self) -> None:
        if not any(FIXTURES.glob(f"*/sources/{EXECUTABLE}")):
            self.skipTest("Generate local corpus with python -m tools.build_compatibility")
        for version, stride, footer in RELEASES:
            path = FIXTURES / version / "sources" / EXECUTABLE
            if not path.exists():
                continue
            with self.subTest(version=version):
                graph = load_graph(path, Limits())
                self.assertEqual(graph.format.container, NATIVE_CONTAINER)
                self.assertEqual(
                    (graph.format.record_size, graph.format.footer_size),
                    (stride, footer),
                )
                self.assertGreaterEqual(len(graph.modules), 1)
                self.assertEqual(sum(module.is_entry_point for module in graph.modules), 1)
                entry = next(module for module in graph.modules if module.is_entry_point)
                self.assertGreater(entry.contents.size, 0)
                self.assertTrue(entry.contents.read(100_000))

    def test_cross_container_graphs(self) -> None:
        if not any(CROSS.glob("*/*/sample*")):
            self.skipTest(
                "Cross-compiled executables not installed under build/compatibility/cross"
            )
        for version, target, container, stride, footer in CROSS_RELEASES:
            path = CROSS / version / target / ("sample.exe" if container == "pe" else "sample")
            if not path.exists():
                continue
            with self.subTest(version=version, target=target):
                graph = load_graph(path, Limits())
                self.assertEqual(
                    (
                        graph.format.container,
                        graph.format.record_size,
                        graph.format.footer_size,
                    ),
                    (container, stride, footer),
                )
                self.assertTrue(graph.modules[0].is_entry_point)
                self.assertGreater(graph.modules[0].contents.size, 0)

    def test_real_asset_modules(self) -> None:
        if not any(FIXTURES.glob(f"*/assets/{EXECUTABLE}")):
            self.skipTest("Assets fixtures not installed")
        for version, encoding in (
            ("0.6.0", "latin1"),
            ("1.1.22", "binary"),
            ("1.3.9", "binary"),
            ("1.4.2", "binary"),
        ):
            path = FIXTURES / version / "assets" / EXECUTABLE
            if not path.exists():
                continue
            with self.subTest(version=version):
                graph = load_graph(path, Limits())
                assets = [module for module in graph.modules if module.loader == "file"]
                self.assertTrue(assets)
                for asset in assets:
                    self.assertEqual(asset.encoding, encoding)
                    self.assertEqual(len(asset.contents.read(100_000)), asset.contents.size)
                self.assertTrue(any(asset.contents.size > 0 for asset in assets))

    def test_multi_module_graph_and_legacy_footer_padding(self) -> None:
        path = FIXTURES / "1.3.0" / "splitting" / EXECUTABLE
        if not path.exists():
            self.skipTest("Splitting fixture not installed")
        graph = load_graph(path, Limits())
        self.assertGreater(len(graph.modules), 1)
        self.assertEqual(sum(module.is_entry_point for module in graph.modules), 1)
        self.assertEqual(graph.format.footer_size, 32)

    def test_exec_argv_and_modern_bytecode_origin(self) -> None:
        argv_path = FIXTURES / "1.4.2" / "exec-argv" / EXECUTABLE
        bytecode_path = FIXTURES / "1.4.2" / "bytecode" / EXECUTABLE
        if not argv_path.exists() or not bytecode_path.exists():
            self.skipTest("Modern fixtures not installed")
        self.assertTrue(load_graph(argv_path, Limits()).exec_argv)
        module = load_graph(bytecode_path, Limits()).modules[0]
        self.assertIsNotNone(module.bytecode)
        self.assertIsNotNone(module.bytecode_origin_path)
        self.assertEqual(module.bytecode_origin_path, module.path)

    def test_legacy_nonzero_padding_and_embedded_nul(self) -> None:
        name = b"compiled://root/app.js\0"
        contents = b"a\0b"
        record = struct.pack("<IIIIII", 0, len(name), len(name), len(contents), 0, 0)
        record += bytes([1]) + b"\xaa" * 7
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sample"
            path.write_bytes(_appended_elf(record, name + contents))
            graph = load_graph(path, Limits())
            self.assertEqual(graph.format.record_size, 32)
            self.assertEqual(graph.modules[0].path, "compiled://root/app.js")
            self.assertEqual(graph.modules[0].contents.read(5), contents)
            self.assertEqual(graph.modules[0].side, "server")

    def test_28_byte_loader_enum_without_version_marker(self) -> None:
        name = b"compiled://root/config.toml\0"
        record = struct.pack("<IIIIII", 0, len(name), len(name), 4, 0, 0) + bytes([1, 7, 255, 255])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sample"
            path.write_bytes(_appended_elf(record, name + b"a=1\n"))
            graph = load_graph(path, Limits())
            self.assertEqual(graph.modules[0].loader, "toml")
            self.assertEqual(graph.format.record_size, 28)

    def test_zero_length_content_at_graph_end(self) -> None:
        name = b"compiled://root/empty.js\0"
        record = struct.pack("<IIIIII", 0, len(name), len(name) + 32, 0, 0, 0)
        record += bytes([1]) + b"\xaa" * 7
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sample"
            path.write_bytes(_appended_elf(record, name))
            module = load_graph(path, Limits()).modules[0]
            self.assertEqual(module.contents.size, 0)
            self.assertEqual(module.contents.read(1), b"")
            self.assertIsNone(module.sourcemap)

    def test_fat_macho_section_reader(self) -> None:
        name = b"compiled://root/main.js\0"
        record = struct.pack("<IIIIII", 0, len(name), len(name), 6, 0, 0)
        record += bytes([1]) + b"\0" * 7
        graph = _appended_elf(record, name + b"source")[68:-8]
        section_data = struct.pack("<Q", len(graph)) + graph
        header = bytearray(32)
        header[:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into("<II", header, 16, 1, 152)
        command = bytearray(152)
        struct.pack_into("<II", command, 0, 0x19, 152)
        command[8:13] = b"__BUN"
        struct.pack_into("<I", command, 64, 1)
        command[72:77] = b"__bun"
        command[88:93] = b"__BUN"
        struct.pack_into("<Q", command, 72 + 40, len(section_data))
        struct.pack_into("<I", command, 72 + 48, 184)
        thin = bytes(header) + bytes(command) + section_data
        fat = struct.pack(">4sI", b"\xca\xfe\xba\xbe", 1)
        fat += struct.pack(">IIIII", 0x0100000C, 0, 4096, len(thin), 12)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "universal"
            path.write_bytes(fat.ljust(4096, b"\0") + thin)
            result = load_graph(path, Limits())
            self.assertEqual(result.format.container, "macho")
            self.assertEqual(result.modules[0].contents.read(100), b"source")

    def test_36_byte_padding_needs_profile_evidence(self) -> None:
        name = b"compiled://root/app.js\0"
        record = struct.pack("<IIIIIIII", 0, len(name), len(name), 6, 0, 0, 0, 0)
        record += bytes([1, 1, 1, 1])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sample"
            path.write_bytes(_appended_elf(record, name + b"source"))
            with self.assertRaisesRegex(BunUnpackError, "Ambiguous module side"):
                load_graph(path, Limits())
            path.write_bytes(
                _appended_elf(record, name + b"source", runtime_marker=b"1.2.16+abcdef123")
            )
            self.assertEqual(load_graph(path, Limits()).modules[0].side, "server")
            path.write_bytes(
                _appended_elf(record, name + b"source", runtime_marker=b"1.2.17+abcdef123")
            )
            self.assertEqual(load_graph(path, Limits()).modules[0].side, "client")

            # The marker is outside the fast tail window. A bounded runtime-only
            # fallback scan must still resolve the side rather than reject it.
            marker = b"1.2.17+abcdef123"
            raw = _appended_elf(record, name + b"source", runtime_marker=marker)
            prefix_length = 68 + len(marker)
            with path.open("wb") as stream:
                stream.write(raw[:prefix_length])
                stream.seek(prefix_length + 17 * 1024 * 1024)
                stream.write(raw[prefix_length:-8])
                stream.write(struct.pack("<Q", stream.tell() + 8))
            self.assertEqual(load_graph(path, Limits()).modules[0].side, "client")

    def test_reject_malformed_graph(self) -> None:
        name = b"compiled://root/app.js\0"
        contents = b"hello"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sample"
            for defect in ("pointer", "count", "entry", "enum", "trailer"):
                with self.subTest(defect=defect):
                    record = bytearray(
                        struct.pack("<IIIIII", 0, len(name), len(name), len(contents), 0, 0)
                        + bytes([1])
                        + b"\0" * 7
                    )
                    if defect == "pointer":
                        struct.pack_into("<I", record, 8, 0xFFFFFFF0)
                    if defect == "enum":
                        record[24] = 255
                    raw = bytearray(
                        _appended_elf(
                            bytes(record),
                            name + contents,
                            entry=5 if defect == "entry" else 0,
                            count=31 if defect == "count" else None,
                        )
                    )
                    if defect == "trailer":
                        raw[-24] = 0
                    path.write_bytes(raw)
                    with self.assertRaises(BunUnpackError):
                        load_graph(path, Limits())

    def test_flagged_optional_records_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sample"
            # Source hash, builtin count, startup count, and two string-table pointers.
            flags = (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9)
            good = b"hash" + struct.pack("<I", 0) + struct.pack("<II", 0, 0)
            good += struct.pack("<I", 1) + struct.pack("<II", 0, 0)
            path.write_bytes(_modern_elf(good, flags))
            self.assertEqual(load_graph(path, Limits()).format.record_size, 52)
            for defect, optional in (
                ("missing hashes", b""),
                ("huge builtin count", b"hash" + struct.pack("<I", 0xFFFFFFFF)),
                (
                    "out-of-range bytecode string table",
                    b"hash"
                    + struct.pack("<I", 0)
                    + struct.pack("<II", 0xFFFFFFFF, 4)
                    + struct.pack("<I", 1)
                    + struct.pack("<II", 0, 0),
                ),
                (
                    "invalid startup count",
                    b"hash"
                    + struct.pack("<I", 0)
                    + struct.pack("<II", 0, 0)
                    + struct.pack("<I", 2)
                    + struct.pack("<II", 0, 0),
                ),
            ):
                with self.subTest(defect=defect):
                    path.write_bytes(_modern_elf(optional, flags))
                    with self.assertRaises(BunUnpackError):
                        load_graph(path, Limits())

            # 52-byte records always carry flags, even when a version marker is absent.
            raw = _modern_elf(good, flags | (1 << 31))
            path.write_bytes(raw.replace(b"1.4.2+abcdef123", b"_" * len(b"1.4.2+abcdef123"), 1))
            with self.assertRaisesRegex(BunUnpackError, "Unknown Bun graph flag bits"):
                load_graph(path, Limits())
            raw = _modern_elf(b"", flags)
            path.write_bytes(raw.replace(b"1.4.2+abcdef123", b"_" * len(b"1.4.2+abcdef123"), 1))
            with self.assertRaisesRegex(BunUnpackError, "Source hash table"):
                load_graph(path, Limits())


if __name__ == "__main__":
    unittest.main()
