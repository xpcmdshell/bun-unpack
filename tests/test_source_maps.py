"""Source-map codecs and byte-preserving recovery, runnable by unittest CI."""

from __future__ import annotations

import io
import json
import struct
import unittest

import zstandard as zstd

from bun_unpack._model import Limits
from bun_unpack.errors import BunUnpackError
from bun_unpack.source_maps import read_source_map, read_source_paths


def compact(names: list[str], contents: list[bytes], mapping: bytes) -> bytes:
    assert len(names) == len(contents)
    body = bytearray(struct.pack("<II", len(names), len(mapping)))
    body.extend(bytes(16 * len(names)))
    body.extend(mapping)
    for table, values in (
        (8, [name.encode() for name in names]),
        (8 + 8 * len(names), contents),
    ):
        for index, value in enumerate(values):
            offset = len(body)
            body.extend(value)
            struct.pack_into("<II", body, table + index * 8, offset, len(value))
    return bytes(body)


def binary_map() -> bytes:
    # Two mappings: (0,0,0,0,0), (0,5,0,0,5). A bit-packed window.
    window = bytearray(32)
    window[0] = 2
    window[16] = 1  # original line equals generated line
    window[24] = 1  # original column equals generated column
    struct.pack_into("<H", window, 2, 1)
    window += b"\x0a"  # zigzag varint +5
    sync = struct.pack("<iiIiii", 0, 0, 0, 0, 0, 0)
    total = 32 + len(sync) + len(window) + 1
    return struct.pack("<QQQII", total, 2, 1, 1, 56) + sync + window + b"\x00"


def legacy(document: dict[str, object]) -> bytes:
    return zstd.ZstdCompressor().compress(json.dumps(document).encode())


class TestSourceMaps(unittest.TestCase):
    def test_compact_ascii_and_exact_content(self) -> None:
        data = compact(
            ["src/a.ts", "empty.ts"],
            [
                zstd.ZstdCompressor().compress(b"\xff\x00"),
                zstd.ZstdCompressor().compress(b""),
            ],
            b"AAAA",
        )
        parsed = read_source_map(data, Limits(), include_mappings=True)
        self.assertEqual(
            [(source.path, source.content) for source in parsed.sources],
            [("src/a.ts", b"\xff\x00"), ("empty.ts", b"")],
        )
        self.assertEqual(parsed.mappings, "AAAA")
        self.assertEqual(parsed.to_dict()["sourcesContent"], [None, ""])

    def test_compact_windows_paths_and_crlf_are_preserved(self) -> None:
        path = r"src\unicode.ts"
        content = "// café / 日本語 / 🐇\r\nexport const value = 1;\r\n"
        data = compact(
            [path], [zstd.ZstdCompressor().compress(content.encode("utf-8"))], b"AAAA"
        )
        parsed = read_source_map(data, Limits(), include_mappings=True)
        self.assertEqual(parsed.sources[0].path, path)
        self.assertEqual(parsed.sources[0].content, content.encode("utf-8"))
        self.assertEqual(parsed.to_dict()["sources"], [path])
        self.assertEqual(parsed.to_dict()["sourcesContent"], [content])

    def test_legacy_zstd_metadata_and_null(self) -> None:
        original = {
            "version": 3,
            "sources": ["a.ts", "b.ts"],
            "sourcesContent": ["", None],
            "sourceRoot": "/src/",
            "names": ["hi"],
            "mappings": "AAAA",
            "debugId": "real-debug-id",
            "file": "bundle.js",
            "x_custom": {"nested": [1, "data"]},
        }
        data = legacy(original)
        parsed = read_source_map(data, Limits(), include_mappings=True)
        self.assertEqual(parsed.sources[0].content, b"")
        self.assertIsNone(parsed.sources[1].content)
        self.assertEqual(parsed.to_dict(), original)
        self.assertEqual(
            parsed.metadata,
            {
                "debugId": "real-debug-id",
                "file": "bundle.js",
                "x_custom": {"nested": [1, "data"]},
            },
        )
        self.assertIsNone(read_source_map(data, Limits()).mappings)
        parsed.metadata["sources"] = ["not-the-real-sources"]
        self.assertEqual(parsed.to_dict()["sources"], ["a.ts", "b.ts"])

    def test_legacy_binary_content_is_lossless(self) -> None:
        png = bytes.fromhex("89504e470d0a1a0aff00")
        escaped = json.dumps(png.decode("latin1"), ensure_ascii=False).encode("latin1")
        raw = (
            b'{"version":3,"sources":["logo.png"],"sourcesContent":['
            + escaped
            + b'],"names":[],"mappings":"AAAA"}'
        )
        parsed = read_source_map(
            zstd.ZstdCompressor().compress(raw), Limits(), include_mappings=True
        )
        self.assertEqual(parsed.sources[0].content, png)
        self.assertEqual(parsed.to_dict()["sourcesContent"], [None])

    def test_legacy_js_escape_and_raw_mapping_control(self) -> None:
        # Old Bun emitted JS-only \\v and raw non-UTF-8 asset bytes.
        raw = (
            b'{"version":3,"sources":["asset.png"],"sourcesContent":["'
            + bytes([0x89])
            + b'PNG\\v\\u0000"],"names":[],"mappings":"A'
            + bytes([0])
            + b'"}'
        )
        parsed = read_source_map(
            zstd.ZstdCompressor().compress(raw), Limits(), include_mappings=True
        )
        self.assertEqual(parsed.sources[0].content, b"\x89PNG\x0b\x00")
        self.assertEqual(parsed.mappings, "A\x00")
        self.assertEqual(len(parsed.warnings), 1)

    def test_legacy_escape_lexer_respects_literal_backslashes_and_keys(self) -> None:
        raw = (
            b'{"sources":["sourcesContent", "other.ts"],"version":3,'
            b'"sourcesContent":["\\\\v", "\\v"],"names":[],"mappings":"AAAA"}'
        )
        parsed = read_source_map(zstd.ZstdCompressor().compress(raw), Limits())
        self.assertEqual(parsed.sources[0].path, "sourcesContent")
        self.assertEqual([source.content for source in parsed.sources], [b"\\v", b"\x0b"])

    def test_bitpacked_mappings_to_vlq(self) -> None:
        data = compact(["a.ts"], [zstd.ZstdCompressor().compress(b"x")], binary_map())
        parsed = read_source_map(data, Limits(), include_mappings=True)
        self.assertEqual(parsed.mappings, "AAAA,KAAK")
        self.assertEqual(parsed.to_dict()["mappings"], "AAAA,KAAK")

    def test_bitpacked_line_exception_and_source_index(self) -> None:
        window = bytearray(32)
        window[0] = 2
        window[1] = 12  # generated-line exception and source-index delta
        window[8] = window[16] = window[24] = 1
        struct.pack_into("<H", window, 2, 1)
        window += b"\x06\x00\x04\xff" + bytes(8) + b"\x02"
        sync = struct.pack("<iiIiii", 0, 0, 0, 0, 0, 0)
        mapping = struct.pack("<QQQII", 32 + 24 + len(window) + 1, 2, 3, 1, 56)
        data = compact(["a.ts", "b.ts"], [b"", b""], mapping + sync + window + b"\x00")
        self.assertEqual(
            read_source_map(data, Limits(), include_mappings=True).mappings,
            "AAAA;;GCEG",
        )

    def test_empty_compact_map(self) -> None:
        parsed = read_source_map(struct.pack("<II", 0, 0), Limits(), include_mappings=True)
        self.assertEqual(parsed.sources, ())
        self.assertEqual(parsed.mappings, "")

    def test_invalid_map_rejected(self) -> None:
        cases = (
            b"bad",
            compact(["a"], [b"invalid-zstd"], b"AAAA"),
            compact(["a"], [b""], binary_map()[:-1]),
            compact(["a"], [b""], b"!"),
        )
        for data in cases:
            with self.subTest(data=data[:16]), self.assertRaises(BunUnpackError):
                read_source_map(data, Limits(), include_mappings=True)

    def test_producer_malformed_mappings_are_preserved_with_warning(self) -> None:
        bad_mapping = "AA//////DAAA"  # six fields in a real Bun 1.0.x map
        document = {
            "version": 3,
            "sources": ["a.ts"],
            "sourcesContent": ["a"],
            "names": [],
            "mappings": bad_mapping,
        }
        encoded = legacy(document)
        parsed = read_source_map(encoded, Limits(), include_mappings=True)
        self.assertEqual(parsed.mappings, bad_mapping)
        self.assertEqual(parsed.to_dict()["mappings"], bad_mapping)
        self.assertEqual(
            parsed.warnings,
            ("Embedded source map mappings are invalid: VLQ mapping must have 1, 4, or 5 fields",),
        )
        default = read_source_map(encoded, Limits())
        self.assertEqual(default.sources[0].content, b"a")
        self.assertEqual(default.warnings, ())

    def test_source_paths_inspection_skips_compact_content_decompression(self) -> None:
        data = compact(["../../packages/shared/src/x.ts", "empty.ts"], [b"not zstd", b""], b"AAAA")
        self.assertEqual(
            read_source_paths(data, Limits()),
            (("../../packages/shared/src/x.ts", "empty.ts"), ""),
        )
        with self.assertRaises(BunUnpackError):
            read_source_map(data, Limits())

        damaged = bytearray(data)
        content_table = 8 + 2 * 8
        struct.pack_into("<II", damaged, content_table, len(data) + 1, 4)
        with self.assertRaisesRegex(BunUnpackError, "pointer"):
            read_source_paths(bytes(damaged), Limits())

    def test_source_paths_inspection_legacy_root(self) -> None:
        document = {
            "version": 3,
            "sources": ["../other.ts", "empty.ts"],
            "sourcesContent": ["a", None],
            "sourceRoot": "../packages/",
            "names": [],
            "mappings": "AAAA",
        }
        self.assertEqual(
            read_source_paths(legacy(document), Limits()),
            (("../other.ts", "empty.ts"), "../packages/"),
        )

    def test_pointer_bounds_and_path_unicode(self) -> None:
        data = bytearray(compact(["a.ts"], [zstd.ZstdCompressor().compress(b"a")], b"AAAA"))
        struct.pack_into("<II", data, 8, len(data) + 1, 4)
        with self.assertRaisesRegex(BunUnpackError, "pointer"):
            read_source_map(bytes(data), Limits())
        bad_path = compact(["a.ts"], [b""], b"AAAA").replace(b"a.ts", b"\xff.ts")
        with self.assertRaisesRegex(BunUnpackError, "UTF-8 source path"):
            read_source_map(bad_path, Limits())

    def test_decompression_limits_and_frame_completeness(self) -> None:
        compressed = zstd.ZstdCompressor().compress(b"x" * 100)
        data = compact(["a"], [compressed], b"AAAA")
        with self.assertRaises(BunUnpackError):
            read_source_map(data, Limits(max_file_bytes=20))
        with self.assertRaises(BunUnpackError):
            read_source_map(data, Limits(max_total_bytes=10))
        for invalid_frame in (
            compressed[:-1],
            compressed + b"junk",
            compressed + compressed,
        ):
            with (
                self.subTest(frame=invalid_frame[-12:]),
                self.assertRaises(BunUnpackError),
            ):
                read_source_map(compact(["a"], [invalid_frame], b"AAAA"), Limits())
        json_frame = legacy(
            {
                "version": 3,
                "sources": [],
                "sourcesContent": [],
                "names": [],
                "mappings": "",
            }
        )
        for invalid_frame in (
            json_frame[:-1],
            json_frame + b"junk",
            json_frame + json_frame,
        ):
            with (
                self.subTest(legacy_frame=invalid_frame[-12:]),
                self.assertRaises(BunUnpackError),
            ):
                read_source_map(invalid_frame, Limits())

    def test_legacy_excessively_nested_json_is_domain_error(self) -> None:
        # A valid zstd frame can still contain JSON beyond Python's recursion limit.
        raw = b"[" * 1500 + b"0" + b"]" * 1500
        with self.assertRaises(BunUnpackError):
            read_source_map(zstd.ZstdCompressor().compress(raw), Limits())

    def test_unknown_size_frame_limit(self) -> None:
        destination = io.BytesIO()
        with zstd.ZstdCompressor().stream_writer(destination, closefd=False) as writer:
            writer.write(b"x" * 100)
        data = compact(["a"], [destination.getvalue()], b"AAAA")
        with self.assertRaises(BunUnpackError):
            read_source_map(data, Limits(max_total_bytes=50))

    def test_binary_header_and_window_bitwidth_guards(self) -> None:
        original = binary_map()
        malformed = bytearray(original)
        struct.pack_into("<Q", malformed, 8, 1 << 63)  # count overflow cannot allocate
        with self.assertRaises(BunUnpackError):
            read_source_map(
                compact(["a"], [b""], bytes(malformed)), Limits(), include_mappings=True
            )
        malformed = bytearray(original)
        malformed[88] = 0xFF  # varint overrun; only one delta byte was allocated
        with self.assertRaises(BunUnpackError):
            read_source_map(
                compact(["a"], [b""], bytes(malformed)), Limits(), include_mappings=True
            )


if __name__ == "__main__":
    unittest.main()
