"""Decode embedded Bun standalone source maps into lossless source artifacts."""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field

import zstandard as zstd

from bun_unpack._model import Limits
from bun_unpack.errors import BunUnpackError

from ._internal import decode_internal_map, is_internal_map
from ._vlq import MAPPING_BYTES, decode_segment

_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_CORE_FIELDS = frozenset(
    ("version", "sources", "sourcesContent", "names", "mappings", "sourceRoot")
)


@dataclass(frozen=True)
class Source:
    path: str
    content: bytes | None


@dataclass(frozen=True)
class SourceMap:
    sources: tuple[Source, ...]
    mappings: str | None
    names: tuple[str, ...] = ()
    source_root: str = ""
    warnings: tuple[str, ...] = ()
    metadata: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        if self.mappings is None:
            raise BunUnpackError("Read the map with include_mappings=True to export v3 JSON")
        # A binary asset may occur in Bun's legacy sourcesContent. The asset is
        # returned losslessly as Source.content, but JSON v3 cannot carry it.
        contents: list[str | None] = []
        for source in self.sources:
            if source.content is None:
                contents.append(None)
            else:
                try:
                    contents.append(source.content.decode("utf-8"))
                except UnicodeDecodeError:
                    contents.append(None)
        result: dict[str, object] = {
            **{key: value for key, value in self.metadata.items() if key not in _CORE_FIELDS},
            "version": 3,
            "sources": [source.path for source in self.sources],
            "sourcesContent": contents,
            "names": list(self.names),
            "mappings": self.mappings,
        }
        if self.source_root:
            result["sourceRoot"] = self.source_root
        return result


def _decompress(data: bytes, max_bytes: int) -> bytes:
    if max_bytes < 0:
        raise BunUnpackError("Decompressed source map exceeds byte limit")
    try:
        parameters = zstd.get_frame_parameters(data)
        frame_size = parameters.content_size
        if parameters.window_size > max(1024 * 1024, max_bytes):
            raise BunUnpackError("Source map zstd window exceeds byte limit")
        if frame_size != zstd.CONTENTSIZE_UNKNOWN and frame_size > max_bytes:
            raise BunUnpackError("Decompressed source map exceeds byte limit")
        # For unknown-size frames, max_output_size caps decompression. For
        # known-size frames zstandard ignores that cap, hence the precheck.
        result = zstd.ZstdDecompressor().decompress(
            data, max_output_size=max_bytes, allow_extra_data=False
        )
        if len(result) > max_bytes:
            raise BunUnpackError("Decompressed source map exceeds byte limit")
        return result
    except zstd.ZstdError as exc:
        raise BunUnpackError(f"Invalid or oversized zstd source map: {exc}") from exc


def _validate_vlq(mappings: str, sources_count: int, names_count: int) -> None:
    source = original_line = original_column = name = 0
    for line in mappings.split(";"):
        generated_column = 0
        for segment in line.split(","):
            if not segment:
                if line:
                    raise BunUnpackError("Empty VLQ mapping segment")
                continue
            values = decode_segment(segment)
            if len(values) not in (1, 4, 5):
                raise BunUnpackError("VLQ mapping must have 1, 4, or 5 fields")
            if values[0] < 0:
                raise BunUnpackError("Generated columns must be sorted")
            generated_column += values[0]
            if len(values) > 1:
                source += values[1]
                original_line += values[2]
                original_column += values[3]
                if not 0 <= source < sources_count or original_line < 0 or original_column < 0:
                    raise BunUnpackError("VLQ mapping references an invalid source or coordinate")
                if len(values) == 5:
                    name += values[4]
                    if not 0 <= name < names_count:
                        raise BunUnpackError("VLQ mapping references an invalid name")


def _mapping_warnings(mappings: str, sources_count: int, names_count: int) -> tuple[str, ...]:
    try:
        _validate_vlq(mappings, sources_count, names_count)
    except BunUnpackError as exc:
        # The compiler produced this text; do not change it or lose sources.
        return (f"Embedded source map mappings are invalid: {exc}",)
    return ()


def _normalize_legacy_escapes(raw: bytes, max_bytes: int) -> bytes:
    """Normalize Bun's JS-only ``\\v`` escape while lexing JSON strings."""
    normalized = bytearray()
    in_string = False
    escaped = False
    for character in raw:
        if in_string:
            if escaped:
                if character == ord("v"):
                    normalized[-1:] = b"\\u000b"
                    escaped = False
                    if len(normalized) > max_bytes:
                        raise BunUnpackError("Source map JSON exceeds total byte limit")
                    continue
                escaped = False
            elif character == ord("\\"):
                escaped = True
            elif character == ord('"'):
                in_string = False
        elif character == ord('"'):
            in_string = True
        normalized.append(character)
    return bytes(normalized)


def _legacy(data: bytes, limits: Limits, include_mappings: bool) -> SourceMap:
    raw = _decompress(data, limits.max_total_bytes)
    try:
        # Bun historically inserted raw asset bytes directly into JSON strings.
        # Surrogateescape retains those bytes without corrupting binary assets.
        text = _normalize_legacy_escapes(raw, limits.max_total_bytes).decode(
            "utf-8", errors="surrogateescape"
        )
        document = json.loads(text, strict=False)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise BunUnpackError("Invalid UTF-8 source map JSON") from exc
    if not isinstance(document, dict) or document.get("version") != 3:
        raise BunUnpackError("Expected version 3 source map JSON")
    paths = document.get("sources")
    contents = document.get("sourcesContent")
    names = document.get("names", [])
    mappings = document.get("mappings")
    source_root = document.get("sourceRoot", "")
    if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
        raise BunUnpackError("Invalid source map sources")
    if len(paths) > limits.max_sources:
        raise BunUnpackError("Source count exceeds limit")
    if contents is None:
        contents = [None] * len(paths)
    if (
        not isinstance(contents, list)
        or len(contents) != len(paths)
        or any(content is not None and not isinstance(content, str) for content in contents)
        or not isinstance(names, list)
        or not all(isinstance(name, str) for name in names)
        or not isinstance(mappings, str)
        or not isinstance(source_root, str)
    ):
        raise BunUnpackError("Invalid source map metadata")
    warnings = _mapping_warnings(mappings, len(paths), len(names)) if include_mappings else ()
    try:
        for text in (*paths, *names, source_root):
            text.encode("utf-8")
        sources = []
        total_bytes = 0
        for path, content in zip(paths, contents):
            source_bytes = (
                content.encode("utf-8", errors="surrogateescape") if content is not None else None
            )
            if source_bytes is not None:
                if len(source_bytes) > limits.max_file_bytes:
                    raise BunUnpackError("Source content exceeds file byte limit")
                total_bytes += len(source_bytes)
                if total_bytes > limits.max_total_bytes:
                    raise BunUnpackError("Source contents exceed total byte limit")
            sources.append(Source(path, source_bytes))
    except UnicodeError as exc:
        raise BunUnpackError("Invalid Unicode in source map metadata") from exc
    metadata = {key: value for key, value in document.items() if key not in _CORE_FIELDS}
    return SourceMap(
        tuple(sources),
        mappings if include_mappings else None,
        tuple(names),
        source_root,
        warnings,
        metadata,
    )


def _pointer_bounds(data: bytes, position: int, minimum: int) -> tuple[int, int]:
    offset, length = struct.unpack_from("<II", data, position)
    if not length:
        if offset and not minimum <= offset <= len(data):
            raise BunUnpackError("Invalid zero-length source map pointer")
    elif offset < minimum or offset + length > len(data):
        raise BunUnpackError("Source map pointer is out of bounds")
    return offset, length


def _pointer(data: bytes, position: int, minimum: int) -> bytes | None:
    offset, length = _pointer_bounds(data, position, minimum)
    return data[offset : offset + length] if length else None


def _compact(
    data: bytes,
    limits: Limits,
    include_mappings: bool,
    *,
    include_contents: bool = True,
) -> SourceMap:
    if len(data) < 8:
        raise BunUnpackError("Truncated compact source map header")
    count, mapping_length = struct.unpack_from("<II", data)
    if count > limits.max_sources:
        raise BunUnpackError("Source count exceeds limit")
    mapping_offset = 8 + count * 16
    mapping_end = mapping_offset + mapping_length
    if mapping_end > len(data):
        raise BunUnpackError("Compact source map pointer table or mappings truncated")
    mappings = None
    warnings: tuple[str, ...] = ()
    if include_mappings:
        mapping_bytes = data[mapping_offset:mapping_end]
        if all(byte in MAPPING_BYTES for byte in mapping_bytes):
            mappings = mapping_bytes.decode("ascii")
            warnings = _mapping_warnings(mappings, count, 0)
        elif is_internal_map(mapping_bytes):
            mappings = decode_internal_map(mapping_bytes, count, limits.max_total_bytes)
        else:
            raise BunUnpackError("Unrecognized compact source map mapping format")
        if len(mappings) > limits.max_total_bytes:
            raise BunUnpackError("Mapping output exceeds total byte limit")
    used = 0
    sources: list[Source] = []
    for index in range(count):
        name_bytes = _pointer(data, 8 + index * 8, mapping_end)
        try:
            path = (name_bytes or b"").decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BunUnpackError("Invalid UTF-8 source path") from exc
        content_pointer = 8 + count * 8 + index * 8
        content = None
        if include_contents:
            compressed = _pointer(data, content_pointer, mapping_end)
            if compressed is not None:
                content = _decompress(
                    compressed,
                    min(limits.max_file_bytes, limits.max_total_bytes - used),
                )
                used += len(content)
        else:
            _pointer_bounds(data, content_pointer, mapping_end)
        sources.append(Source(path, content))
    return SourceMap(tuple(sources), mappings, warnings=warnings)


def _parse(
    data: bytes, limits: Limits, *, include_mappings: bool, include_contents: bool
) -> SourceMap:
    if len(data) > limits.max_file_bytes:
        raise BunUnpackError("Embedded source map exceeds file byte limit")
    if data.startswith(_ZSTD_MAGIC):
        # Legacy maps hold the whole document in one JSON frame, so contents
        # must be decoded to inspect paths; the same limits still apply.
        return _legacy(data, limits, include_mappings)
    return _compact(data, limits, include_mappings, include_contents=include_contents)


def read_source_map(data: bytes, limits: Limits, *, include_mappings: bool = False) -> SourceMap:
    """Read a complete embedded source-map blob, enforcing decompression limits."""
    return _parse(data, limits, include_mappings=include_mappings, include_contents=True)


def read_source_paths(data: bytes, limits: Limits) -> tuple[tuple[str, ...], str]:
    """Inspect source references without decompressing compact source contents."""
    parsed = _parse(data, limits, include_mappings=False, include_contents=False)
    return tuple(source.path for source in parsed.sources), parsed.source_root


__all__ = ["Source", "SourceMap", "read_source_map", "read_source_paths"]
