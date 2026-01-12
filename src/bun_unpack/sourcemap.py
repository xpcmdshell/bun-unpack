from __future__ import annotations

"""Parser for Bun's serialized sourcemap format.

Bun embeds sourcemaps in a compact binary layout, where each source's contents
is zstd-compressed.

If a sourcemap can't be parsed, we return None and continue extraction.
"""

import zstandard as zstd

from .types import ParsedSourceMap, SourceMapHeader, StringPointer


def parse_serialized_sourcemap(data: bytes) -> ParsedSourceMap | None:

    if len(data) < SourceMapHeader.SIZE:
        return None

    header = SourceMapHeader.from_bytes(data)
    if header.source_files_count == 0:
        return None

    names_start = SourceMapHeader.SIZE
    names_size = header.source_files_count * StringPointer.SIZE
    contents_start = names_start + names_size
    contents_size = header.source_files_count * StringPointer.SIZE
    mappings_start = contents_start + contents_size
    mappings_end = mappings_start + header.map_bytes_length

    if mappings_end > len(data):
        return None

    sources: list[str] = []
    for i in range(header.source_files_count):
        ptr = StringPointer.from_bytes(data, names_start + i * StringPointer.SIZE)
        sources.append(ptr.slice_str(data))

    sources_content: list[str] = []
    dctx = zstd.ZstdDecompressor()
    for i in range(header.source_files_count):
        ptr = StringPointer.from_bytes(data, contents_start + i * StringPointer.SIZE)
        compressed = ptr.slice(data)
        if not compressed:
            sources_content.append("")
            continue
        try:
            decompressed = dctx.decompress(compressed)
            sources_content.append(decompressed.decode("utf-8", errors="replace"))
        except Exception:
            sources_content.append("")

    mappings_bytes = data[mappings_start:mappings_end]
    mappings = mappings_bytes.decode("ascii", errors="replace")

    return ParsedSourceMap(mappings=mappings, sources=sources, sources_content=sources_content)
