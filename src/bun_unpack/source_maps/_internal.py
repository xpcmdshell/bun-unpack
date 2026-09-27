"""Decode Bun's bit-packed InternalSourceMap (1.3.13+).

Layout follows src/sourcemap/InternalSourceMap.{zig,rs} in Bun. All offsets and
varints are checked before use; the runtime's own blob validator checks only
its outer header, which is insufficient for reading an untrusted executable.
"""

from __future__ import annotations

import struct

from bun_unpack.errors import BunUnpackError

from ._vlq import encode as vlq

MAP_HEADER_SIZE = 32
SYNC_ENTRY_SIZE = 24
WINDOW_HEADER_SIZE = 32
MIN_SIZE = MAP_HEADER_SIZE + 1


def parse_header(data: bytes) -> tuple[int, int, int, int] | None:
    """Return (total, count, sync_count, stream_offset) when the outer header is self-consistent."""
    if len(data) < MIN_SIZE:
        return None
    total, count, _, sync_count, stream_offset = struct.unpack_from("<QQQII", data)
    if total != len(data) or sync_count != (count + 63) // 64:
        return None
    if stream_offset != MAP_HEADER_SIZE + sync_count * SYNC_ENTRY_SIZE or stream_offset >= len(
        data
    ):
        return None
    return total, count, sync_count, stream_offset


def is_internal_map(data: bytes) -> bool:
    return parse_header(data) is not None


def _varint(data: bytes, position: int, end: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 35, 7):
        if position >= end:
            raise BunUnpackError("Truncated InternalSourceMap varint")
        byte = data[position]
        position += 1
        if shift == 28 and byte > 15:
            raise BunUnpackError("InternalSourceMap varint exceeds 32 bits")
        value |= (byte & 127) << shift
        if not byte & 128:
            return ((value >> 1) ^ -(value & 1)), position
    raise BunUnpackError("InternalSourceMap varint exceeds 5 bytes")


def _bit(mask: int, index: int) -> bool:
    return bool(mask & (1 << index))


def decode_internal_map(data: bytes, sources_count: int, max_output_bytes: int) -> str:
    header = parse_header(data)
    if header is None:
        raise BunUnpackError("Invalid InternalSourceMap header")
    _, count, sync_count, stream_offset = header
    if count > max_output_bytes // 4:
        raise BunUnpackError("InternalSourceMap mapping count exceeds limit")
    if data[-1] != 0:
        raise BunUnpackError("Invalid InternalSourceMap stream offset or tail")
    stream_end = len(data) - 1

    previous_line = previous_column = previous_source = 0
    previous_original_line = previous_original_column = 0
    current_line = 0
    segments: list[str] = []
    output_bytes = 0
    seen = 0
    cursor = stream_offset

    def emit(state: tuple[int, int, int, int, int]) -> None:
        nonlocal previous_line, previous_column, previous_source
        nonlocal previous_original_line, previous_original_column
        nonlocal current_line, output_bytes
        line, column, source, original_line, original_column = state
        if (
            not 0 <= source < sources_count
            or min(line, column, original_line, original_column) < 0
            or max(line, column, original_line, original_column) > 0x7FFFFFFF
        ):
            raise BunUnpackError("Invalid InternalSourceMap source or coordinate")
        if line < previous_line or (line == previous_line and column < previous_column):
            raise BunUnpackError("InternalSourceMap mappings are out of order")
        separator = ""
        if line > current_line:
            gap = line - current_line
            if gap > max_output_bytes - output_bytes:
                raise BunUnpackError("InternalSourceMap mapping output exceeds limit")
            separator = ";" * gap
            previous_column = 0
            current_line = line
        elif seen > 0:
            separator = ","
        segment = "".join(
            (
                vlq(column - previous_column),
                vlq(source - previous_source),
                vlq(original_line - previous_original_line),
                vlq(original_column - previous_original_column),
            )
        )
        output_bytes += len(separator) + len(segment)
        if output_bytes > max_output_bytes or line > max_output_bytes:
            raise BunUnpackError("InternalSourceMap mapping output exceeds limit")
        segments.extend((separator, segment))
        previous_line, previous_column, previous_source = line, column, source
        previous_original_line, previous_original_column = (
            original_line,
            original_column,
        )

    for index in range(sync_count):
        (
            generated_line,
            generated_column,
            offset,
            original_line,
            original_column,
            source,
        ) = struct.unpack_from("<iiIiii", data, MAP_HEADER_SIZE + index * SYNC_ENTRY_SIZE)
        start = stream_offset + offset
        if start != cursor or start + WINDOW_HEADER_SIZE > stream_end:
            raise BunUnpackError("Invalid InternalSourceMap window offset")
        window_count, flags, col_length, line_length, original_col_length = struct.unpack_from(
            "<BBHHH", data, start
        )
        if not 1 <= window_count <= 64 or flags & ~12:
            raise BunUnpackError("Invalid InternalSourceMap window header")
        if window_count != min(64, count - seen):
            raise BunUnpackError("InternalSourceMap mapping count mismatch")
        gen_line_mask, orig_line_mask, orig_col_mask = struct.unpack_from("<QQQ", data, start + 8)
        delta_mask = (1 << (window_count - 1)) - 1
        if (gen_line_mask | orig_line_mask | orig_col_mask) & ~delta_mask:
            raise BunUnpackError("Invalid InternalSourceMap equality mask")
        col_start = start + WINDOW_HEADER_SIZE
        col_end = col_start + col_length
        line_end = col_end + line_length
        orig_col_end = line_end + original_col_length
        if orig_col_end > stream_end:
            raise BunUnpackError("InternalSourceMap window exceeds blob")
        col_pos, line_pos, original_col_pos = col_start, col_end, line_end
        rare_pos = orig_col_end
        exceptions: dict[int, int] = {}
        if flags & 4:
            while True:
                if rare_pos >= stream_end:
                    raise BunUnpackError("Unterminated InternalSourceMap exception list")
                delta_index = data[rare_pos]
                rare_pos += 1
                if delta_index == 255:
                    break
                if delta_index >= window_count - 1 or delta_index in exceptions:
                    raise BunUnpackError("Invalid InternalSourceMap exception index")
                exceptions[delta_index], rare_pos = _varint(data, rare_pos, stream_end)
                if exceptions[delta_index] <= 1:
                    raise BunUnpackError("Invalid generated line exception")
        source_mask = delta_mask
        if flags & 8:
            if rare_pos + 8 > stream_end:
                raise BunUnpackError("Truncated InternalSourceMap source mask")
            source_mask = struct.unpack_from("<Q", data, rare_pos)[0]
            rare_pos += 8
            if source_mask & ~delta_mask:
                raise BunUnpackError("Invalid InternalSourceMap source mask")

        state = (
            generated_line,
            generated_column,
            source,
            original_line,
            original_column,
        )
        emit(state)
        seen += 1
        for delta_index in range(window_count - 1):
            line, column, source, original_line, original_column = state
            line_delta = exceptions.get(delta_index, int(_bit(gen_line_mask, delta_index)))
            column_delta, col_pos = _varint(data, col_pos, col_end)
            if _bit(orig_line_mask, delta_index):
                original_line_delta = line_delta
            else:
                original_line_delta, line_pos = _varint(data, line_pos, line_end)
            if _bit(orig_col_mask, delta_index):
                original_col_delta = column_delta
            else:
                original_col_delta, original_col_pos = _varint(data, original_col_pos, orig_col_end)
            if not _bit(source_mask, delta_index):
                source_delta, rare_pos = _varint(data, rare_pos, stream_end)
                source += source_delta
            state = (
                line + line_delta,
                column_delta if line_delta else column + column_delta,
                source,
                original_line + original_line_delta,
                original_column + original_col_delta,
            )
            emit(state)
            seen += 1
        if (col_pos, line_pos, original_col_pos) != (col_end, line_end, orig_col_end):
            raise BunUnpackError("InternalSourceMap window has unused varint bytes")
        cursor = rare_pos
    if seen != count or cursor != stream_end:
        raise BunUnpackError("InternalSourceMap has trailing bytes or missing mappings")
    return "".join(segments)
