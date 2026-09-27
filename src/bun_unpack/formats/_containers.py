"""Bounded executable-envelope readers; no graph semantics live here."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from bun_unpack._model import read_range
from bun_unpack.errors import BunUnpackError

TRAILER = b"\n---- Bun! ----\n"
MAX_HEADERS = 4096
MAX_NAME_TABLE = 1024 * 1024


@dataclass(frozen=True)
class Candidate:
    container: str
    start: int  # graph begins here, after any section length prefix
    end: int  # graph, footer and trailer end here
    appended: bool
    prefix_size: int = 0


def _section(
    stream: BinaryIO,
    file_size: int,
    container: str,
    offset: int,
    size: int,
    prefixes: tuple[int, ...],
) -> list[Candidate]:
    if offset < 0 or size < 0 or offset + size > file_size:
        raise BunUnpackError("Bun section points outside the executable")
    candidates: list[Candidate] = []
    for prefix in prefixes:
        if size < prefix:
            continue
        length = int.from_bytes(read_range(stream, offset, prefix, file_size), "little")
        if length < 24 + len(TRAILER) or length > size - prefix:
            continue
        start = offset + prefix
        end = start + length
        if read_range(stream, end - len(TRAILER), len(TRAILER), file_size) == TRAILER:
            candidates.append(Candidate(container, start, end, False, prefix))
    return candidates


def _macho(
    stream: BinaryIO, file_size: int, base: int = 0, span: int | None = None
) -> list[Candidate]:
    if span is None:
        span = file_size
    magic = read_range(stream, base, 4, file_size)
    if magic not in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return []
    is_64 = magic[0] == 0xCF
    header_size = 32 if is_64 else 28
    header = read_range(stream, base, header_size, file_size)
    command_count, command_bytes = struct.unpack_from("<II", header, 16)
    if command_count > MAX_HEADERS or command_bytes > span - header_size:
        raise BunUnpackError("Invalid Mach-O load-command table")
    cursor = base + header_size
    command_end = cursor + command_bytes
    results: list[Candidate] = []
    for _ in range(command_count):
        command, length = struct.unpack("<II", read_range(stream, cursor, 8, file_size))
        if length < 8 or cursor + length > command_end:
            raise BunUnpackError("Invalid Mach-O load command")
        if command in (0x19, 0x1):
            segment_header = 72 if command == 0x19 else 56
            section_size = 80 if command == 0x19 else 68
            if length < segment_header:
                raise BunUnpackError("Invalid Mach-O segment")
            segment = read_range(stream, cursor, segment_header, file_size)
            sections = struct.unpack_from("<I", segment, 64 if command == 0x19 else 48)[0]
            if sections > MAX_HEADERS or segment_header + sections * section_size > length:
                raise BunUnpackError("Invalid Mach-O section count")
            for index in range(sections):
                section = read_range(
                    stream,
                    cursor + segment_header + index * section_size,
                    section_size,
                    file_size,
                )
                if (
                    section[:16].rstrip(b"\0") != b"__bun"
                    or section[16:32].rstrip(b"\0") != b"__BUN"
                ):
                    continue
                if command == 0x19:
                    section_length = struct.unpack_from("<Q", section, 40)[0]
                    section_offset = struct.unpack_from("<I", section, 48)[0]
                else:
                    section_length, section_offset = struct.unpack_from("<II", section, 36)
                if section_offset + section_length > span:
                    raise BunUnpackError("Mach-O Bun section exceeds its slice")
                results.extend(
                    _section(
                        stream,
                        file_size,
                        "macho",
                        base + section_offset,
                        section_length,
                        (4, 8),
                    )
                )
        cursor += length
    return results


def _fat_macho(stream: BinaryIO, file_size: int) -> list[Candidate]:
    magic = read_range(stream, 0, 4, file_size)
    endian = ">" if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") else "<"
    is_64 = magic in (b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")
    count = struct.unpack(endian + "I", read_range(stream, 4, 4, file_size))[0]
    entry_size = 32 if is_64 else 20
    if count > MAX_HEADERS or 8 + count * entry_size > file_size:
        raise BunUnpackError("Invalid fat Mach-O slice table")
    results: list[Candidate] = []
    for index in range(count):
        row = read_range(stream, 8 + index * entry_size, entry_size, file_size)
        offset, size = struct.unpack_from(endian + ("QQ" if is_64 else "II"), row, 8)
        if offset + size > file_size:
            raise BunUnpackError("Fat Mach-O slice exceeds the file")
        results.extend(_macho(stream, file_size, offset, size))
    return results


def _pe(stream: BinaryIO, file_size: int) -> list[Candidate]:
    if file_size < 64:
        raise BunUnpackError("Truncated PE header")
    pe_offset = struct.unpack("<I", read_range(stream, 60, 4, file_size))[0]
    header = read_range(stream, pe_offset, 24, file_size)
    if header[:4] != b"PE\0\0":
        raise BunUnpackError("Invalid PE signature")
    sections = struct.unpack_from("<H", header, 6)[0]
    optional_size = struct.unpack_from("<H", header, 20)[0]
    if sections > MAX_HEADERS or pe_offset + 24 + optional_size + sections * 40 > file_size:
        raise BunUnpackError("Invalid PE section table")
    results: list[Candidate] = []
    for index in range(sections):
        section = read_range(stream, pe_offset + 24 + optional_size + index * 40, 40, file_size)
        if section[:8].rstrip(b"\0") != b".bun":
            continue
        logical_size = struct.unpack_from("<I", section, 8)[0]
        raw_size, raw_offset = struct.unpack_from("<II", section, 16)
        if raw_offset + raw_size > file_size or logical_size > raw_size:
            raise BunUnpackError("Invalid PE Bun section extent")
        results.extend(_section(stream, file_size, "pe", raw_offset, logical_size, (8, 4)))
    return results


def _elf(stream: BinaryIO, file_size: int) -> list[Candidate]:
    ident = read_range(stream, 0, 16, file_size)
    if ident[5] != 1 or ident[4] not in (1, 2):
        raise BunUnpackError("Unsupported ELF class or endianness")
    is_64 = ident[4] == 2
    header = read_range(stream, 0, 64 if is_64 else 52, file_size)
    if is_64:
        section_offset = struct.unpack_from("<Q", header, 40)[0]
        entry_size, count, names_index = struct.unpack_from("<HHH", header, 58)
        offset_field, size_field = 24, 32
        minimum_size = 64
    else:
        section_offset = struct.unpack_from("<I", header, 32)[0]
        entry_size, count, names_index = struct.unpack_from("<HHH", header, 46)
        offset_field, size_field = 16, 20
        minimum_size = 40
    if not section_offset or not count:
        return []
    if (
        count > MAX_HEADERS
        or names_index >= count
        or entry_size < minimum_size
        or section_offset + entry_size * count > file_size
    ):
        raise BunUnpackError("Invalid ELF section table")
    names_header = read_range(
        stream, section_offset + names_index * entry_size, minimum_size, file_size
    )
    names_offset = struct.unpack_from("<Q" if is_64 else "<I", names_header, offset_field)[0]
    names_length = struct.unpack_from("<Q" if is_64 else "<I", names_header, size_field)[0]
    if names_length > MAX_NAME_TABLE:
        raise BunUnpackError("ELF section-name table exceeds limit")
    names = read_range(stream, names_offset, names_length, file_size)
    results: list[Candidate] = []
    for index in range(count):
        section = read_range(stream, section_offset + index * entry_size, minimum_size, file_size)
        name_offset = struct.unpack_from("<I", section)[0]
        if name_offset >= len(names) or names.find(b"\0", name_offset) < 0:
            raise BunUnpackError("Invalid ELF section name")
        name = names[name_offset : names.find(b"\0", name_offset)]
        if name != b".bun":
            continue
        offset = struct.unpack_from("<Q" if is_64 else "<I", section, offset_field)[0]
        size = struct.unpack_from("<Q" if is_64 else "<I", section, size_field)[0]
        results.extend(_section(stream, file_size, "elf", offset, size, (8, 4)))
    return results


def candidates(path: Path) -> list[Candidate]:
    file_size = path.stat().st_size
    with path.open("rb") as stream:
        magic = read_range(stream, 0, min(4, file_size), file_size)
        if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
            container, sections = "macho", _macho(stream, file_size)
        elif magic in (
            b"\xca\xfe\xba\xbe",
            b"\xbe\xba\xfe\xca",
            b"\xca\xfe\xba\xbf",
            b"\xbf\xba\xfe\xca",
        ):
            container, sections = "macho", _fat_macho(stream, file_size)
        elif magic[:2] == b"MZ":
            container, sections = "pe", _pe(stream, file_size)
        elif magic == b"\x7fELF":
            container, sections = "elf", _elf(stream, file_size)
        else:
            raise BunUnpackError("Unsupported executable container (expected Mach-O, PE, or ELF)")
        if file_size >= 24 and read_range(stream, file_size - 24, 16, file_size) == TRAILER:
            marker = struct.unpack("<Q", read_range(stream, file_size - 8, 8, file_size))[0]
            if marker == file_size:
                sections.append(Candidate(container, 0, file_size - 8, True))
        return sections
