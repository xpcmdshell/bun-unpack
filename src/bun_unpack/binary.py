from __future__ import annotations

"""Binary parsing for Bun standalone executables.

This module extracts Bun's embedded "StandaloneModuleGraph" blob from:
- Mach-O: `__BUN,__bun` section
- PE: `.bun` section
- ELF: appended trailer data

The returned payload is the serialized module graph used by `module_graph.py`.
"""

import struct
from pathlib import Path

import lief

from .paths import TRAILER
from .types import Offsets

lief.logging.disable()


def extract_section_data_elf(file_bytes: bytes) -> bytes | None:
    if len(file_bytes) < 8:
        return None
    total_byte_count = struct.unpack("<Q", file_bytes[-8:])[0]
    if total_byte_count > len(file_bytes) or total_byte_count < 64:
        return None
    start = len(file_bytes) - total_byte_count
    return file_bytes[start:-8]


def extract_embedded_data(filepath: Path) -> tuple[bytes, Offsets, str] | None:
    raw_data = filepath.read_bytes()

    binary = lief.parse(str(filepath))
    if binary is None:
        return None

    fmt = "unknown"
    section_data: bytes | None = None

    def extract_section_data_macho(macho: "lief.MachO.Binary") -> bytes | None:
        section = macho.get_section("__BUN", "__bun")
        if section is None:
            return None
        raw = bytes(section.content)

        # Historical note: Bun has used different length header sizes here.
        # - Newer builds: u64 little-endian length, followed by that many bytes.
        # - Older builds: u32 little-endian length, followed by that many bytes.
        if len(raw) < 4:
            return None

        def try_length(prefix_size: int) -> bytes | None:
            if len(raw) < prefix_size:
                return None
            if prefix_size == 8:
                length = struct.unpack("<Q", raw[:8])[0]
            else:
                length = struct.unpack("<I", raw[:4])[0]

            if length == 0 or length + prefix_size > len(raw):
                return None

            payload = raw[prefix_size : prefix_size + length]
            if len(payload) < len(TRAILER) + Offsets.SIZE:
                return None

            return payload

        return try_length(8) or try_length(4)

    def extract_section_data_pe(pe: "lief.PE.Binary") -> bytes | None:
        section = pe.get_section(".bun")
        if section is None:
            return None
        content = bytes(section.content)
        if len(content) < 8:
            return None
        size = struct.unpack("<Q", content[:8])[0]
        if size == 0 or size + 8 > len(content):
            return None
        return content[8 : 8 + size]

    if isinstance(binary, lief.MachO.FatBinary):
        fmt = "macho_fat"
        for b in binary:
            section_data = extract_section_data_macho(b)
            if section_data:
                break
    elif isinstance(binary, lief.MachO.Binary):
        fmt = "macho"
        section_data = extract_section_data_macho(binary)
    elif isinstance(binary, lief.PE.Binary):
        fmt = "pe"
        section_data = extract_section_data_pe(binary)
    elif isinstance(binary, lief.ELF.Binary):
        fmt = "elf"
        section_data = extract_section_data_elf(raw_data)

    if section_data is None:
        return None

    if len(section_data) < len(TRAILER) + Offsets.SIZE:
        return None

    trailer_start = len(section_data) - len(TRAILER)
    if section_data[trailer_start:] != TRAILER:
        return None

    offsets_start = trailer_start - Offsets.SIZE
    offsets = Offsets.from_bytes(section_data, offsets_start)

    return (section_data, offsets, fmt)
