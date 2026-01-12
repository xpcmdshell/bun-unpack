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

_lief_initialized = False


def _init_lief() -> None:
    global _lief_initialized
    if not _lief_initialized:
        lief.logging.disable()
        _lief_initialized = True


def extract_section_data_elf(file_bytes: bytes) -> bytes | None:
    """Extract embedded data from ELF.

    ELF structure at end of file:
    [payload (byte_count bytes)] [Offsets (32 bytes)] [trailer (16 bytes)] [total_file_size (8 bytes)]

    We return just the payload portion. The caller will find trailer/offsets at the end of it.
    """
    trailer = b"\n---- Bun! ----\n"

    # Last 8 bytes = total file size (sanity check marker)
    if len(file_bytes) < 8 + 16 + 32:
        return None

    # Find trailer (it's 24 bytes from end: 16 trailer + 8 size)
    trailer_start = len(file_bytes) - 8 - 16
    if file_bytes[trailer_start : trailer_start + 16] != trailer:
        return None

    # Offsets are 32 bytes before trailer
    offsets_start = trailer_start - 32

    # byte_count is first 8 bytes of offsets
    byte_count = struct.unpack("<Q", file_bytes[offsets_start : offsets_start + 8])[0]
    if byte_count < 32 or byte_count > len(file_bytes):
        return None

    # Payload is byte_count bytes before offsets
    payload_start = offsets_start - byte_count
    if payload_start < 0:
        return None

    # Return payload + offsets + trailer (what the rest of the code expects)
    return file_bytes[payload_start : trailer_start + 16]


def extract_embedded_data(filepath: Path) -> tuple[bytes, Offsets, str] | None:
    _init_lief()
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
