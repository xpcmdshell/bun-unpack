from __future__ import annotations

"""Data model for Bun's embedded standalone module graph.

These structures mirror the layout used by Bun when serializing the
`StandaloneModuleGraph`.
"""

import struct
from dataclasses import dataclass
from enum import IntEnum


class _UnknownFallbackEnum(IntEnum):
    """Base for enums that return UNKNOWN for unrecognized values."""

    @classmethod
    def _missing_(cls, value: object) -> "_UnknownFallbackEnum":
        return cls.UNKNOWN  # type: ignore[attr-defined]


class Encoding(_UnknownFallbackEnum):
    BINARY = 0
    LATIN1 = 1
    UTF8 = 2
    UNKNOWN = 255


class Loader(_UnknownFallbackEnum):
    JSX = 0
    JS = 1
    TS = 2
    TSX = 3
    CSS = 4
    FILE = 5
    JSON = 6
    TOML = 7
    WASM = 8
    NAPI = 9
    BASE64 = 10
    DATAURL = 11
    TEXT = 12
    SQLITE = 13
    SQLITE_EMBEDDED = 14
    HTML = 15
    UNKNOWN = 255


class ModuleFormat(_UnknownFallbackEnum):
    NONE = 0
    ESM = 1
    CJS = 2
    UNKNOWN = 255


class FileSide(_UnknownFallbackEnum):
    SERVER = 0
    CLIENT = 1
    UNKNOWN = 255


@dataclass(frozen=True)
class StringPointer:
    offset: int
    length: int

    SIZE = 8

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> "StringPointer":
        return cls(*struct.unpack_from("<II", data, offset))

    def slice(self, data: bytes) -> bytes:
        if self.length == 0:
            return b""
        return data[self.offset : self.offset + self.length]

    def slice_str(self, data: bytes) -> str:
        return self.slice(data).rstrip(b"\x00").decode("utf-8", errors="replace")


@dataclass(frozen=True)
class Flags:
    disable_default_env_files: bool
    disable_autoload_bunfig: bool
    disable_autoload_tsconfig: bool
    disable_autoload_package_json: bool

    @classmethod
    def from_int(cls, value: int) -> "Flags":
        return cls(
            disable_default_env_files=bool(value & 1),
            disable_autoload_bunfig=bool(value & 2),
            disable_autoload_tsconfig=bool(value & 4),
            disable_autoload_package_json=bool(value & 8),
        )


@dataclass(frozen=True)
class Offsets:
    byte_count: int
    modules_ptr: StringPointer
    entry_point_id: int
    compile_exec_argv_ptr: StringPointer
    flags: Flags

    SIZE = 32

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> "Offsets":
        byte_count = struct.unpack_from("<Q", data, offset)[0]
        modules_ptr = StringPointer.from_bytes(data, offset + 8)
        entry_point_id = struct.unpack_from("<I", data, offset + 16)[0]
        compile_exec_argv_ptr = StringPointer.from_bytes(data, offset + 20)
        flags_raw = struct.unpack_from("<I", data, offset + 28)[0]
        return cls(
            byte_count=byte_count,
            modules_ptr=modules_ptr,
            entry_point_id=entry_point_id,
            compile_exec_argv_ptr=compile_exec_argv_ptr,
            flags=Flags.from_int(flags_raw),
        )


@dataclass(frozen=True)
class SourceMapHeader:
    source_files_count: int
    map_bytes_length: int

    SIZE = 8

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> "SourceMapHeader":
        return cls(*struct.unpack_from("<II", data, offset))


@dataclass(frozen=True)
class CompiledModuleGraphFile:
    name: StringPointer
    contents: StringPointer
    sourcemap: StringPointer
    bytecode: StringPointer
    encoding: Encoding
    loader: Loader
    module_format: ModuleFormat
    side: FileSide

    SIZE = 36

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> "CompiledModuleGraphFile":
        name = StringPointer.from_bytes(data, offset)
        contents = StringPointer.from_bytes(data, offset + 8)
        sourcemap = StringPointer.from_bytes(data, offset + 16)
        bytecode = StringPointer.from_bytes(data, offset + 24)
        encoding, loader, module_format, side = struct.unpack_from("<BBBB", data, offset + 32)
        return cls(
            name=name,
            contents=contents,
            sourcemap=sourcemap,
            bytecode=bytecode,
            encoding=Encoding(encoding),
            loader=Loader(loader),
            module_format=ModuleFormat(module_format),
            side=FileSide(side),
        )


@dataclass(frozen=True)
class ParsedSourceMap:
    mappings: str
    sources: list[str]
    sources_content: list[str]


@dataclass(frozen=True)
class ExtractedFile:
    virtual_path: str
    real_path: str
    contents: bytes
    sourcemap: ParsedSourceMap | None
    bytecode: bytes | None
    encoding: Encoding
    loader: Loader
    module_format: ModuleFormat
    side: FileSide
    is_entry_point: bool
