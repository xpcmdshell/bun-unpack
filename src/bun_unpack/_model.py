"""Shared internal primitives: embedded-data descriptions and bounded reads."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .errors import BunUnpackError


@dataclass(frozen=True)
class Limits:
    max_file_bytes: int = 256 * 1024 * 1024
    max_total_bytes: int = 1024 * 1024 * 1024
    max_modules: int = 100_000
    max_sources: int = 100_000
    max_path_bytes: int = 16 * 1024
    max_total_path_bytes: int = 32 * 1024 * 1024

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


def read_range(stream: BinaryIO, offset: int, size: int, file_size: int) -> bytes:
    """Read exactly one bounded range of an executable."""
    if offset < 0 or size < 0 or offset + size > file_size:
        raise BunUnpackError(f"Embedded range points outside the executable: {offset}+{size}")
    stream.seek(offset)
    data = stream.read(size)
    if len(data) != size:
        raise BunUnpackError("Executable was truncated while reading embedded data")
    return data


@dataclass(frozen=True)
class Blob:
    path: Path
    offset: int
    size: int

    def read(self, limit: int) -> bytes:
        if self.size > limit:
            raise BunUnpackError(f"Embedded blob exceeds the {limit}-byte limit: {self.size}")
        if self.offset < 0 or self.size < 0:
            raise BunUnpackError("Negative embedded blob range")
        with self.path.open("rb") as stream:
            return read_range(stream, self.offset, self.size, self.path.stat().st_size)


@dataclass(frozen=True)
class FormatInfo:
    container: str
    record_size: int
    footer_size: int
    runtime_version: str | None = None
    runtime_revision: str | None = None


@dataclass(frozen=True)
class ModuleRecord:
    path: str
    contents: Blob
    sourcemap: Blob | None
    bytecode: Blob | None
    encoding: str
    loader: str
    module_format: str
    side: str
    is_entry_point: bool
    module_info: Blob | None = None
    bytecode_origin_path: str | None = None


@dataclass(frozen=True)
class ModuleGraph:
    modules: tuple[ModuleRecord, ...]
    format: FormatInfo
    exec_argv: bytes = b""
