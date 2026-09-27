"""Validate historical graph records against explicit ABI profiles."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from bun_unpack._model import (
    Blob,
    FormatInfo,
    Limits,
    ModuleGraph,
    ModuleRecord,
    read_range,
)
from bun_unpack.errors import BunUnpackError

from ._containers import TRAILER, Candidate

# The enum is append-only *within* a family, but jsonc inserted at index 7 in 1.2.5.
# These boundaries follow tagged src/options.zig and src/ast/loader.rs.
LOADERS_EARLY = (
    "jsx",
    "js",
    "ts",
    "tsx",
    "css",
    "file",
    "json",
    "toml",
    "wasm",
    "napi",
    "base64",
    "dataurl",
    "text",
    "bunsh",
    "sqlite",
    "sqlite_embedded",
)
LOADERS_HTML = LOADERS_EARLY + ("html",)
LOADERS_JSONC = LOADERS_EARLY[:7] + ("jsonc",) + LOADERS_HTML[7:]
LOADERS_YAML = LOADERS_JSONC + ("yaml",)
LOADERS_JSON5 = LOADERS_YAML + ("json5",)
LOADERS_MD = LOADERS_JSON5 + ("md",)
LOADERS_XML = LOADERS_MD + ("xml",)
VERSION_MARKER = re.compile(rb"(?<![\w.])(\d{1,2}\.\d{1,2}\.\d{1,3})\+[a-f0-9]{9,40}(?![a-f0-9])")
VERSION_PROBE_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class RecordLayout:
    stride: int
    pointer_count: int
    enums_at: int


RECORD_LAYOUTS = (
    RecordLayout(32, 3, 24),
    RecordLayout(28, 3, 24),
    RecordLayout(36, 4, 32),
    RecordLayout(52, 6, 48),
)


@dataclass(frozen=True)
class RawRecord:
    path: str
    contents: Blob
    sourcemap: Blob | None
    bytecode: Blob | None
    encoding: int
    loader: int
    module_format: int
    side: int
    module_info: Blob | None
    bytecode_origin_path: str | None


def _range(offset: int, length: int, graph_size: int, label: str) -> None:
    if offset > graph_size or length > graph_size - offset:
        raise BunUnpackError(f"{label} points outside the module graph")


def _version_markers(stream: BinaryIO, start: int, end: int, file_size: int) -> set[str]:
    """Scan only the requested runtime interval in bounded chunks."""
    matches: set[str] = set()
    for offset in range(start, end, 64 * 1024):
        scan_start = max(0, offset - 1)
        data = read_range(stream, scan_start, min(64 * 1024 + 65, end - scan_start), file_size)
        for match in VERSION_MARKER.finditer(data):
            position = scan_start + match.start()
            if offset <= position < offset + 64 * 1024:
                matches.add(match.group(0).decode("ascii"))
    return matches


def _matches_version(candidate: Candidate, stride: int, footer_size: int, version: str) -> bool:
    """Use runtime markers only to corroborate a structurally valid profile."""
    release = tuple(map(int, version.split(".")))
    if stride == 32 and release >= (1, 1, 22):
        return False
    if stride == 28 and not (1, 1, 22) <= release < (1, 1, 30):
        return False
    if stride == 36 and not (1, 1, 30) <= release < (1, 3, 9):
        return False
    if stride == 52 and release < (1, 3, 9):
        return False
    if (footer_size == 32) != (release >= (1, 2, 21)):
        return False
    return not (
        candidate.container == "macho"
        and candidate.prefix_size
        and (candidate.prefix_size == 8) != (release >= (1, 3, 4))
    )


def decode(path: Path, candidate: Candidate, limits: Limits, file_size: int) -> list[ModuleGraph]:
    graphs: list[ModuleGraph] = []
    failures: list[str] = []
    markers: set[str] = set()
    tail_checked = False
    full_checked = False
    with path.open("rb") as stream:
        end = candidate.end
        if read_range(stream, end - 16, 16, file_size) != TRAILER:
            raise BunUnpackError("Missing Bun graph trailer")
        for footer_size in (24, 32):
            footer_start = end - 16 - footer_size
            if footer_start < candidate.start:
                continue
            footer = read_range(stream, footer_start, footer_size, file_size)
            byte_count = struct.unpack_from("<Q", footer)[0]
            if byte_count == 0 or byte_count > footer_start - candidate.start:
                continue
            graph_start = footer_start - byte_count
            if not candidate.appended and graph_start != candidate.start:
                continue
            table_offset, table_size, entry_id = struct.unpack_from("<III", footer, 8)
            if table_size == 0 or table_size > limits.max_modules * 52:
                continue
            if table_offset > byte_count or table_size > byte_count - table_offset:
                continue
            if footer_size == 32:
                argv_offset, argv_length, flags = struct.unpack_from("<III", footer, 20)
                if argv_length:
                    try:
                        _range(argv_offset, argv_length, byte_count, "Compile argv")
                    except BunUnpackError:
                        continue
                # 32-byte footer cannot predate argv or contain a counterfeit table.
            else:
                argv_offset = argv_length = flags = 0
            for layout in RECORD_LAYOUTS:
                if layout.stride == 52 and footer_size != 32:
                    continue
                if table_size % layout.stride:
                    continue
                count = table_size // layout.stride
                if count == 0 or count > limits.max_modules or entry_id >= count:
                    continue
                try:
                    modules = _modules(
                        stream,
                        path,
                        file_size,
                        graph_start,
                        byte_count,
                        table_offset,
                        count,
                        layout,
                        limits,
                    )
                    exec_argv = (
                        read_range(stream, graph_start + argv_offset, argv_length, file_size)
                        if argv_length
                        else b""
                    )
                    tail_start = max(0, graph_start - VERSION_PROBE_BYTES)
                    if not tail_checked:
                        markers.update(_version_markers(stream, tail_start, graph_start, file_size))
                        tail_checked = True
                    if len(markers) != 1 and layout.stride in (36, 52) and not full_checked:
                        markers.update(_version_markers(stream, 0, tail_start, file_size))
                        full_checked = True
                    hint = revision = None
                    if len(markers) == 1:
                        hint, _, revision = next(iter(markers)).partition("+")
                    if hint is not None and not _matches_version(
                        candidate, layout.stride, footer_size, hint
                    ):
                        failures.append("Runtime marker conflicts with the graph profile")
                        continue
                    if layout.stride == 52:
                        if flags & ~0x7FF:
                            raise BunUnpackError("Unknown Bun graph flag bits")
                        _validate_optional_records(
                            stream,
                            file_size,
                            graph_start,
                            byte_count,
                            table_offset + table_size,
                            count,
                            flags,
                            limits,
                        )
                    variants = _interpret(modules, layout.stride, hint, flags, entry_id)
                except BunUnpackError as error:
                    failures.append(str(error))
                    continue
                for variant in variants:
                    graphs.append(
                        ModuleGraph(
                            variant,
                            FormatInfo(
                                candidate.container, layout.stride, footer_size, hint, revision
                            ),
                            exec_argv,
                        )
                    )
    if not graphs:
        detail = "; ".join(dict.fromkeys(failures))[:300]
        raise BunUnpackError(
            f"No valid graph profile in {candidate.container} envelope: {detail or 'invalid footer or table'}"
        )
    return graphs


def _validate_optional_records(
    stream: BinaryIO,
    file_size: int,
    graph_start: int,
    graph_size: int,
    table_end: int,
    module_count: int,
    flags: int,
    limits: Limits,
) -> None:
    """Validate the flag-gated metadata chain after a modern module table."""
    cursor = table_end

    def consume(size: int, label: str) -> bytes:
        nonlocal cursor
        _range(cursor, size, graph_size, label)
        value = read_range(stream, graph_start + cursor, size, file_size)
        cursor += size
        return value

    def pointer(raw: bytes, label: str) -> None:
        offset, size = struct.unpack("<II", raw)
        _range(offset, size, graph_size, label)

    if flags & (1 << 5):  # source hashes, one u32 per module
        consume(module_count * 4, "Source hash table")
    if flags & (1 << 6):  # builtin bytecode: u32 count, then {u32 id, pointer}
        builtin_count = struct.unpack("<I", consume(4, "Builtin bytecode count"))[0]
        if builtin_count > limits.max_modules or builtin_count > (graph_size - cursor) // 12:
            raise BunUnpackError("Invalid builtin bytecode count")
        for _ in range(builtin_count):
            raw = consume(12, "Builtin bytecode record")
            pointer(raw[4:], "Builtin bytecode pointer")
    if flags & (1 << 7):
        pointer(consume(8, "Bytecode string table pointer"), "Bytecode string table")
    if flags & (1 << 8):
        startup_count = struct.unpack("<I", consume(4, "Startup module count"))[0]
        if startup_count > module_count:
            raise BunUnpackError("Startup module count exceeds module table")
    if flags & (1 << 9):
        pointer(consume(8, "Module-info string table pointer"), "Module-info string table")


def _modules(
    stream: BinaryIO,
    path: Path,
    file_size: int,
    base: int,
    graph_size: int,
    table_offset: int,
    count: int,
    layout: RecordLayout,
    limits: Limits,
) -> list[RawRecord]:
    records: list[RawRecord] = []
    total_contents = 0
    total_path_bytes = 0
    for index in range(count):
        record = read_range(
            stream,
            base + table_offset + index * layout.stride,
            layout.stride,
            file_size,
        )
        pointers = [struct.unpack_from("<II", record, i * 8) for i in range(layout.pointer_count)]
        for ptr_index, (offset, length) in enumerate(pointers):
            _range(offset, length, graph_size, f"Module {index} pointer {ptr_index}")
        name_offset, name_length = pointers[0]
        if not 1 <= name_length <= limits.max_path_bytes:
            raise BunUnpackError("Invalid module path length")
        total_path_bytes += name_length
        if total_path_bytes > min(limits.max_total_path_bytes, limits.max_total_bytes):
            raise BunUnpackError("Total module path length exceeds limit")
        raw_name = read_range(stream, base + name_offset, name_length, file_size)
        if raw_name.endswith(b"\0"):
            raw_name = raw_name[:-1]
        if not raw_name or b"\0" in raw_name:
            raise BunUnpackError("Invalid module path")
        try:
            name = raw_name.decode("utf-8")
        except UnicodeDecodeError as error:
            raise BunUnpackError("Invalid UTF-8 module path") from error
        if not name.replace("\\", "/").startswith(("/", "compiled://", "B:/~BUN/")):
            raise BunUnpackError("Unrecognized module path prefix")

        def blob(pointer: tuple[int, int]) -> Blob:
            return Blob(path, base + pointer[0], pointer[1])

        contents = blob(pointers[1])
        if contents.size > limits.max_file_bytes:
            raise BunUnpackError("Module contents exceed file-size limit")
        total_contents += contents.size
        if total_contents > limits.max_total_bytes:
            raise BunUnpackError("Combined module contents exceed total limit")
        sourcemap = blob(pointers[2]) if pointers[2][1] else None
        bytecode = blob(pointers[3]) if layout.pointer_count >= 4 and pointers[3][1] else None
        if layout.stride == 32:
            encoding, loader, module_format, side = 1, record[layout.enums_at], 0, 0
        else:
            encoding, loader = record[layout.enums_at : layout.enums_at + 2]
            module_format = record[layout.enums_at + 2] if layout.pointer_count >= 4 else 0
            side = record[layout.enums_at + 3] if layout.pointer_count >= 4 else 0
        if encoding > 2 or loader > 21 or module_format > 2:
            raise BunUnpackError("Unknown module encoding, loader or format")
        module_info = blob(pointers[4]) if layout.pointer_count == 6 and pointers[4][1] else None
        origin: str | None = None
        if layout.pointer_count == 6 and pointers[5][1]:
            origin_offset, origin_length = pointers[5]
            if origin_length > limits.max_path_bytes:
                raise BunUnpackError("Bytecode origin path exceeds limit")
            total_path_bytes += origin_length
            if total_path_bytes > min(limits.max_total_path_bytes, limits.max_total_bytes):
                raise BunUnpackError("Total module path length exceeds limit")
            raw_origin = read_range(stream, base + origin_offset, origin_length, file_size)
            if raw_origin.endswith(b"\0"):
                raw_origin = raw_origin[:-1]
            if not raw_origin or b"\0" in raw_origin:
                raise BunUnpackError("Invalid bytecode origin path")
            try:
                origin = raw_origin.decode("utf-8")
            except UnicodeDecodeError as error:
                raise BunUnpackError("Invalid UTF-8 bytecode origin path") from error
        records.append(
            RawRecord(
                name,
                contents,
                sourcemap,
                bytecode,
                encoding,
                loader,
                module_format,
                side,
                module_info,
                origin,
            )
        )
    return records


def _interpret(
    records: list[RawRecord],
    stride: int,
    version: str | None,
    flags: int,
    entry_id: int,
) -> list[tuple[ModuleRecord, ...]]:
    # Distinct enum meanings require runtime corroboration when values overlap.
    release = tuple(map(int, version.split("."))) if version is not None else None
    utf16 = release is not None and release >= (1, 4, 1)
    if release is not None and release >= (1, 3, 3):
        known_bits = 0x7FF if utf16 else 0xF
        if flags & ~known_bits:
            return []
    if release is None:
        loaders = LOADERS_EARLY
    elif release >= (1, 4, 0):
        loaders = LOADERS_XML
    elif release >= (1, 3, 8):
        loaders = LOADERS_MD
    elif release >= (1, 3, 7):
        loaders = LOADERS_JSON5
    elif release >= (1, 2, 21):
        loaders = LOADERS_YAML
    elif release >= (1, 2, 5):
        loaders = LOADERS_JSONC
    elif release >= (1, 2, 0):
        loaders = LOADERS_HTML
    else:
        loaders = LOADERS_EARLY
    modules: list[ModuleRecord] = []
    for index, record in enumerate(records):
        if record.encoding == 2 and release is None:
            raise BunUnpackError("Encoding 2 needs a corroborated runtime version")
        if release is None and record.loader >= 7 and stride not in (28, 32):
            raise BunUnpackError("Loader enum needs a corroborated runtime version")
        if record.loader >= len(loaders):
            return []
        side = record.side
        if stride == 36:
            # Until 1.2.17 this byte was arbitrary padding, not an enum.
            if release is None and side == 1:
                raise BunUnpackError("Ambiguous module side: could be legacy padding")
            if release is None or release < (1, 2, 17):
                side = 0
        if side > 1:
            return []
        modules.append(
            ModuleRecord(
                record.path,
                record.contents,
                record.sourcemap,
                record.bytecode,
                ("binary", "latin1", "utf16" if utf16 else "utf8")[record.encoding],
                loaders[record.loader],
                ("none", "esm", "cjs")[record.module_format],
                ("server", "client")[side],
                index == entry_id,
                record.module_info,
                record.bytecode_origin_path,
            )
        )
    return [tuple(modules)]
