from __future__ import annotations

"""Standalone module graph parsing.

Takes the embedded payload extracted from an executable and produces a list of
`ExtractedFile` entries describing the virtual path, bytes, and (optional)
embedded sourcemap/bytecode blobs.
"""

from .paths import normalize_module_path
from .sourcemap import parse_serialized_sourcemap
from .types import CompiledModuleGraphFile, ExtractedFile, Offsets


def parse_modules(data: bytes, offsets: Offsets) -> list[tuple[CompiledModuleGraphFile, int]]:
    modules_data = offsets.modules_ptr.slice(data)
    num_modules = len(modules_data) // CompiledModuleGraphFile.SIZE

    modules: list[tuple[CompiledModuleGraphFile, int]] = []
    for i in range(num_modules):
        module = CompiledModuleGraphFile.from_bytes(modules_data, i * CompiledModuleGraphFile.SIZE)
        modules.append((module, i))

    return modules


def extract_files(data: bytes, offsets: Offsets) -> list[ExtractedFile]:
    modules = parse_modules(data, offsets)
    extracted: list[ExtractedFile] = []

    for module, idx in modules:
        virtual_path = module.name.slice_str(data)
        real_path = normalize_module_path(virtual_path)
        contents = module.contents.slice(data)

        if contents and contents[-1:] == b"\x00":
            contents = contents[:-1]

        sourcemap = None
        if module.sourcemap.length > 0:
            sourcemap_data = module.sourcemap.slice(data)
            sourcemap = parse_serialized_sourcemap(sourcemap_data)

        bytecode = None
        if module.bytecode.length > 0:
            bytecode = module.bytecode.slice(data)

        extracted.append(
            ExtractedFile(
                virtual_path=virtual_path,
                real_path=real_path,
                contents=contents,
                sourcemap=sourcemap,
                bytecode=bytecode,
                encoding=module.encoding,
                loader=module.loader,
                module_format=module.module_format,
                side=module.side,
                is_entry_point=(idx == offsets.entry_point_id),
            )
        )

    return extracted
