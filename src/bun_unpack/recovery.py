"""Recover files without exposing Bun's format variants to filesystem code."""

from __future__ import annotations

import hashlib
import json
import posixpath
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import PurePosixPath

from ._model import Limits, ModuleGraph, ModuleRecord
from .errors import BunUnpackError
from .paths import normalize_module_path
from .source_maps import read_source_map, read_source_paths
from .source_paths import SourceLayout


@dataclass(frozen=True)
class Artifact:
    path: str
    contents: bytes
    kind: str
    embedded_path: str | None = None


def restored_bytes(module: ModuleRecord, embedded: bytes) -> bytes:
    """Return the bytes this file had before Bun packed it.

    Bun stores `contents` as its internal JS string whenever the loader yields a
    string, and `encoding` names that representation. Only `utf16` differs from
    what was packed: every other representation is already the original bytes
    (UTF-8 source, ASCII text, or opaque binary). Nothing else is transformed.
    """
    if module.encoding != "utf16":
        return embedded
    try:
        return embedded.decode("utf-16-le").encode("utf-8")
    except UnicodeError as error:
        raise BunUnpackError(f"Invalid utf16 contents in {module.path}") from error


class Recovery:
    def __init__(self, graph: ModuleGraph, limits: Limits, mode: str, include_assets: bool) -> None:
        self.graph = graph
        self.limits = limits
        self.mode = mode
        self.include_assets = include_assets
        self.warnings: list[str] = []
        self.decoded_bytes = 0
        self.source_count = 0

    def _file_artifact(self, module: ModuleRecord, kind: str) -> Artifact:
        embedded = module.contents.read(self.limits.max_file_bytes)
        return Artifact(
            self._output_path(module), restored_bytes(module, embedded), kind, module.path
        )

    def _output_path(self, module: ModuleRecord) -> str:
        path = normalize_module_path(module.path)
        if self.mode == "sources" and module.sourcemap is not None:
            return posixpath.join("_bundles", path)
        return path

    def _source_layout(self) -> SourceLayout:
        references: list[tuple[str, str]] = []
        metadata_bytes = 0
        path_bytes = 0
        for module in self.graph.modules:
            if module.sourcemap is None:
                continue
            metadata_bytes += module.sourcemap.size
            if metadata_bytes > self.limits.max_total_bytes:
                raise BunUnpackError("Total source-map metadata limit exceeded")
            paths, root = read_source_paths(
                module.sourcemap.read(self.limits.max_file_bytes), self.limits
            )
            for path in paths:
                length = len(path.encode("utf-8")) + len(root.encode("utf-8"))
                path_bytes += length
                if length > self.limits.max_path_bytes or path_bytes > min(
                    self.limits.max_total_path_bytes, self.limits.max_total_bytes
                ):
                    raise BunUnpackError("Source path metadata exceeds limit")
                references.append((path, root))
            if len(references) > self.limits.max_sources:
                raise BunUnpackError("Total source count limit exceeded")
        return SourceLayout(references)

    def artifacts(self) -> Iterator[Artifact]:
        layout = self._source_layout() if self.mode == "sources" else SourceLayout([])
        self.warnings.extend(layout.warnings)
        # Without a source map, `contents` is the artifact itself. With one, the
        # originals are recoverable from the map and `contents` is generated code.
        standalone = [module for module in self.graph.modules if module.sourcemap is None]
        asset_identities: dict[tuple[str, str], list[int]] = {}
        if self.mode == "sources":
            for index, module in enumerate(standalone):
                data = restored_bytes(module, module.contents.read(self.limits.max_file_bytes))
                key = (hashlib.sha256(data).hexdigest(), PurePosixPath(module.path).suffix)
                asset_identities.setdefault(key, []).append(index)
        recovered_assets: set[int] = set()
        asset_suffixes = {PurePosixPath(module.path).suffix for module in standalone}

        for module in self.graph.modules:
            if module.sourcemap is None:
                continue
            bundle_path = self._output_path(module)
            yield self._file_artifact(module, "bundle")
            source_limits = Limits(
                max_file_bytes=self.limits.max_file_bytes,
                max_total_bytes=self.limits.max_total_bytes - self.decoded_bytes,
                max_modules=self.limits.max_modules,
                max_sources=self.limits.max_sources,
                max_path_bytes=self.limits.max_path_bytes,
                max_total_path_bytes=self.limits.max_total_path_bytes,
            )
            source_map = read_source_map(
                module.sourcemap.read(self.limits.max_file_bytes),
                source_limits,
                include_mappings=self.mode == "bundle",
            )
            self.warnings.extend(source_map.warnings)
            self.source_count += len(source_map.sources)
            if self.source_count > self.limits.max_sources:
                raise BunUnpackError("Total source count limit exceeded")
            self.decoded_bytes += sum(
                len(source.content) for source in source_map.sources if source.content is not None
            )

            if self.mode == "bundle":
                encoded_map = (
                    json.dumps(source_map.to_dict(), ensure_ascii=True, indent=2).encode("utf-8")
                    + b"\n"
                )
                yield Artifact(bundle_path + ".map", encoded_map, "sourcemap", module.path)
            else:
                for source in source_map.sources:
                    path = layout.path(source.path, source_map.source_root)
                    if source.content is None:
                        self.warnings.append(
                            f"No sourcesContent for {source.path}; bundled code retained"
                        )
                        continue
                    key = (hashlib.sha256(source.content).hexdigest(), PurePosixPath(path).suffix)
                    matching_assets = asset_identities.get(key, [])
                    if len(matching_assets) == 1:
                        # A byte-exact identity recovers an original asset path
                        # without guessing how Bun generated its hashed filename.
                        recovered_assets.add(matching_assets[0])
                        if self.include_assets:
                            yield Artifact(path, source.content, "asset", source.path)
                        continue
                    try:
                        source.content.decode("utf-8")
                    except UnicodeError:
                        if PurePosixPath(path).suffix in asset_suffixes:
                            self.warnings.append(
                                f"Non-text source-map copy of {source.path} ignored; embedded assets retained"
                            )
                            continue
                    yield Artifact(path, source.content, "source", source.path)

        if self.mode == "bundle":
            for module in self.graph.modules:
                path = self._output_path(module)
                for blob, suffix, kind in (
                    (module.bytecode, ".bytecode", "bytecode"),
                    (module.module_info, ".module-info", "module-info"),
                ):
                    if blob is not None:
                        yield Artifact(
                            path + suffix, blob.read(self.limits.max_file_bytes), kind, module.path
                        )

        if self.include_assets:
            for index, module in enumerate(standalone):
                if index in recovered_assets:
                    continue
                yield self._file_artifact(module, "asset")
