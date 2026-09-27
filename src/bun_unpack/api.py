"""The public extraction API. Container and serialization details stay below it."""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ._model import FormatInfo, Limits
from .errors import BunUnpackError
from .formats import load_graph
from .paths import normalize_relative_path, safe_join
from .recovery import Recovery


@dataclass(frozen=True)
class RecoveredFile:
    path: Path
    kind: str
    size: int
    embedded_path: str | None
    relative_path: Path


@dataclass(frozen=True)
class UnpackReport:
    files: tuple[RecoveredFile, ...]
    warnings: tuple[str, ...]
    info: FormatInfo
    dry_run: bool = False

    @property
    def source_count(self) -> int:
        return sum(file.kind == "source" for file in self.files)

    @property
    def asset_count(self) -> int:
        return sum(file.kind == "asset" for file in self.files)

    @property
    def bundle_count(self) -> int:
        return sum(file.kind == "bundle" for file in self.files)

    @property
    def total_bytes(self) -> int:
        return sum(file.size for file in self.files)


class BunUnpacker:
    """Inspect a Bun executable without executing it, then recover its files.

    Source mode restores available sourcesContent byte-for-byte, recovers assets,
    and retains bundled code under `_bundles/` for inputs whose original form was
    not embedded. Bundle mode exports modules, maps, and bytecode metadata.

    Extraction validates and stages all artifacts before publishing them. Existing
    identical files are reusable; different files are never silently overwritten.
    """

    def __init__(self, executable: str | Path, *, limits: Limits | None = None) -> None:
        self.limits = limits or Limits()
        try:
            self.executable = Path(executable).resolve(strict=True)
            self._identity = self.executable.stat()
            self._graph = load_graph(self.executable, self.limits)
        except OSError as error:
            raise BunUnpackError(f"Cannot read executable: {error}") from error

    @property
    def info(self) -> FormatInfo:
        return self._graph.format

    def _check_executable(self) -> None:
        current = self.executable.stat()
        for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns"):
            if getattr(current, field) != getattr(self._identity, field):
                raise BunUnpackError("Executable changed after it was inspected")

    def unpack(
        self,
        output_dir: str | Path,
        *,
        mode: str = "sources",
        include_assets: bool = True,
        dry_run: bool = False,
    ) -> UnpackReport:
        if mode not in {"sources", "bundle"}:
            raise ValueError("mode must be 'sources' or 'bundle'")
        try:
            return self._unpack(Path(output_dir).resolve(), mode, include_assets, dry_run)
        except OSError as error:
            raise BunUnpackError(f"Cannot extract files: {error}") from error

    def _unpack(self, output: Path, mode: str, include_assets: bool, dry_run: bool) -> UnpackReport:
        self._check_executable()
        recovery = Recovery(self._graph, self.limits, mode, include_assets)
        files: dict[str, RecoveredFile] = {}
        identities: dict[str, str] = {}
        total_bytes = 0
        # Staging prevents a corrupt late module from leaving a successful-looking
        # partial extraction. Keep the staging tree on the destination filesystem.
        if not dry_run:
            output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix=".bun-unpack-", dir=None if dry_run else output.parent
        ) as temporary:
            staging = Path(temporary)
            for artifact in recovery.artifacts():
                relative = normalize_relative_path(artifact.path)
                target = safe_join(output, relative)
                identity = hashlib.sha256(artifact.contents).hexdigest()
                if relative in identities:
                    if identities[relative] != identity:
                        raise BunUnpackError(f"Conflicting embedded contents for {relative}")
                    continue
                total_bytes += len(artifact.contents)
                if len(artifact.contents) > self.limits.max_file_bytes:
                    raise BunUnpackError(f"Recovered file exceeds size limit: {relative}")
                if total_bytes > self.limits.max_total_bytes:
                    raise BunUnpackError("Total extraction size limit exceeded")
                identities[relative] = identity
                files[relative] = RecoveredFile(
                    target,
                    artifact.kind,
                    len(artifact.contents),
                    artifact.embedded_path,
                    Path(relative),
                )
                if not dry_run:
                    staged = safe_join(staging, relative)
                    if staged.exists():
                        raise BunUnpackError(f"Filesystem path collision: {relative}")
                    staged.parent.mkdir(parents=True, exist_ok=True)
                    staged.write_bytes(artifact.contents)

            self._check_executable()
            if not dry_run:
                self._publish(output, staging, files, identities)
        return UnpackReport(
            tuple(files.values()), tuple(dict.fromkeys(recovery.warnings)), self.info, dry_run
        )

    @staticmethod
    def _publish(
        output: Path,
        staging: Path,
        files: dict[str, RecoveredFile],
        identities: dict[str, str],
    ) -> None:
        if output.exists() and not output.is_dir():
            raise BunUnpackError(f"Output is not a directory: {output}")
        # Check every destination before moving the first file.
        for relative in files:
            target = safe_join(output, relative)
            parent = target.parent
            while parent != output:
                if parent.exists() and not parent.is_dir():
                    raise BunUnpackError(f"Output parent is not a directory: {parent}")
                parent = parent.parent
            if target.exists():
                if not target.is_file():
                    raise BunUnpackError(f"Output path is not a file: {target}")
                if hashlib.sha256(target.read_bytes()).hexdigest() != identities[relative]:
                    raise BunUnpackError(f"Refusing to overwrite a different file: {target}")
        if files and not output.exists():
            os.replace(staging, output)
            return
        for relative in files:
            target = safe_join(output, relative)
            if target.exists():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(safe_join(staging, relative), target)
