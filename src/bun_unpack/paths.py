from __future__ import annotations

"""Path normalization and safe filesystem joins.

The Bun standalone module graph uses virtual paths (e.g. `/$bunfs/`) and
sourcemaps may contain absolute paths, URLs, and Windows-style paths.

This module is the only place that interprets an untrusted path string:
- `normalize_module_path()` turns a module's virtual path into an output path.
- `source_reference()` turns a sourcemap reference into its producer reference
  and its projected output path.
- `safe_join()` prevents directory traversal when writing outputs.
"""

import posixpath
import re
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit, urlunsplit

from .errors import UnsafePathError

TRAILER = b"\n---- Bun! ----\n"

BUNFS_PREFIX_LEGACY = "compiled://"
BUNFS_PREFIX_UNIX = "/$bunfs/"
BUNFS_PREFIX_WINDOWS = "B:\\~BUN\\"
BUNFS_PREFIX_WINDOWS_URL = "B:/~BUN/"

_DRIVE_LETTER = re.compile(r"^[A-Za-z]:$")


def _strip_known_prefixes(path: str) -> str:
    """Remove Bun's virtual FS prefixes and the optional `root/` prefix."""

    for prefix in (
        BUNFS_PREFIX_LEGACY,
        BUNFS_PREFIX_UNIX,
        BUNFS_PREFIX_WINDOWS,
        BUNFS_PREFIX_WINDOWS_URL,
    ):
        if path.startswith(prefix):
            path = path[len(prefix) :]
            if path.startswith(("root/", "root\\")):
                path = path[5:]
            return path

    return path


def _require_text(path: str) -> None:
    if "\x00" in path:
        raise UnsafePathError("Path contains a NUL byte")


def normalize_module_path(virtual_path: str) -> str:
    """Normalize a standalone module virtual path into a relative POSIX path."""

    path = _strip_known_prefixes(virtual_path)
    return normalize_relative_path(path.replace("\\", "/").lstrip("/"))


def normalize_relative_path(untrusted_path: str) -> str:
    """Normalize an untrusted path into a safe, relative, POSIX-like path.

    - Removes URL schemes ("file://", "webpack://", etc.)
    - Normalizes separators to '/'
    - Resolves '.' and '..' segments
    - Strips Windows drive letters
    - Rejects embedded NUL bytes

    Raises UnsafePathError for empty paths or any attempt to escape above the
    output directory.
    """

    _require_text(untrusted_path)
    path = _strip_known_prefixes(untrusted_path)

    if "://" in path:
        path = path.split("://", 1)[1]

    path = path.replace("\\", "/").lstrip("/")

    parts: list[str] = []
    attempted_escape = False
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if _DRIVE_LETTER.match(part):
            continue
        if part == "..":
            if parts:
                parts.pop()
            else:
                attempted_escape = True
            continue
        parts.append(part)

    if attempted_escape:
        raise UnsafePathError(f"Path attempts to escape root: {untrusted_path!r}")

    if not parts:
        raise UnsafePathError(f"Unsafe/empty path: {untrusted_path!r}")

    return str(PurePosixPath(*parts))


def source_reference(path: str, root: str) -> tuple[str, str]:
    """Resolve one sourcemap reference into (producer reference, output path).

    `root` is the map's `sourceRoot`, applied before normalization. A leading
    `../` anchors to the producer's bundle directory rather than the output root,
    so it is dropped instead of being treated as traversal. URL references keep
    their scheme and authority in the reference and contribute their path to the
    output tree.
    """

    _require_text(path)
    _require_text(root)
    path = path.replace("\\", "/")
    root = root.replace("\\", "/")
    if root and not path.startswith("/") and ":" not in path:
        path = posixpath.join(root, path)

    if "://" in path:
        try:
            parsed = urlsplit(path)
        except ValueError as error:
            raise UnsafePathError("Invalid source URL") from error
        try:
            decoded = unquote(parsed.path, errors="strict")
        except UnicodeError as error:
            raise UnsafePathError("Invalid UTF-8 source URL") from error
        normalized = posixpath.normpath(decoded)
        reference = urlunsplit(
            (parsed.scheme, parsed.netloc, normalized, parsed.query, parsed.fragment)
        )
        projected = posixpath.join(parsed.netloc, normalized.lstrip("/"))
    else:
        reference = posixpath.normpath(path)
        projected = reference

    while projected.startswith("../"):
        projected = projected[3:]
    return reference, normalize_relative_path(projected)


def safe_join(base: Path, relative_path: str) -> Path:
    """Join an untrusted path to a base directory without allowing traversal."""

    rel = normalize_relative_path(relative_path)

    # Convert posix-ish path to platform path safely.
    joined = base.joinpath(*PurePosixPath(rel).parts)

    base_resolved = base.resolve(strict=False)
    joined_resolved = joined.resolve(strict=False)

    if not joined_resolved.is_relative_to(base_resolved):
        raise UnsafePathError(f"Path escapes output directory: {relative_path!r}")

    return joined
