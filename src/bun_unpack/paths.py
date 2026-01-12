from __future__ import annotations

"""Path normalization and safe filesystem joins.

The Bun standalone module graph uses virtual paths (e.g. `/$bunfs/`) and
sourcemaps may contain absolute paths, URLs, and Windows-style paths.

This module provides:
- Normalizers to turn those inputs into stable, relative paths.
- A `safe_join()` helper that prevents directory traversal when writing outputs.
"""

import re
from pathlib import Path, PurePosixPath

from .errors import UnsafePathError

TRAILER = b"\n---- Bun! ----\n"

BUNFS_PREFIX_UNIX = "/$bunfs/"
BUNFS_PREFIX_WINDOWS = "B:\\~BUN\\"
BUNFS_PREFIX_WINDOWS_URL = "B:/~BUN/"


def _strip_known_prefixes(path: str) -> str:
    """Remove Bun's virtual FS prefixes and the optional `root/` prefix."""

    for prefix in (BUNFS_PREFIX_UNIX, BUNFS_PREFIX_WINDOWS, BUNFS_PREFIX_WINDOWS_URL):
        if path.startswith(prefix):
            path = path[len(prefix) :]
            break

    if path.startswith("root/") or path.startswith("root\\"):
        path = path[5:]

    return path


def normalize_module_path(virtual_path: str) -> str:
    """Normalize a standalone module virtual path into a relative POSIX path."""

    path = _strip_known_prefixes(virtual_path)
    path = path.replace("\\", "/")
    path = path.lstrip("/")
    return path


_DRIVE_LETTER = re.compile(r"^[A-Za-z]:$")


def normalize_relative_path(untrusted_path: str) -> str:
    """Normalize an untrusted path into a safe, relative, POSIX-like path.

    - Removes URL schemes ("file://", "webpack://", etc.)
    - Normalizes separators to '/'
    - Resolves '.' and '..' segments
    - Strips Windows drive letters

    Raises UnsafePathError for empty paths or any attempt to escape above the
    output directory.
    """

    path = _strip_known_prefixes(untrusted_path)

    if "://" in path:
        path = path.split("://", 1)[1]

    path = path.replace("\\", "/")
    path = path.lstrip("/")

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
