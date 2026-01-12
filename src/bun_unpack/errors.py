from __future__ import annotations


class BunUnpackError(Exception):
    """Base exception for bun-unpack."""


class UnsafePathError(BunUnpackError):
    """Raised when an embedded path is unsafe to write to disk."""
