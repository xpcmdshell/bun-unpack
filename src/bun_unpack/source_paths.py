"""Assign distinct output paths to sourcemap references that would collide.

Path interpretation lives in `paths.source_reference`; this module only decides
where each resolved reference is written. Distinct producer references that
project onto the same output path are namespaced rather than overwritten or
silently merged.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict

from .errors import BunUnpackError
from .paths import source_reference


class SourceLayout:
    def __init__(self, references: list[tuple[str, str]]) -> None:
        groups: dict[str, set[str]] = defaultdict(set)
        for path, root in references:
            reference, projected = source_reference(path, root)
            groups[projected].add(reference)

        self._paths: dict[str, str] = {}
        self.warnings: list[str] = []
        for projected, origins in groups.items():
            for reference in sorted(origins):
                if len(origins) == 1:
                    self._paths[reference] = projected
                    continue
                identity = hashlib.sha256(reference.encode("utf-8")).hexdigest()[:16]
                destination = f"_source_roots/{identity}/{projected}"
                self._paths[reference] = destination
                self.warnings.append(
                    f"Ambiguous source reference {reference!r} recovered as {destination}"
                )

    def path(self, path: str, root: str) -> str:
        reference, _ = source_reference(path, root)
        try:
            return self._paths[reference]
        except KeyError as error:
            raise BunUnpackError("Source metadata changed during recovery") from error
