"""Identify Bun executable envelopes and decode historical graph profiles."""

from __future__ import annotations

from pathlib import Path

from bun_unpack._model import Limits, ModuleGraph
from bun_unpack.errors import BunUnpackError

from ._containers import candidates
from ._profiles import decode


def load_graph(path: Path, limits: Limits) -> ModuleGraph:
    """Read bounded metadata and return graph records with lazy source ranges."""
    file_size = path.stat().st_size
    found = candidates(path)
    if not found:
        raise BunUnpackError("No Bun module graph section or valid appended trailer found")
    decoded: list[ModuleGraph] = []
    failures: list[str] = []
    for candidate in found:
        try:
            decoded.extend(decode(path, candidate, limits, file_size))
        except BunUnpackError as error:
            failures.append(str(error))
    if not decoded:
        raise BunUnpackError("Unsupported or invalid Bun module graph: " + "; ".join(failures))
    unique: list[ModuleGraph] = []
    for graph in decoded:
        # Structurally distinct profiles can still describe the same recovered graph.
        if not any(
            graph.modules == prior.modules and graph.exec_argv == prior.exec_argv
            for prior in unique
        ):
            unique.append(graph)
    if len(unique) != 1:
        details = ", ".join(
            f"{graph.format.container}/{graph.format.footer_size}/{graph.format.record_size}"
            for graph in unique
        )
        raise BunUnpackError(f"Ambiguous Bun module graph interpretations: {details}")
    return unique[0]


__all__ = ["load_graph"]
