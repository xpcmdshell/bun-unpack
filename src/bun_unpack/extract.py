from __future__ import annotations

"""Extraction helpers.

There are two related extraction modes:

- Source recovery (default): walk embedded sourcemaps and reconstruct the original
  project structure by writing each `sourcesContent` entry to disk.
- Bundle extraction (`--bundle`): write the bundled output and (if present) an
  externalized `.map` file next to it.

This module is intentionally filesystem-focused and does not parse binaries.
"""

import json
import sys
from pathlib import Path

from .errors import UnsafePathError
from .paths import safe_join
from .types import ExtractedFile, Loader


def extract_sources(files: list[ExtractedFile], output_dir: Path, *, verbose: bool = False) -> int:
    """Extract original sources from embedded sourcemaps.

    Returns the number of files written.
    """

    extracted_count = 0

    for entry in files:
        if entry.sourcemap is None:
            continue

        sourcemap = entry.sourcemap
        if len(sourcemap.sources) != len(sourcemap.sources_content):
            continue

        for source_path, content in zip(sourcemap.sources, sourcemap.sources_content):
            if not content:
                continue

            try:
                out_path = safe_join(output_dir, source_path)
            except UnsafePathError as e:
                if verbose:
                    print(f"  SKIP: {source_path} ({e})", file=sys.stderr)
                continue

            try:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(content, encoding="utf-8")
                extracted_count += 1
                if verbose:
                    print(f"  {out_path.relative_to(output_dir)}")
            except OSError as e:
                if verbose:
                    print(f"  FAILED: {source_path} - {e}", file=sys.stderr)

    return extracted_count


def extract_assets(files: list[ExtractedFile], output_dir: Path, *, verbose: bool = False) -> int:
    """Extract embedded non-JS assets.

    Returns the number of files written.

    Note: this intentionally does *not* attempt to decode `base64:` or `data:`
    payloads; it writes the embedded bytes as-is.
    """

    extracted_count = 0

    for entry in files:
        if entry.loader not in (Loader.FILE, Loader.BASE64, Loader.DATAURL):
            continue
        if not entry.real_path:
            continue

        try:
            out_path = safe_join(output_dir, entry.real_path)
        except UnsafePathError as e:
            if verbose:
                print(f"  SKIP: {entry.real_path} ({e})", file=sys.stderr)
            continue

        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(entry.contents)
            extracted_count += 1

            if verbose:
                rel = out_path.relative_to(output_dir)
                print(f"  {rel} ({len(entry.contents)} bytes)")
        except OSError as e:
            if verbose:
                print(f"  FAILED: {entry.real_path} - {e}", file=sys.stderr)

    return extracted_count


def extract_bundle(files: list[ExtractedFile], output_dir: Path) -> None:
    """Extract the bundled output files.

    If a file has an embedded sourcemap, write it as a sibling `.map` file.
    """

    for entry in files:
        if not entry.real_path:
            continue

        try:
            out_path = safe_join(output_dir, entry.real_path)
        except UnsafePathError:
            continue

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(entry.contents)

        if entry.sourcemap is None:
            continue

        sourcemap_path = out_path.with_name(out_path.name + ".map")
        sourcemap_json = {
            "version": 3,
            "sources": entry.sourcemap.sources,
            "sourcesContent": entry.sourcemap.sources_content,
            "mappings": entry.sourcemap.mappings,
            "names": [],
        }
        sourcemap_path.write_text(json.dumps(sourcemap_json, indent=2), encoding="utf-8")
