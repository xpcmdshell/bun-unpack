"""Command-line presentation of the public BunUnpacker API."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .api import BunUnpacker
from .errors import BunUnpackError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Recover source files and assets from Bun compiled executables",
    )
    parser.add_argument("executable", type=Path, help="Bun executable to inspect without running")
    parser.add_argument("-o", "--output", type=Path, dest="output_dir")
    parser.add_argument("-v", "--verbose", action="store_true", help="List recovered files")
    parser.add_argument(
        "-n", "--dry-run", action="store_true", help="Inspect without writing files"
    )
    parser.add_argument(
        "--bundle", action="store_true", help="Export bundles, source maps, and bytecode metadata"
    )
    parser.add_argument("--no-assets", action="store_true", help="Do not extract embedded assets")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    mode = "bundle" if args.bundle else "sources"
    suffix = "_bundle" if args.bundle else "_src"
    output = args.output_dir or Path(args.executable.stem + suffix)
    try:
        result = BunUnpacker(args.executable).unpack(
            output,
            mode=mode,
            include_assets=not args.no_assets,
            dry_run=args.dry_run,
        )
    except BunUnpackError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    for warning in result.warnings:
        print(f"Warning: {warning}", file=sys.stderr)
    if args.verbose or args.dry_run:
        for file in result.files:
            print(f"  {file.relative_path} ({file.size} bytes, {file.kind})")
    action = "Would recover" if args.dry_run else "Recovered"
    print(
        f"{action} {result.source_count} sources, {result.asset_count} assets, "
        f"and {result.bundle_count} bundles to {output}/"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
