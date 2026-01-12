from __future__ import annotations

"""Command-line interface for bun-unpack.

Default mode reconstructs the original project structure from embedded
sourcemaps. Use `--bundle` to extract the bundled output instead.
"""

import argparse
import sys
from pathlib import Path

from .binary import extract_embedded_data
from .extract import extract_assets, extract_bundle, extract_sources
from .module_graph import extract_files
from .types import Loader


def build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        description="Extract original source files from Bun compiled executables",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    bun-unpack myapp -o src/         # Extract sources to src/
    bun-unpack myapp                 # Extract to myapp_src/
    bun-unpack myapp -n              # Dry run - list files
    bun-unpack myapp --bundle -o out # Extract raw bundle instead
        """,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parser.add_argument("executable", help="Path to Bun compiled executable")
    parser.add_argument("-o", "--output", dest="output_dir", help="Output directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="List each file")
    parser.add_argument("-n", "--dry-run", action="store_true", help="List files without extracting")
    parser.add_argument(
        "--bundle",
        action="store_true",
        help="Extract raw bundled JS + sourcemaps instead of original sources",
    )
    parser.add_argument(
        "--no-assets",
        action="store_true",
        help="Don't extract embedded assets (images, audio, etc.)",
    )

    args = parser.parse_args(argv)

    exe_path = Path(args.executable)
    if not exe_path.exists():
        print(f"Error: {exe_path} not found", file=sys.stderr)
        return 1

    default_suffix = "_bundle" if args.bundle else "_src"
    output_dir = Path(args.output_dir) if args.output_dir else Path(f"{exe_path.stem}{default_suffix}")

    result = extract_embedded_data(exe_path)
    if not result:
        print("Error: No embedded Bun module graph found", file=sys.stderr)
        return 1

    embedded_data, offsets, _fmt = result
    files = extract_files(embedded_data, offsets)

    source_count = sum(len(f.sourcemap.sources) for f in files if f.sourcemap)
    asset_count = sum(1 for f in files if f.loader in (Loader.FILE, Loader.BASE64, Loader.DATAURL))

    if args.dry_run:
        if args.bundle:
            print(f"Would extract {len(files)} bundled files to {output_dir}/")
            for f in files:
                marker = " [entry]" if f.is_entry_point else ""
                print(f"  {f.real_path} ({len(f.contents)} bytes){marker}")
        else:
            print(f"Would extract {source_count} source files to {output_dir}/")
            if not args.no_assets and asset_count:
                print(f"Would extract {asset_count} assets")
        return 0

    output_dir.mkdir(parents=True, exist_ok=True)

    if args.bundle:
        extract_bundle(files, output_dir)
        print(f"Extracted {len(files)} bundled files to {output_dir}/")
        return 0

    count = extract_sources(files, output_dir, verbose=args.verbose)
    print(f"Extracted {count} source files to {output_dir}/")

    if not args.no_assets and asset_count:
        asset_dir = output_dir / "_assets"
        acount = extract_assets(files, asset_dir, verbose=args.verbose)
        if acount:
            print(f"Extracted {acount} assets to {asset_dir}/")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
