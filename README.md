# bun-unpack

[![CI](https://github.com/xpcmdshell/bun-unpack/actions/workflows/ci.yml/badge.svg)](https://github.com/xpcmdshell/bun-unpack/actions/workflows/ci.yml)
[![Python 3.15+](https://img.shields.io/badge/python-3.15+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Extract original source files from Bun-compiled executables.

## How It Works

When Bun compiles a project with `bun build --compile`, it embeds a module graph containing all bundled sources, their metadata, and sourcemaps into the resulting executable. This tool locates and parses that embedded data to reconstruct the original source files.

For a detailed walkthrough of the binary format and extraction process, see the blog post: **[Dissecting Droid: Reversing Bun Executables](https://0day.gg/blog/dissecting-droid-reversing-bun-executables/)**

## Install

```bash
uv tool install git+ssh://git@github.com/xpcmdshell/bun-unpack.git
```

## Usage

```bash
bun-unpack /path/to/executable
bun-unpack /path/to/executable -o out/
bun-unpack /path/to/executable --bundle -o out/
```

## Development

Use Python 3.15 or newer and uv 0.13.5 or newer.
Install Bun to run the compiler and installed-package integration tests.

```bash
git clone git@github.com:xpcmdshell/bun-unpack.git
cd bun-unpack
uv sync --locked
uv run --locked bun-unpack /path/to/executable
uv run --locked prek install
uv run --locked prek run --all-files
uv run --locked python -m pytest
uv build
```

Build the historical compatibility corpus before running the full recovery checks:

```bash
uv run --locked python -m tools.build_compatibility
uv run --locked python -m pytest
```

The checks use Ruff for formatting and linting, and ty for type checking.
The distribution test rebuilds the source archive and exercises the installed CLI in an isolated environment.

## License

MIT
