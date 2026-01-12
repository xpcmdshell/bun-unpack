# bun-unpack

[![CI](https://github.com/xpcmdshell/bun-unpack/actions/workflows/ci.yml/badge.svg)](https://github.com/xpcmdshell/bun-unpack/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
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

```bash
git clone git@github.com:xpcmdshell/bun-unpack.git
cd bun-unpack
uv sync --frozen
uv run bun-unpack /path/to/executable
uv run python -m unittest discover -s tests -p "test_*.py" -v
```

## License

MIT
