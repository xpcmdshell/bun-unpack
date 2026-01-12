# bun-unpack

Extract original source files from Bun-compiled executables by reconstructing sources from the embedded module graph + sourcemaps.

## Install

```bash
uv tool install git+ssh://git@github.com/xpcmdshell/bun-unpack.git
```

This installs `bun-unpack` globally via uv's tool management.

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

## Notes

- This tool expects a Bun executable produced via Bun's compile feature.
- Output paths are derived from sourcemaps; some builds may include absolute paths.
