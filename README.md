# bun-unpack

Extract original source files from Bun-compiled executables by reconstructing sources from the embedded module graph + sourcemaps.

## Install

```bash
pip install bun-unpack
```

## Development

```bash
uv sync --frozen
uv run bun-unpack /path/to/executable
uv run python -m unittest discover -s tests -p "test_*.py" -v
```

## Usage

```bash
bun-unpack /path/to/executable
bun-unpack /path/to/executable -o out/
bun-unpack /path/to/executable --bundle -o out/
```

## Notes

- This tool expects a Bun executable produced via Bun's compile feature.
- Output paths are derived from sourcemaps; some builds may include absolute paths.
