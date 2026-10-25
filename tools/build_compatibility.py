"""Build the recovery corpus with portable Bun releases in an isolated workspace."""

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import urllib.error
from dataclasses import dataclass
from pathlib import Path

from .bun import (
    isolated_environment,
    portable_bun,
    require_flags,
    sha256,
    validate_version,
)

INPUTS = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "recovery"
VERSIONS = (
    "0.6.0",
    "1.0.0",
    "1.1.0",
    "1.1.22",
    "1.1.29",
    "1.1.30",
    "1.2.0",
    "1.2.4",
    "1.3.0",
    "1.3.4",
    "1.3.9",
    "1.3.14",
    "1.4.2",
)
PROGRAM_SOURCES = (
    "main.ts",
    "src/lib/greeting.ts",
    "src/lib/legacy.cjs",
    "src/features/lazy.ts",
    "src/data/settings.json",
)
ASSETS = ("assets/picture.svg", "assets/binary.png", "assets/empty.svg")
WEB_INPUTS = ("web.ts", "web/client.ts", "web/index.html", "web/styles.css")
# Observed omissions in these specific corpus releases, not a guessed release
# boundary. The original input is still inventoried and the bundle is retained.
EMPTY_ASSET_OMITTED_IN = frozenset({"1.1.0", "1.1.22", "1.1.29", "1.1.30", "1.2.0", "1.2.4"})


def version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def cases_for(version: str) -> dict[str, tuple[str, ...]]:
    cases: dict[str, tuple[str, ...]] = {
        "sources": ("--sourcemap=external",),
        "assets": ("--sourcemap=external",),
    }
    if version_tuple(version) >= (1, 1, 30):
        cases["bytecode"] = ("--sourcemap=external", "--bytecode")
    if version_tuple(version) >= (1, 3, 0):
        cases["splitting"] = ("--sourcemap=external", "--splitting")
        cases["exec-argv"] = ("--sourcemap=external", "--compile-exec-argv=--smol")
        cases["web"] = ("--sourcemap=external",)
    if version_tuple(version) >= (1, 3, 9):
        cases["split-bytecode"] = (
            "--sourcemap=external",
            "--splitting",
            "--bytecode",
            "--format=esm",
        )
    return cases


def record_size_for(version: str) -> int:
    value = version_tuple(version)
    if value < (1, 1, 22):
        return 32
    if value < (1, 1, 30):
        return 28
    if value < (1, 3, 9):
        return 36
    return 52


def _prepare_compiler(
    version: str, bun: Path, environment: dict[str, str]
) -> tuple[dict[str, str], str]:
    """Check the release and return a private environment and advertised flags."""
    validate_version(version)
    environment = dict(environment)
    environment["PATH"] = str(bun.parent) + os.pathsep + environment.get("PATH", "")
    actual = subprocess.check_output(
        [str(bun), "--version"], env=environment, text=True, timeout=30
    ).strip()
    if actual != version:
        raise ValueError(f"Expected Bun {version}, found {actual}")
    help_result = subprocess.run(
        [str(bun), "build", "--help"],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return environment, help_result.stdout + help_result.stderr


def _inputs_for_case(case: str) -> tuple[str, ...]:
    if case == "assets":
        return ("assets.ts", *ASSETS)
    if case == "web":
        return WEB_INPUTS
    return PROGRAM_SOURCES


def _case_fingerprint(
    version: str,
    case: str,
    flags: tuple[str, ...],
    compiler_hash: str,
    consumed_hashes: dict[str, str],
) -> str:
    # Keep the schema marker, input order, and JSON encoding stable for caches.
    return hashlib.sha256(
        json.dumps([2, version, case, flags, compiler_hash, consumed_hashes]).encode()
    ).hexdigest()


def _verify_cached_fixture(output: Path, fingerprint: str) -> bool:
    manifest_path = output / "expected.json"
    if not manifest_path.exists():
        return False
    existing = json.loads(manifest_path.read_text(encoding="utf-8"))
    executable = output / existing["executable"]
    if (
        existing["fingerprint"] != fingerprint
        or sha256(executable) != existing["executable_sha256"]
    ):
        raise ValueError(
            f"Stale or changed fixture; remove its directory and rebuild: {output}"
        )
    return True


def _build_case(
    bun: Path,
    case: str,
    flags: tuple[str, ...],
    executable: Path,
    temporary_root: Path,
    environment: dict[str, str],
) -> None:
    output = executable.parent
    output.mkdir(parents=True, exist_ok=False)
    entrypoint = {"assets": "assets.ts", "web": "web.ts"}.get(case, "main.ts")
    with tempfile.TemporaryDirectory(dir=temporary_root) as temporary:
        source = Path(temporary) / "source"
        shutil.copytree(INPUTS, source)
        command = [
            str(bun),
            "build",
            "--compile",
            entrypoint,
            "--outfile",
            executable.name,
            *flags,
        ]
        with (output / "build.log").open("w", encoding="utf-8") as log:
            subprocess.run(
                command,
                cwd=source,
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                check=True,
                timeout=120,
            )
        shutil.move(str(source / executable.name), executable)


@dataclass
class _RecoveryExpectations:
    sources: dict[str, str]
    assets: list[str]
    transformed_inputs: dict[str, list[str]]
    unavailable_inputs: dict[str, str]
    source_warnings: list[str]


def _web_asset_hashes(executable: Path, environment: dict[str, str]) -> list[str]:
    # Independent oracle: ask our own fixture for the hashes of Bun's
    # transformed HTML/CSS assets. Never run an executable being unpacked.
    result = subprocess.run(
        [str(executable), "--artifact-manifest"],
        cwd=executable.parent,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    oracle = json.loads(result.stdout)
    asset_hashes = [
        entry["sha256"] for entry in oracle if entry["name"].endswith((".html", ".css"))
    ]
    if len(asset_hashes) != 2:
        raise ValueError(f"Expected HTML and CSS from fixture's own asset inventory: {oracle}")
    (executable.parent / "compiler-assets.json").write_text(
        json.dumps(oracle, indent=2) + "\n", encoding="utf-8"
    )
    return asset_hashes


def _expected_recovery(
    version: str,
    case: str,
    input_hashes: dict[str, str],
    executable: Path,
    environment: dict[str, str],
) -> _RecoveryExpectations:
    """Describe observed corpus behavior without consulting the production decoder."""
    sources = list(PROGRAM_SOURCES)
    assets = list(ASSETS) if case == "assets" else []
    transformed_inputs: dict[str, list[str]] = {}
    unavailable_inputs: dict[str, str] = {}
    source_warnings: list[str] = []
    if case == "assets":
        sources = ["assets.ts"]
        # Linux 0.6.0/1.0.0 also omit the empty source-map entry that
        # their macOS builds retain. Verified in native CI binaries:
        # three module records, three map sources, empty_default = {}.
        empty_asset_omitted = version in EMPTY_ASSET_OMITTED_IN or (
            platform.system() == "Linux" and version in {"0.6.0", "1.0.0"}
        )
        if empty_asset_omitted:
            assets.remove("assets/empty.svg")
            unavailable_inputs["assets/empty.svg"] = (
                "Compiler omitted the empty asset's module and source-map entry"
            )
            transformed_inputs["assets/empty.svg"] = [
                "assets/empty.svg",
                "var empty_default = {};",
            ]
        if version_tuple(version) < (1, 1, 22):
            # The old module table omits the empty asset, but its complete
            # contents survive in the legacy sourcemap as an original source.
            if not empty_asset_omitted:
                assets.remove("assets/empty.svg")
                sources.append("assets/empty.svg")
            source_warnings.append(
                f"Non-text source-map copy of {Path('assets/binary.png')} ignored; embedded assets retained"
            )
    elif case == "web":
        sources = ["web.ts", "web/client.ts"]
        unavailable_inputs["web/index.html"] = (
            "Compiler retains transformed HTML, not original formatting"
        )
        unavailable_inputs["web/styles.css"] = (
            "Compiler retains transformed CSS, not original formatting"
        )
    elif version_tuple(version) >= (1, 1, 22):
        # Bun omits JSON sourcesContent in its compact source maps. Preserve
        # the bundle's representation; do not pretend its formatting survived.
        sources.remove("src/data/settings.json")
        transformed_inputs["src/data/settings.json"] = ["JSON_MAGIC"]
    asset_hashes = [input_hashes[path] for path in assets]
    if case == "web":
        asset_hashes = _web_asset_hashes(executable, environment)
    return _RecoveryExpectations(
        sources={path: input_hashes[path] for path in sources},
        assets=asset_hashes,
        transformed_inputs=transformed_inputs,
        unavailable_inputs=unavailable_inputs,
        source_warnings=source_warnings,
    )


def _write_manifest(
    version: str,
    case: str,
    executable: Path,
    compiler_hash: str,
    fingerprint: str,
    input_hashes: dict[str, str],
    consumed_hashes: dict[str, str],
    expected: _RecoveryExpectations,
) -> None:
    manifest = {
        "version": version,
        "case": case,
        "record_size": record_size_for(version),
        "compiler_sha256": compiler_hash,
        "fingerprint": fingerprint,
        "executable": executable.name,
        "executable_sha256": sha256(executable),
        "sources": expected.sources,
        "assets": expected.assets,
        "consumed_inputs": consumed_hashes,
        "transformed_inputs": expected.transformed_inputs,
        "unavailable_inputs": expected.unavailable_inputs,
        "source_warnings": expected.source_warnings,
        "input_sha256": input_hashes,
    }
    (executable.parent / "expected.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )


def build_version(
    version: str, bun: Path, workspace: Path, environment: dict[str, str]
) -> None:
    environment, compiler_help = _prepare_compiler(version, bun, environment)
    compiler_hash = sha256(bun)
    input_hashes = {
        path.relative_to(INPUTS).as_posix(): sha256(path)
        for path in sorted(INPUTS.rglob("*"))
        if path.is_file()
    }
    for case, flags in cases_for(version).items():
        require_flags(compiler_help, ("--compile", *flags))
        output = workspace / "fixtures" / version / case
        consumed_hashes = {path: input_hashes[path] for path in _inputs_for_case(case)}
        fingerprint = _case_fingerprint(version, case, flags, compiler_hash, consumed_hashes)
        executable_name = "sample.exe" if platform.system() == "Windows" else "sample"
        executable = output / executable_name
        if _verify_cached_fixture(output, fingerprint):
            print(f"Verified cached {version}/{case}", flush=True)
        else:
            _build_case(bun, case, flags, executable, workspace / "temporary", environment)
            print(f"Built {version}/{case}", flush=True)

        expected = _expected_recovery(version, case, input_hashes, executable, environment)
        _write_manifest(
            version,
            case,
            executable,
            compiler_hash,
            fingerprint,
            input_hashes,
            consumed_hashes,
            expected,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path("build/compatibility"))
    parser.add_argument(
        "--version", action="append", dest="versions", help="Repeat to select releases"
    )
    parser.add_argument(
        "--import-runtimes", type=Path, help="Reuse <directory>/<version>/bun portable builds"
    )
    parser.add_argument(
        "--bun", type=Path, help="Use an existing compiler; requires one --version"
    )
    args = parser.parse_args(argv)
    versions = args.versions or VERSIONS
    if args.bun is not None and len(versions) != 1:
        parser.error("--bun requires exactly one --version")
    workspace = args.workspace.resolve()
    environment = isolated_environment(workspace)
    for version in versions:
        validate_version(version)
        if args.bun is not None:
            found = shutil.which(str(args.bun))
            if found is None:
                parser.error(f"Compiler not found: {args.bun}")
            bun = Path(found).resolve()
        else:
            try:
                bun = portable_bun(version, workspace, args.import_runtimes)
            except urllib.error.HTTPError as error:
                print(
                    f"Skipped {version}: no Bun release for this platform (HTTP {error.code})"
                )
                continue
        build_version(version, bun, workspace, environment)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
