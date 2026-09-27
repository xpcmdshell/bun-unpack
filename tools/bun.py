"""Portable compiler acquisition and isolation for repository tests."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import tempfile
import urllib.request
import zipfile
from pathlib import Path

MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024


def validate_version(version: str) -> None:
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None:
        raise ValueError(f"Expected an exact stable Bun release, got {version!r}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_flags(help_text: str, flags: tuple[str, ...]) -> None:
    """Old compilers silently accept unknown options; require advertised flags."""
    advertised = set(re.findall(r"(?<!\S)--[a-z][a-z-]*", help_text))
    missing = {flag.partition("=")[0] for flag in flags} - advertised
    if missing:
        raise ValueError(
            f"Compiler does not advertise required flags: {', '.join(sorted(missing))}"
        )


def isolated_environment(workspace: Path) -> dict[str, str]:
    environment = os.environ.copy()
    for key in ("BUN_OPTIONS", "NODE_OPTIONS"):
        environment.pop(key, None)
    for key, directory in {
        "HOME": "home",
        "USERPROFILE": "home",
        "BUN_INSTALL": "bun-home",
        "BUN_INSTALL_CACHE_DIR": "cache",
        "BUN_RUNTIME_TRANSPILER_CACHE_PATH": "cache",
        "XDG_CACHE_HOME": "cache",
        "BUN_TMPDIR": "temporary",
        "TMPDIR": "temporary",
        "TEMP": "temporary",
        "TMP": "temporary",
    }.items():
        path = workspace / directory
        path.mkdir(parents=True, exist_ok=True)
        environment[key] = str(path)
    return environment


def portable_bun(version: str, workspace: Path, import_dir: Path | None = None) -> Path:
    validate_version(version)
    systems = {"Darwin": "darwin", "Linux": "linux", "Windows": "windows"}
    architectures = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x64", "AMD64": "x64"}
    try:
        system = systems[platform.system()]
        architecture = architectures[platform.machine()]
    except KeyError as error:
        raise ValueError("No portable Bun download configured for this host") from error
    name = "bun.exe" if system == "windows" else "bun"
    destination = workspace / "runtimes" / version / name
    if not destination.resolve().is_relative_to(workspace.resolve()):
        raise ValueError("Portable runtime path escapes the workspace")
    if destination.is_file():
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_root = workspace / "temporary"
    temporary_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=temporary_root) as temporary:
        staged = Path(temporary) / name
        if import_dir is not None and (import_dir / version / name).is_file():
            shutil.copy2(import_dir / version / name, staged)
        else:
            archive_name = f"bun-{system}-{architecture}"
            url = f"https://github.com/oven-sh/bun/releases/download/bun-v{version}/{archive_name}.zip"
            print(f"Downloading portable Bun {version} to {destination.parent}", flush=True)
            archive = Path(temporary) / "bun.zip"
            with urllib.request.urlopen(url, timeout=60) as response, archive.open("wb") as output:
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise ValueError("Portable Bun download exceeds size limit")
                    output.write(chunk)
            with zipfile.ZipFile(archive) as bundle:
                member = bundle.getinfo(f"{archive_name}/{name}")
                if member.file_size > MAX_DOWNLOAD_BYTES:
                    raise ValueError("Portable Bun executable exceeds size limit")
                with bundle.open(member) as source, staged.open("wb") as output:
                    shutil.copyfileobj(source, output)
        staged.chmod(0o755)
        os.replace(staged, destination)
    return destination
