"""Exercise the distributed CLI outside the source checkout."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


def run_command(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        text=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 0, f"{command!r}\n{result.stdout}\n{result.stderr}"
    return result


def test_installed_distribution_recovers_sources_and_preserves_existing_files(
    tmp_path: Path,
) -> None:
    uv = shutil.which("uv")
    bun = shutil.which("bun")
    if uv is None or bun is None:
        if os.environ.get("BUN_UNPACK_REQUIRE_FIXTURES") == "1":
            pytest.fail("Installed-package checks require uv and Bun")
        pytest.skip("Installed-package checks require uv and Bun")

    project = Path(__file__).resolve().parents[1]
    distributions = tmp_path / "dist"
    run_command([uv, "build", "--out-dir", str(distributions)], cwd=project)
    (source_distribution,) = distributions.glob("*.tar.gz")
    # Rebuild from the sdist so missing build inputs cannot hide in the checkout.
    rebuilt = tmp_path / "rebuilt"
    run_command(
        [uv, "build", str(source_distribution), "--wheel", "--out-dir", str(rebuilt)],
        cwd=tmp_path,
    )
    (wheel,) = rebuilt.glob("*.whl")
    environment = tmp_path / "consumer"
    run_command([uv, "venv", "--python", sys.executable, str(environment)], cwd=tmp_path)
    scripts = environment / ("Scripts" if os.name == "nt" else "bin")
    python = scripts / ("python.exe" if os.name == "nt" else "python")
    cli = scripts / ("bun-unpack.exe" if os.name == "nt" else "bun-unpack")
    run_command([uv, "pip", "install", "--python", str(python), str(wheel)], cwd=tmp_path)
    run_command(
        [
            str(python),
            "-I",
            "-c",
            "from importlib.resources import files; "
            "from bun_unpack import BunUnpacker, UnpackReport; "
            "assert files('bun_unpack').joinpath('py.typed').is_file()",
        ],
        cwd=tmp_path,
    )

    source = "import { greeting } from './greeting';\nconsole.log(greeting);\n"
    dependency = "export const greeting = 'Hello, café';\n"
    (tmp_path / "main.ts").write_text(source, encoding="utf-8")
    (tmp_path / "greeting.ts").write_text(dependency, encoding="utf-8")
    executable = tmp_path / ("sample.exe" if os.name == "nt" else "sample")
    run_command(
        [bun, "build", "--compile", "--sourcemap", "main.ts", "--outfile", str(executable)],
        cwd=tmp_path,
    )
    output = tmp_path / "recovered"
    command = [str(cli), str(executable), "-o", str(output)]
    preview = run_command([*command, "--dry-run"], cwd=tmp_path)
    assert "Would recover" in preview.stdout
    assert not output.exists()

    run_command(command, cwd=tmp_path)
    assert (output / "main.ts").read_bytes() == source.encode("utf-8")
    assert (output / "greeting.ts").read_bytes() == dependency.encode("utf-8")
    run_command(command, cwd=tmp_path)

    (output / "main.ts").write_bytes(b"user edits\n")
    conflict = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True)
    assert conflict.returncode == 1
    assert "Refusing to overwrite" in conflict.stderr
    assert (output / "main.ts").read_bytes() == b"user edits\n"

    bundle = tmp_path / "bundle"
    run_command(
        [str(python), "-I", "-m", "bun_unpack", str(executable), "--bundle", "-o", str(bundle)],
        cwd=tmp_path,
    )
    assert any(bundle.rglob("*.map"))
