"""End-to-end recovery checks against real, locally built historical executables."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from bun_unpack import BunUnpacker

FIXTURES = Path(os.environ.get("BUN_UNPACK_FIXTURES", "build/compatibility/fixtures"))


class TestCompatibility(unittest.TestCase):
    def manifests(self) -> list[Path]:
        manifests = sorted(FIXTURES.glob("*/*/expected.json"))
        if not manifests:
            if os.environ.get("BUN_UNPACK_REQUIRE_FIXTURES") == "1":
                self.fail("Required compatibility corpus is missing")
            self.skipTest("Generate fixtures with python -m tools.build_compatibility")
        return manifests

    def test_recovery_matches_original_artifacts(self):
        for manifest_path in self.manifests():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            with self.subTest(version=manifest["version"], case=manifest["case"]):
                unpacker = BunUnpacker(manifest_path.parent / manifest["executable"])
                self.assertEqual(unpacker.info.record_size, manifest["record_size"])
                with tempfile.TemporaryDirectory() as temporary:
                    output = Path(temporary) / "recovered"
                    result = unpacker.unpack(output)
                    self.assertEqual(result.warnings, tuple(manifest["source_warnings"]))
                    for relative_path, expected_hash in manifest["sources"].items():
                        recovered = output / relative_path
                        self.assertTrue(recovered.is_file(), f"Missing source: {relative_path}")
                        self.assertEqual(
                            hashlib.sha256(recovered.read_bytes()).hexdigest(), expected_hash
                        )
                    # Source-map paths are exact. An asset keeps its embedded
                    # name whenever the compiler did not record the original one.
                    source_paths = {
                        artifact.relative_path.as_posix()
                        for artifact in result.files
                        if artifact.kind == "source"
                    }
                    self.assertTrue(set(manifest["sources"]) <= source_paths)
                    self.assertTrue(source_paths <= set(manifest["consumed_inputs"]))

                    recovered_hashes = {
                        hashlib.sha256(artifact.path.read_bytes()).hexdigest()
                        for artifact in result.files
                    }
                    for expected_hash in manifest["assets"]:
                        self.assertIn(expected_hash, recovered_hashes)
                    for path, expected_hash in manifest["optional_inputs"].items():
                        recovered = output / path
                        if recovered.exists():
                            self.assertEqual(
                                hashlib.sha256(recovered.read_bytes()).hexdigest(),
                                expected_hash,
                                path,
                            )
                    bundles = b"\n".join(
                        artifact.path.read_bytes()
                        for artifact in result.files
                        if artifact.kind == "bundle"
                    )
                    self.assertTrue(bundles)
                    for original_path, markers in manifest["transformed_inputs"].items():
                        for marker in markers:
                            self.assertIn(marker.encode("utf-8"), bundles, original_path)

    def test_bundle_and_external_sourcemaps_remain_consistent(self):
        for manifest_path in self.manifests():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            with self.subTest(version=manifest["version"], case=manifest["case"]):
                unpacker = BunUnpacker(manifest_path.parent / manifest["executable"])
                with tempfile.TemporaryDirectory() as temporary:
                    result = unpacker.unpack(Path(temporary), mode="bundle")
                    maps = [artifact for artifact in result.files if artifact.kind == "sourcemap"]
                    self.assertTrue(maps)
                    if "bytecode" in manifest["case"]:
                        self.assertTrue(
                            any(artifact.kind == "bytecode" for artifact in result.files)
                        )
                    recovered_sources: set[str] = set()
                    has_mappings = False
                    for artifact in maps:
                        source_map = json.loads(artifact.path.read_text(encoding="utf-8"))
                        self.assertEqual(source_map["version"], 3)
                        has_mappings = has_mappings or bool(source_map["mappings"])
                        if source_map["sources"]:
                            self.assertTrue(source_map["mappings"])
                        if result.warnings:
                            self.assertTrue(
                                all(
                                    warning.startswith("Embedded source map mappings are invalid:")
                                    for warning in result.warnings
                                )
                            )
                        else:
                            self.assertRegex(source_map["mappings"], r"^[A-Za-z0-9+/;,]*$")
                        self.assertEqual(
                            len(source_map["sources"]), len(source_map["sourcesContent"])
                        )
                        for path, content in zip(
                            source_map["sources"], source_map["sourcesContent"]
                        ):
                            if content is not None:
                                recovered_sources.add(
                                    hashlib.sha256(content.encode("utf-8")).hexdigest()
                                )
                    self.assertTrue(has_mappings)
                    for path, digest in manifest["sources"].items():
                        self.assertIn(
                            digest, recovered_sources, f"Missing from source maps: {path}"
                        )


if __name__ == "__main__":
    unittest.main()
