from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from bun_unpack import BunUnpacker, BunUnpackError, Limits


class TestPublicAPI(unittest.TestCase):
    def test_invalid_executable_is_a_domain_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "not-bun"
            path.write_bytes(b"not an executable")
            with self.assertRaises(BunUnpackError):
                BunUnpacker(path)

    def test_limits_must_be_positive(self):
        with self.assertRaises(ValueError):
            Limits(max_file_bytes=0)


if __name__ == "__main__":
    unittest.main()
