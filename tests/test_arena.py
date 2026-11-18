import unittest

import pytest


class TestPlumblineSuite(unittest.TestCase):
    """Bridge for test runners expecting standard unittest discovery."""

    def test_full_plumbline_suite(self) -> None:
        ret = pytest.main(["tests/unit", "-q"])
        self.assertEqual(ret, 0, "Pytest test suite returned non-zero exit code")


if __name__ == "__main__":
    unittest.main()
