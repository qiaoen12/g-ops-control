from __future__ import annotations

import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).parents[4]


class ReadmeTests(unittest.TestCase):
    def test_install_and_test_documents_unit_and_integration_discovery(self) -> None:
        root_readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")
        package_readme = (
            REPOSITORY_ROOT / "1-code" / "ops-control" / "README.md"
        ).read_text(encoding="utf-8")

        self.assertIn("tests/unit", root_readme)
        self.assertIn("tests/integration", root_readme)
        self.assertIn("tests/unit", package_readme)
        self.assertIn("tests/integration", package_readme)


if __name__ == "__main__":
    unittest.main()
