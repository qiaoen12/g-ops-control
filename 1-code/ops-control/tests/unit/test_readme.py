from __future__ import annotations

import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).parents[4]


class ReadmeTests(unittest.TestCase):
    def test_install_and_test_documents_unit_and_integration_discovery(self) -> None:
        readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn("unittest discover -s 1-code/ops-control/tests/unit", readme)
        self.assertIn("unittest discover -s 1-code/ops-control/tests/integration", readme)


if __name__ == "__main__":
    unittest.main()
