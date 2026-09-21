"""Small, dependency-free checks for the Thin OPS public tree."""

from pathlib import Path
import re
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
NON_TEXT_SYSTEM_METADATA_NAMES = frozenset({".DS_Store", "Thumbs.db", "Desktop.ini"})
EXCLUDED_DIRECTORIES = frozenset({".git", "__pycache__"})


def text_files(root):
    root = Path(root)
    return (
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.name not in NON_TEXT_SYSTEM_METADATA_NAMES
        and not EXCLUDED_DIRECTORIES.intersection(path.relative_to(root).parts)
    )


def current_files():
    return text_files(ROOT)


def read_text_file(path):
    path = Path(path)
    if path.name in NON_TEXT_SYSTEM_METADATA_NAMES:
        raise ValueError(f"non-text system metadata: {path.name}")
    return path.read_text(encoding="utf-8")


class StructureTests(unittest.TestCase):
    def test_required_v4_paths_exist(self):
        required_files = {
            "README.md",
            "AGENTS.md",
            ".gitignore",
            ".github/workflows/tests.yml",
            ".github/ISSUE_TEMPLATE/contract.md",
            ".github/pull_request_template.md",
            "ops/framework/README.md",
            "ops/framework/templates/service-card.md",
            "ops/framework/templates/runbook.md",
            "ops/framework/templates/action-catalog.yml",
            "ops/framework/templates/policy.yml",
            "ops/modules/README.md",
            "ops/hub/README.md",
            "ops/sites/example/README.md",
            "docs/architecture.md",
            "docs/decisions/thin-ops-reset.md",
            "tests/test_structure.py",
        }
        for relative in required_files:
            with self.subTest(path=relative):
                self.assertTrue((ROOT / relative).is_file())

        for relative in {
            "ops/framework",
            "ops/framework/templates",
            "ops/modules",
            "ops/hub",
            "ops/sites/example",
            "docs",
            "docs/decisions",
            "tests",
        }:
            with self.subTest(directory=relative):
                self.assertTrue((ROOT / relative).is_dir())

    def test_legacy_paths_are_absent(self):
        forbidden = {
            "1-code",
            "2-infra",
            "ops/gateway.py",
            "ops/broker.py",
            "ops/approval",
            "ops/executor",
            "ops/gates.py",
            "ops/inventory.py",
            "ops/logs.py",
            "ops/models.py",
            "ops/plans.py",
            "ops/registry.py",
            "ops/resources.py",
            "ops/results.py",
            "ops/storage.py",
            "ops/launch.py",
        }
        for relative in forbidden:
            with self.subTest(path=relative):
                self.assertFalse((ROOT / relative).exists())

    def test_readme_describes_public_boundary_and_paths(self):
        readme = read_text_file(ROOT / "README.md")
        for phrase in (
            "Thin OPS",
            "qiaoen12/g-ops-control",
            "Semaphore",
            "Ansible",
            "Komari",
            "Central Logs",
            "Semaphore History",
            "Gateway/Broker/Approval",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, readme)

    def test_templates_have_basic_shape(self):
        service_card = read_text_file(ROOT / "ops/framework/templates/service-card.md")
        runbook = read_text_file(ROOT / "ops/framework/templates/runbook.md")
        catalog = read_text_file(ROOT / "ops/framework/templates/action-catalog.yml")
        policy = read_text_file(ROOT / "ops/framework/templates/policy.yml")

        for phrase in ("# Service Card", "Explicit target", "Secrets"):
            self.assertIn(phrase, service_card)
        for phrase in ("# Runbook", "Before starting", "Recovery and closeout"):
            self.assertIn(phrase, runbook)
        for phrase in (
            "version: 1",
            "actions:",
            "fixed_high_risk_change:",
            "destructive_purge:",
        ):
            self.assertIn(phrase, catalog)
        for phrase in (
            "version: 1",
            "targeting:",
            "explicit_target_required: true",
            "deny_on_uncertain_or_conflicting_facts: true",
            "public_request_or_config: prohibited",
        ):
            self.assertIn(phrase, policy)

    def test_public_safety_scan(self):
        private_key = re.compile(r"-----BEGIN [A-Z0-9 ]+ PRIVATE KEY-----")
        ipv4_literal = re.compile(
            r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
            r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])"
        )
        credential_literal = re.compile(
            r"(?im)^\s*(?:password|passwd|token|api[_-]?key|secret|private[_-]?key)"
            r"\s*[:=]\s*['\"][^'\"]+['\"]"
        )
        personal_marker = re.compile(r"(?i)\bvps\d+\b")

        for path in current_files():
            text = read_text_file(path)
            relative = path.relative_to(ROOT).as_posix()
            for pattern, label in (
                (private_key, "private key material"),
                (ipv4_literal, "IPv4 literal"),
                (credential_literal, "credential literal"),
                (personal_marker, "personal marker"),
            ):
                with self.subTest(path=relative, finding=label):
                    self.assertIsNone(pattern.search(text))

    def test_text_files_skip_known_metadata_but_not_decode_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".DS_Store").write_bytes(b"\xff")
            (root / "Thumbs.db").write_bytes(b"\xfe")
            (root / "regular.txt").write_text("plain text", encoding="utf-8")
            broken = root / "broken.txt"
            broken.write_bytes(b"\xff")

            self.assertEqual(
                {path.name for path in text_files(root)},
                {"regular.txt", "broken.txt"},
            )
            self.assertEqual(read_text_file(root / "regular.txt"), "plain text")
            with self.assertRaises(UnicodeDecodeError):
                read_text_file(broken)

    def test_migration_source_is_not_an_active_dependency(self):
        active_roots = (ROOT / "ops", ROOT / "tests", ROOT / ".github/workflows")
        migration_source_marker = "g-lite" + "-ops"
        for root in active_roots:
            for path in text_files(root):
                with self.subTest(path=path.relative_to(ROOT).as_posix()):
                    self.assertNotIn(migration_source_marker, read_text_file(path))


if __name__ == "__main__":
    unittest.main()
