"""Small, dependency-free checks for the Thin OPS public tree."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


def current_files():
    return (
        path
        for path in ROOT.rglob("*")
        if path.is_file()
        and not {".git", "__pycache__"}.intersection(path.relative_to(ROOT).parts)
    )


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
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for phrase in (
            "Thin OPS",
            "qiaoen12/ops-control",
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
        service_card = (ROOT / "ops/framework/templates/service-card.md").read_text(
            encoding="utf-8"
        )
        runbook = (ROOT / "ops/framework/templates/runbook.md").read_text(
            encoding="utf-8"
        )
        catalog = (ROOT / "ops/framework/templates/action-catalog.yml").read_text(
            encoding="utf-8"
        )
        policy = (ROOT / "ops/framework/templates/policy.yml").read_text(
            encoding="utf-8"
        )

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
            text = path.read_text(encoding="utf-8", errors="replace")
            relative = path.relative_to(ROOT).as_posix()
            for pattern, label in (
                (private_key, "private key material"),
                (ipv4_literal, "IPv4 literal"),
                (credential_literal, "credential literal"),
                (personal_marker, "personal marker"),
            ):
                with self.subTest(path=relative, finding=label):
                    self.assertIsNone(pattern.search(text))

    def test_migration_source_is_not_an_active_dependency(self):
        active_roots = (ROOT / "ops", ROOT / "tests", ROOT / ".github/workflows")
        migration_source_marker = "g-lite" + "-ops"
        for root in active_roots:
            for path in root.rglob("*"):
                if path.is_file() and path.suffix != ".pyc":
                    with self.subTest(path=path.relative_to(ROOT).as_posix()):
                        self.assertNotIn(
                            migration_source_marker,
                            path.read_text(encoding="utf-8"),
                        )


if __name__ == "__main__":
    unittest.main()
