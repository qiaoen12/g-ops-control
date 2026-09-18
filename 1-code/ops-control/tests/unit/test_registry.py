from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

from ops.registry import ActionRegistry, RegistryError
from ops.resources import TrustedResourceProvider


INFRA = Path(__file__).parents[2] / ".." / ".." / "2-infra" / "ops-control"


class RegistryTests(unittest.TestCase):
    def copied_provider(self) -> tuple[tempfile.TemporaryDirectory[str], TrustedResourceProvider]:
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name) / "ops-control"
        shutil.copytree(INFRA, root)
        return temp, TrustedResourceProvider(root)

    def test_manifest_is_the_only_action_index_and_real_legacy_action_is_frozen(self) -> None:
        temp, provider = self.copied_provider()
        try:
            (provider.infra_root / "actions" / "descriptors" / "unlisted.yml").write_text("not: loaded\n", encoding="utf-8")
            actions = ActionRegistry(provider).list_actions()
            self.assertEqual([item.action_id for item in actions], ["ops003.fixture.read", "ops005.noop", "software.check"])
            self.assertTrue(actions[0].enabled)
            self.assertTrue(actions[1].enabled)
            software = next(item for item in actions if item.action_id == "software.check")
            self.assertFalse(software.enabled)
            self.assertIn("OPS-001", software.reason or "")
            with self.assertRaises(RegistryError) as raised:
                ActionRegistry(provider).get("software.check")
            self.assertEqual(raised.exception.code, "action_frozen")
        finally:
            temp.cleanup()

    def test_unsafe_descriptor_adapter_and_link_are_frozen(self) -> None:
        for mutation in ("parent", "link", "protected"):
            temp, provider = self.copied_provider()
            try:
                descriptor_path = provider.infra_root / "actions" / "descriptors" / "ops003-fixture-read.yml"
                descriptor = yaml.safe_load(descriptor_path.read_text(encoding="utf-8"))
                if mutation == "parent":
                    descriptor["adapter_ref"] = "../escape.yml"
                elif mutation == "link":
                    adapter = provider.infra_root / "actions" / "adapters" / "ops003-readonly-fixture.yml"
                    adapter.unlink()
                    adapter.symlink_to(provider.infra_root / "actions" / "adapters" / "legacy-software-check.yml")
                else:
                    descriptor["parameter_schema"]["properties"] = {"force_parallel": {"type": "boolean"}}
                descriptor_path.write_text(yaml.safe_dump(descriptor, sort_keys=False), encoding="utf-8")
                records = ActionRegistry(provider).list_actions()
                if mutation == "parent":
                    record = records[0]
                    self.assertFalse(record.enabled)
                    self.assertIn("adapter", record.reason or "")
                elif mutation == "link":
                    record = records[0]
                    self.assertFalse(record.enabled)
                    self.assertIn("adapter", record.reason or "")
                else:
                    record = records[0]
                    self.assertFalse(record.enabled)
                    self.assertIn("protected", record.reason or "")
            finally:
                temp.cleanup()

    def test_manifest_path_traversal_is_not_loaded(self) -> None:
        temp, provider = self.copied_provider()
        try:
            manifest = provider.infra_root / "actions" / "manifest.yml"
            value = yaml.safe_load(manifest.read_text(encoding="utf-8"))
            value["actions"][0]["descriptor"] = "../policy/special-rules.yml"
            manifest.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
            actions = ActionRegistry(provider).list_actions()
            self.assertFalse(actions[0].enabled)
            self.assertIn("unsafe", actions[0].reason or "")
        finally:
            temp.cleanup()


if __name__ == "__main__":
    unittest.main()
