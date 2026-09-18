from __future__ import annotations

import unittest
from pathlib import Path

from ops.inventory import Inventory, InventoryError, PolicyEvaluator
from ops.resources import TrustedResourceProvider


ROOT = Path(__file__).parents[2] / ".." / ".."


class InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        provider = TrustedResourceProvider(ROOT / "2-infra" / "ops-control")
        cls.inventory = Inventory.from_provider(provider)
        cls.policy = PolicyEvaluator.from_provider(provider)

    def test_target_syntax_is_strict_and_group_expansion_is_sorted(self) -> None:
        resolution = self.inventory.resolve_targets("group:aether_primary_hosts")
        self.assertEqual(resolution.resolved_targets, ["lab-global-primary", "lab-paused-svc"])
        self.assertEqual(resolution.resolved_targets, sorted(set(resolution.resolved_targets)))
        for invalid in ("all", "all:!managed_linux", "host:a,b", "group:", "host:missing"):
            with self.subTest(target=invalid):
                with self.assertRaises(InventoryError):
                    self.inventory.resolve_targets(invalid)

    def test_retired_and_conflicted_targets_fail_closed(self) -> None:
        with self.assertRaises(InventoryError) as retired:
            self.inventory.resolve_targets("host:lab-retired-vmiss")
        self.assertEqual(retired.exception.code, "unsupported_target")
        with self.assertRaises(InventoryError) as conflict:
            self.inventory.resolve_targets("host:lab-global-ops")
        self.assertEqual(conflict.exception.code, "context_conflict")
        with self.assertRaises(InventoryError) as empty:
            self.inventory.resolve_targets("group:cpa_hosts")
        self.assertEqual(empty.exception.code, "unknown_target")

    def test_windows_local_client_nat_and_paused_facts_are_distinct(self) -> None:
        windows = self.inventory.resolve_targets("host:lab-win-1").hosts[0]
        self.assertEqual(windows.platform["os"], "windows")
        local_client = self.inventory.resolve_targets("host:lab-unmanaged-pc").hosts[0]
        self.assertEqual(local_client.kind, "local_client")
        self.assertIsNone(local_client.connection)
        nat = self.inventory.resolve_targets("host:lab-nat-1").hosts[0]
        self.assertEqual(nat.machine_class, "nat_trial")
        paused = self.inventory.resolve_targets("host:lab-paused-svc").hosts[0]
        self.assertEqual(paused.projection["services"]["demo_paused"]["expected_state"], "paused")
        self.assertEqual(paused.projection["lifecycle"], "active")

    def test_resolved_group_is_frozen_when_group_membership_changes(self) -> None:
        resolution = self.inventory.resolve_targets("group:aether_primary_hosts")
        original = self.inventory.groups["aether_primary_hosts"]
        try:
            self.inventory.groups["aether_primary_hosts"] = tuple(
                sorted(set(original) | {"lab-cn-1"})
            )
            self.assertEqual(resolution.resolved_targets, ["lab-global-primary", "lab-paused-svc"])
        finally:
            self.inventory.groups["aether_primary_hosts"] = original

    def test_deny_wins_offload_and_primary_standby_rules(self) -> None:
        cn = self.inventory.hosts["lab-cn-1"]
        denied = self.policy.evaluate(
            cn,
            "software.update",
            {"software_id": "fixture", "fetches_overseas": True, "via_offload": False},
        )
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.rule_id, "offload-required")
        allowed = self.policy.evaluate(
            cn,
            "software.update",
            {"software_id": "fixture", "fetches_overseas": True, "via_offload": True},
        )
        self.assertTrue(allowed.allowed)
        hosts = [self.inventory.hosts["lab-global-primary"], self.inventory.hosts["lab-global-ops"]]
        mutex = self.policy.evaluate_batch(
            hosts,
            "software.update",
            {"software_id": "sw-dual-role", "force_parallel": False},
        )
        self.assertTrue(mutex)
        self.assertTrue(all(not item.allowed for item in mutex))
        self.assertTrue(all(item.rule_id == "primary-standby-mutex" for item in mutex))

    def test_primary_standby_mutex_defaults_missing_force_parallel_to_false(self) -> None:
        hosts = [self.inventory.hosts["lab-global-primary"], self.inventory.hosts["lab-global-ops"]]
        mutex = self.policy.evaluate_batch(hosts, "software.update", {"software_id": "sw-dual-role"})
        self.assertEqual(len(mutex), 2)
        self.assertTrue(all(not item.allowed for item in mutex))
        self.assertTrue(all(item.rule_id == "primary-standby-mutex" for item in mutex))


if __name__ == "__main__":
    unittest.main()
