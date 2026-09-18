from __future__ import annotations

import dataclasses
import tempfile
import unittest
from pathlib import Path

from ops.gates import ExecutionGate, GateError
from ops.inventory import Inventory, PolicyEvaluator
from ops.plans import FixtureResolver, PlanService, StaticIdentityProvider
from ops.registry import ActionRegistry
from ops.resources import TrustedResourceProvider
from ops.storage import AtomicJsonStore


ROOT = Path(__file__).parents[2] / ".." / ".."
OWNER = "33333333-3333-4333-8333-333333333333"


class GateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        provider = TrustedResourceProvider(ROOT / "2-infra" / "ops-control")
        self.registry = ActionRegistry(provider)
        self.inventory = Inventory.from_provider(provider)
        self.policy = PolicyEvaluator.from_provider(provider)
        self.resolver = FixtureResolver()
        store_root = Path(self.temp.name) / "store"
        store_root.mkdir(mode=0o700)
        self.store = AtomicJsonStore(store_root)
        self.identity = StaticIdentityProvider(OWNER)
        self.service = PlanService(
            registry=self.registry,
            inventory=self.inventory,
            policy=self.policy,
            store=self.store,
            identity_provider=self.identity,
            resolver=self.resolver,
            now=lambda: "2026-09-10T01:00:00Z",
        )
        self.plan = self.service.create_plan("ops003.fixture.read", "host:lab-global-primary", {})

    def tearDown(self) -> None:
        self.temp.cleanup()

    def gate(self, *, inventory=None, policy=None, resolver=None, now=lambda: "2026-09-10T01:00:00Z") -> ExecutionGate:
        return ExecutionGate(
            store=self.store,
            registry=self.registry,
            inventory=inventory or self.inventory,
            policy=policy or self.policy,
            identity_provider=self.identity,
            resolver=resolver or self.resolver,
            now=now,
        )

    def approval(self, *, start_before: str = "2026-09-10T02:00:00Z") -> dict[str, object]:
        return {
            "schema_version": 1,
            "approval_id": "55555555-5555-4555-8555-555555555555",
            "owner_id": OWNER,
            "plan_id": self.plan["plan_id"],
            "plan_digest": self.plan["plan_digest"],
            "approver_credential_id": "ops-approve",
            "approved_at": "2026-09-10T00:59:00Z",
            "start_before": start_before,
            "max_runtime_seconds": 30,
        }

    def test_missing_approval_is_the_default_deny_and_success_is_read_only(self) -> None:
        with self.assertRaises(GateError) as denied:
            self.gate().validate_for_start(self.plan["plan_id"])
        self.assertEqual(denied.exception.code, "approval_required")
        result = self.gate().validate_for_start(self.plan["plan_id"], approval=self.approval())
        self.assertEqual(result["resolved_targets"], ["lab-global-primary"])
        self.assertEqual(result["executor_calls"], 0)

    def test_expired_approval_is_rejected(self) -> None:
        with self.assertRaises(GateError) as denied:
            self.gate().validate_for_start(
                self.plan["plan_id"],
                approval=self.approval(start_before="2026-09-10T00:59:00Z"),
            )
        self.assertEqual(denied.exception.code, "approval_expired")

    def test_approval_owner_and_digest_mismatch_are_rejected(self) -> None:
        for field, value in (
            ("owner_id", "44444444-4444-4444-8444-444444444444"),
            ("plan_digest", "a" * 64),
        ):
            with self.subTest(field=field):
                candidate = self.approval()
                candidate[field] = value
                with self.assertRaises(GateError) as denied:
                    self.gate().validate_for_start(self.plan["plan_id"], approval=candidate)
                self.assertEqual(denied.exception.code, "approval_required")

    def test_plan_tamper_fails_closed(self) -> None:
        relative = f"plans/{self.plan['plan_id']}.json"
        tampered = self.store.read_json(relative)
        tampered["resolved_params"] = {"unexpected": "change"}
        self.store.write_json(relative, tampered)
        with self.assertRaises(GateError) as denied:
            self.gate().validate_for_start(self.plan["plan_id"], approval=self.approval())
        self.assertEqual(denied.exception.code, "storage_failed")

    def test_action_resolver_policy_connection_and_inventory_changes_make_plan_stale(self) -> None:
        changed_resolver = FixtureResolver(
            {
                "ops003.fixture.read": {
                    "version": "2.0.0",
                    "source": {
                        "kind": "file",
                        "origin": "fixtures/changed.yml",
                        "version": "2.0.0",
                        "digest": "b" * 64,
                    },
                }
            }
        )
        with self.assertRaises(GateError) as resolver_denied:
            self.gate(resolver=changed_resolver).validate_for_start(self.plan["plan_id"], approval=self.approval())
        self.assertEqual(resolver_denied.exception.code, "plan_stale")

        changed_policy = PolicyEvaluator(
            rules=self.policy.rules,
            machine_classes=self.policy.machine_classes,
            digest="c" * 64,
        )
        with self.assertRaises(GateError) as policy_denied:
            self.gate(policy=changed_policy).validate_for_start(self.plan["plan_id"], approval=self.approval())
        self.assertEqual(policy_denied.exception.code, "plan_stale")

        changed_host = dataclasses.replace(
            self.inventory.hosts["lab-global-primary"],
            connection_digest="d" * 64,
        )
        changed_hosts = dict(self.inventory.hosts)
        changed_hosts[changed_host.host_id] = changed_host
        changed_inventory = Inventory(
            changed_hosts,
            groups=self.inventory.groups,
            inventory_digest="e" * 64,
        )
        with self.assertRaises(GateError) as connection_denied:
            self.gate(inventory=changed_inventory).validate_for_start(self.plan["plan_id"], approval=self.approval())
        self.assertEqual(connection_denied.exception.code, "plan_stale")

        changed_groups = dict(self.inventory.groups)
        changed_groups["new_member_fixture"] = ("lab-cn-1",)
        changed_inventory = Inventory(
            self.inventory.hosts,
            groups=changed_groups,
            inventory_digest="f" * 64,
        )
        with self.assertRaises(GateError) as group_denied:
            self.gate(inventory=changed_inventory).validate_for_start(self.plan["plan_id"], approval=self.approval())
        self.assertEqual(group_denied.exception.code, "plan_stale")


if __name__ == "__main__":
    unittest.main()
