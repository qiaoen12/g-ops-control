from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ops.inventory import Inventory, PolicyEvaluator
from ops.models import canonical_digest, validate_model
from ops.plans import FixtureResolver, PlanError, PlanService, StaticIdentityProvider
from ops.registry import ActionRegistry
from ops.resources import TrustedResourceProvider
from ops.storage import AtomicJsonStore


ROOT = Path(__file__).parents[2] / ".." / ".."
OWNER = "33333333-3333-4333-8333-333333333333"


class PlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        provider = TrustedResourceProvider(ROOT / "2-infra" / "ops-control")
        self.inventory = Inventory.from_provider(provider)
        self.policy = PolicyEvaluator.from_provider(provider)
        store_root = Path(self.temp.name) / "store"
        store_root.mkdir(mode=0o700)
        self.store = AtomicJsonStore(store_root)
        self.service = PlanService(
            registry=ActionRegistry(provider),
            inventory=self.inventory,
            policy=self.policy,
            store=self.store,
            identity_provider=StaticIdentityProvider(OWNER),
            now=lambda: "2026-09-10T01:00:00Z",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_create_plan_consumes_shared_schema_and_writes_once(self) -> None:
        plan = self.service.create_plan("ops003.fixture.read", "host:lab-global-primary", {})
        validate_model("Plan", plan)
        stored = self.store.read_record(f"plans/{plan['plan_id']}.json", "Plan")
        self.assertEqual(stored, plan)
        self.assertEqual(plan["resolved_targets"], ["lab-global-primary"])
        self.assertEqual(plan["target_bindings"]["lab-global-primary"]["platform"]["os"], "linux")
        self.assertEqual(plan["recovery_evidence_refs"], [])
        second = self.service.create_plan("ops003.fixture.read", "host:lab-global-primary", {})
        self.assertNotEqual(plan["plan_id"], second["plan_id"])
        self.assertNotEqual(plan["recovery_generation"], second["recovery_generation"])

    def test_platform_exclusion_is_not_a_resolved_target(self) -> None:
        self.inventory.groups["mixed_platform_fixture"] = ("lab-global-primary", "lab-win-1")
        plan = self.service.create_plan("ops003.fixture.read", "group:mixed_platform_fixture", {})
        self.assertEqual(plan["resolved_targets"], ["lab-global-primary"])
        self.assertEqual(plan["excluded"], [{"host_id": "lab-win-1", "reason": "platform_not_supported:windows"}])
        self.assertNotIn("lab-win-1", plan["target_bindings"])

    def test_all_excluded_and_frozen_actions_do_not_create_plans(self) -> None:
        with self.assertRaises(PlanError) as excluded:
            self.service.create_plan("ops003.fixture.read", "host:lab-win-1", {})
        self.assertEqual(excluded.exception.code, "precondition_failed")
        with self.assertRaises(PlanError) as frozen:
            self.service.create_plan("software.check", "host:lab-global-primary", {"software_id": "ops-core"})
        self.assertEqual(frozen.exception.code, "action_frozen")

    def test_protected_request_fields_and_unknown_action_params_are_rejected(self) -> None:
        for params in ({"force_parallel": False}, {"approved": True}, {"playbook": "x.yml"}):
            with self.subTest(params=params):
                with self.assertRaises(PlanError) as raised:
                    self.service.create_plan("ops003.fixture.read", "host:lab-global-primary", params)
                self.assertEqual(raised.exception.code, "invalid_request")

    def test_latest_is_frozen_by_injected_resolver_and_source_digest_binds_bundle(self) -> None:
        resolver = FixtureResolver(
            {
                "ops003.fixture.read": {
                    "version": "1.2.3",
                    "source": {
                        "kind": "file",
                        "origin": "fixtures/resolver.yml",
                        "version": "1.2.3",
                        "digest": "a" * 64,
                    },
                }
            }
        )
        self.service.resolver = resolver
        plan = self.service.create_plan("ops003.fixture.read", "host:lab-global-primary", {})
        self.assertEqual(plan["action_version"], "1.2.3")
        self.assertEqual(len(plan["package_digest"]), 64)
        self.assertTrue(plan["bundle_id"].startswith("bundle-"))

    def test_plan_digest_is_independent_of_object_key_order(self) -> None:
        plan = self.service.create_plan("ops003.fixture.read", "host:lab-global-primary", {})
        reordered = {key: plan[key] for key in reversed(list(plan))}
        self.assertEqual(plan["plan_digest"], canonical_digest(reordered, omit=("plan_digest",)))


if __name__ == "__main__":
    unittest.main()
