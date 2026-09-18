from __future__ import annotations

import sys
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from ops.approval.store import ApprovalStore, TrustedApprovalProvider
from ops.executor.broker import BrokerInvocation
from ops.executor.launch import (
    ExactlyOnceLauncher,
    LaunchError,
    ServiceManagerResponseLost,
    ServiceManagerResult,
)
from ops.gates import ExecutionGate
from ops.inventory import Inventory, PolicyEvaluator
from ops.models import utc_now
from ops.plans import FixtureResolver, PlanService, StaticIdentityProvider
from ops.registry import ActionRegistry
from ops.resources import TrustedResourceProvider
from ops.results import ResultService
from ops.storage import AtomicJsonStore, StorageError


ROOT = Path(__file__).parents[2] / ".." / ".."
OWNER = "33333333-3333-4333-8333-333333333333"


class FakeBroker:
    def __init__(self, release: Path) -> None:
        self.release = release
        self.calls = 0
        self.release_history: list[Path] = []

    def build_invocation(self, capability: str) -> BrokerInvocation:
        self.calls += 1
        self.release_history.append(self.release)
        return BrokerInvocation(
            executable=Path(sys.executable),
            argv=(sys.executable, "fixed-broker", "--capability", capability),
            cwd=self.release,
            environment={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            release=self.release,
        )


class FakeManager:
    def __init__(self, result: ServiceManagerResult | None = None, error: BaseException | None = None) -> None:
        self.result = result or ServiceManagerResult(accepted=True, completed=True, exit_code=0)
        self.error = error
        self.calls = 0
        self.releases: list[Path] = []

    def start(self, invocation: BrokerInvocation, *, run_id: str, plan: dict[str, object]) -> ServiceManagerResult:
        self.calls += 1
        self.releases.append(invocation.release)
        if self.error is not None:
            raise self.error
        return self.result


class FaultStore(AtomicJsonStore):
    def __init__(self, root: Path, *, fail_model: str | None = None) -> None:
        super().__init__(root)
        self.fail_model = fail_model

    def write_immutable_record(self, relative: str, model_name: str, value: object) -> Path:
        if model_name == self.fail_model:
            raise StorageError("injected write failure")
        return super().write_immutable_record(relative, model_name, value)


class LaunchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "store").mkdir(mode=0o700)
        self.store = AtomicJsonStore(self.root / "store")
        provider = TrustedResourceProvider(ROOT / "2-infra" / "ops-control")
        inventory = Inventory.from_provider(provider)
        policy = PolicyEvaluator.from_provider(provider)
        self.service = PlanService(
            registry=ActionRegistry(provider),
            inventory=inventory,
            policy=policy,
            store=self.store,
            identity_provider=StaticIdentityProvider(OWNER),
            resolver=FixtureResolver(),
            now=lambda: "2026-09-11T12:00:00Z",
        )
        self.plan = self.service.create_plan("ops005.noop", "host:lab-global-primary", {})
        self.approval = {
            "schema_version": 1,
            "approval_id": "55555555-5555-4555-8555-555555555555",
            "owner_id": OWNER,
            "plan_id": self.plan["plan_id"],
            "plan_digest": self.plan["plan_digest"],
            "approver_credential_id": "mac-passkey-fixture",
            "approved_at": "2026-09-11T12:00:00Z",
            "start_before": "2026-09-11T12:29:00Z",
            "max_runtime_seconds": 30,
        }
        ApprovalStore(self.store).publish(self.approval)
        self.release = self.root / "release-a"
        self.release.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def launcher(self, *, store=None, manager=None, broker=None) -> tuple[ExactlyOnceLauncher, FakeBroker, FakeManager]:
        store = store or self.store
        manager = manager or FakeManager()
        broker = broker or FakeBroker(self.release)
        gate = ExecutionGate(
            store=store,
            registry=ActionRegistry(TrustedResourceProvider(ROOT / "2-infra" / "ops-control")),
            inventory=Inventory.from_provider(TrustedResourceProvider(ROOT / "2-infra" / "ops-control")),
            policy=PolicyEvaluator.from_provider(TrustedResourceProvider(ROOT / "2-infra" / "ops-control")),
            identity_provider=StaticIdentityProvider(OWNER),
            resolver=FixtureResolver(),
            now=lambda: "2026-09-11T12:00:00Z",
            approval_provider=TrustedApprovalProvider(ApprovalStore(store)),
        )
        return (
            ExactlyOnceLauncher(
                store=store,
                gate=gate,
                broker=broker,
                service_manager=manager,
                result_service=ResultService(store, now=lambda: "2026-09-11T12:00:00Z"),
                now=lambda: "2026-09-11T12:00:00Z",
            ),
            broker,
            manager,
        )

    def test_repeated_apply_returns_one_run_and_one_manager_call(self) -> None:
        results_dir = self.root / "store" / "results"
        results_dir.mkdir(mode=0o750)
        Path.chmod(results_dir, 0o2750)
        chmod_calls: list[Path] = []
        original_chmod = Path.chmod

        def track_chmod(path: Path, mode: int) -> None:
            chmod_calls.append(path)
            original_chmod(path, mode)

        launcher, broker, manager = self.launcher()
        with patch.object(Path, "chmod", new=track_chmod):
            first = launcher.apply(self.plan["plan_id"])
        second = launcher.apply(self.plan["plan_id"])
        self.assertEqual(first.run_id, second.run_id)
        self.assertEqual(first.status, "succeeded")
        self.assertEqual(second.status, "succeeded")
        self.assertEqual(manager.calls, 1)
        self.assertEqual(broker.calls, 1)
        self.assertEqual(len(list((self.root / "store" / "uses").glob("*.json"))), 1)
        self.assertEqual(len(list((self.root / "store" / "launches").glob("*.json"))), 1)
        result_file = results_dir / f"{first.run_id}.json"
        self.assertEqual(chmod_calls, [result_file])
        self.assertEqual(stat.S_IMODE(results_dir.stat().st_mode), 0o2750)

    def test_concurrent_apply_has_one_use_and_one_launch(self) -> None:
        launcher, broker, manager = self.launcher()
        barrier = threading.Barrier(2)
        outcomes: list[object] = []

        def worker() -> None:
            barrier.wait(timeout=2)
            outcomes.append(launcher.apply(self.plan["plan_id"]))

        threads = [threading.Thread(target=worker), threading.Thread(target=worker)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=4)
        self.assertEqual(len(outcomes), 2)
        run_ids = {outcome.run_id for outcome in outcomes}  # type: ignore[attr-defined]
        self.assertEqual(len(run_ids), 1)
        # One caller may observe the durable use while the winner is still
        # writing the initial run; it must not launch a second process.
        self.assertEqual(manager.calls, 1)
        self.assertEqual(broker.calls, 1)

    def test_use_run_and_launch_fault_windows_return_unknown_without_retry(self) -> None:
        for model in ("UseRecord", "RunSummary", "LaunchRecord"):
            with self.subTest(model=model):
                root = self.root / f"fault-{model}"
                root.mkdir(mode=0o700)
                store = FaultStore(root, fail_model=model)
                store.write_immutable_record(store.record_path("plans", self.plan["plan_id"]), "Plan", self.plan)
                # Approval is copied into the fault store before the targeted
                # write is injected.
                ApprovalStore(store).publish(self.approval)
                launcher, broker, manager = self.launcher(store=store)
                outcome = launcher.apply(self.plan["plan_id"])
                self.assertEqual(outcome.status, "unknown")
                self.assertEqual(manager.calls, 0)
                retry = launcher.apply(self.plan["plan_id"])
                self.assertEqual(retry.run_id, outcome.run_id)
                self.assertEqual(retry.status, "unknown")
                self.assertEqual(manager.calls, 0)

    def test_service_manager_accept_then_response_loss_is_unknown_and_not_restarted(self) -> None:
        manager = FakeManager(error=ServiceManagerResponseLost())
        launcher, broker, _manager = self.launcher(manager=manager)
        first = launcher.apply(self.plan["plan_id"])
        second = launcher.apply(self.plan["plan_id"])
        self.assertEqual(first.status, "unknown")
        self.assertEqual(second.run_id, first.run_id)
        self.assertEqual(second.status, "unknown")
        self.assertEqual(manager.calls, 1)
        self.assertEqual(broker.calls, 1)
        self.assertEqual(ResultService(self.store).get(first.run_id)["status"], "unknown")

    def test_accepted_without_completion_is_unknown_and_terminal(self) -> None:
        manager = FakeManager(result=ServiceManagerResult(accepted=True, completed=False, exit_code=None))
        launcher, broker, _manager = self.launcher(manager=manager)
        first = launcher.apply(self.plan["plan_id"])
        second = launcher.apply(self.plan["plan_id"])
        self.assertEqual(first.status, "unknown")
        self.assertEqual(second.run_id, first.run_id)
        self.assertEqual(second.status, "unknown")
        self.assertEqual(ResultService(self.store).get(first.run_id)["status"], "unknown")
        self.assertEqual(manager.calls, 1)
        self.assertEqual(broker.calls, 1)

    def test_concurrent_retry_cannot_overwrite_succeeded_result(self) -> None:
        entered = threading.Event()
        complete_manager = threading.Event()
        stale_read = threading.Event()
        resume_reader = threading.Event()

        class PausedManager(FakeManager):
            def start(self, invocation, *, run_id, plan):
                entered.set()
                if not complete_manager.wait(10):
                    raise RuntimeError("manager completion was not signalled")
                return super().start(invocation, run_id=run_id, plan=plan)

        manager = PausedManager()
        writer, broker, _writer_manager = self.launcher(manager=manager)
        reader, _reader_broker, _reader_manager = self.launcher(manager=manager)
        original_get = reader.results.get_if_present
        delayed = {"done": False}

        def delayed_get(run_id):
            value = original_get(run_id)
            if value is not None and value.get("status") == "running" and not delayed["done"]:
                delayed["done"] = True
                stale_read.set()
                if not resume_reader.wait(10):
                    raise RuntimeError("reader resume was not signalled")
            return value

        reader.results.get_if_present = delayed_get
        responses: dict[str, object] = {}
        errors: list[BaseException] = []

        def apply(name: str, launcher: ExactlyOnceLauncher) -> None:
            try:
                responses[name] = launcher.apply(self.plan["plan_id"])
            except BaseException as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        first_thread = threading.Thread(target=apply, args=("first", writer))
        retry_thread = threading.Thread(target=apply, args=("retry", reader))
        first_thread.start()
        self.assertTrue(entered.wait(10))
        retry_thread.start()
        self.assertTrue(stale_read.wait(10))
        complete_manager.set()
        first_thread.join(timeout=10)
        self.assertFalse(first_thread.is_alive())
        self.assertFalse(errors)
        first = responses["first"]
        self.assertEqual(first.status, "succeeded")  # type: ignore[attr-defined]
        self.assertEqual(ResultService(self.store).get(first.run_id)["status"], "succeeded")  # type: ignore[attr-defined]
        resume_reader.set()
        retry_thread.join(timeout=10)
        self.assertFalse(retry_thread.is_alive())
        self.assertFalse(errors)
        retry = responses["retry"]
        self.assertEqual(retry.run_id, first.run_id)  # type: ignore[attr-defined]
        self.assertEqual(retry.status, "succeeded")  # type: ignore[attr-defined]
        self.assertEqual(ResultService(self.store).get(first.run_id)["status"], "succeeded")  # type: ignore[attr-defined]
        self.assertEqual(manager.calls, 1)
        self.assertEqual(broker.calls, 1)

    def test_current_race_uses_one_pinned_absolute_release(self) -> None:
        second_release = self.root / "release-b"
        second_release.mkdir(mode=0o700)
        class RaceBroker(FakeBroker):
            def build_invocation(self, capability: str) -> BrokerInvocation:
                invocation = super().build_invocation(capability)
                self.release = second_release
                return invocation

        broker = RaceBroker(self.release)
        manager = FakeManager()
        launcher, _broker, _manager = self.launcher(manager=manager, broker=broker)
        first = launcher.apply(self.plan["plan_id"])
        second = launcher.apply(self.plan["plan_id"])
        self.assertEqual(first.run_id, second.run_id)
        self.assertEqual(broker.calls, 1)
        self.assertEqual(manager.releases, [self.release])

    def test_secret_sentinel_never_enters_result(self) -> None:
        manager = FakeManager(result=ServiceManagerResult(accepted=True, completed=True, warning="FAKE_SECRET_SENTINEL"))
        launcher, _broker, _manager = self.launcher(manager=manager)
        outcome = launcher.apply(self.plan["plan_id"])
        self.assertEqual(outcome.status, "unknown")
        encoded = repr(outcome.result)
        self.assertNotIn("FAKE_SECRET_SENTINEL", encoded)
        self.assertNotIn("FAKE_SECRET_SENTINEL", repr(ResultService(self.store).get(outcome.run_id)))

    def test_ops003_fixture_remains_never_executed(self) -> None:
        fixture_plan = self.service.create_plan("ops003.fixture.read", "host:lab-global-primary", {})
        fixture_approval = dict(self.approval)
        fixture_approval.update(
            {
                "approval_id": "66666666-6666-4666-8666-666666666666",
                "plan_id": fixture_plan["plan_id"],
                "plan_digest": fixture_plan["plan_digest"],
            }
        )
        ApprovalStore(self.store).publish(fixture_approval)
        launcher, broker, manager = self.launcher()
        with self.assertRaises(LaunchError) as denied:
            launcher.apply(fixture_plan["plan_id"])
        self.assertEqual(denied.exception.code, "action_frozen")
        self.assertEqual(broker.calls, 0)
        self.assertEqual(manager.calls, 0)

    def test_ops_exec_delegate_consumes_request_v1_and_runs_only_ops005_noop(self) -> None:
        from ops.executor.broker import run_delegated_apply

        response = run_delegated_apply(
            {
                "schema_version": 1,
                "request_id": "88888888-8888-4888-8888-888888888888",
                "command": "apply",
                "params": {"plan_id": self.plan["plan_id"]},
            },
            store_root=self.store.root,
            resource_provider=TrustedResourceProvider(ROOT / "2-infra" / "ops-control"),
            now=lambda: "2026-09-11T12:00:00Z",
        )
        self.assertTrue(response["ok"])
        self.assertEqual(response["data"]["status"], "succeeded")  # type: ignore[index]
        run_id = response["data"]["run_id"]  # type: ignore[index]
        self.assertEqual(ResultService(self.store).get(run_id)["status"], "succeeded")
        self.assertEqual(len(list((self.root / "store" / "uses").glob("*.json"))), 1)
        self.assertEqual(len(list((self.root / "store" / "launches").glob("*.json"))), 1)


if __name__ == "__main__":
    unittest.main()
