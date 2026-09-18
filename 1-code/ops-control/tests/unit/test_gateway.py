from __future__ import annotations

import io
import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops.cli import make_response
from ops.gateway import Gateway, IdentityError, SystemIdentityProvider
from ops.models import canonical_json_bytes
from ops.resources import TrustedResourceProvider


ROOT = Path(__file__).parents[2] / ".." / ".."
OWNER = "33333333-3333-4333-8333-333333333333"
OTHER_OWNER = "44444444-4444-4444-8444-444444444444"
REQUEST_ID = "11111111-1111-4111-8111-111111111111"


class GatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.store_root = root / "store"
        self.params_root = root / "params"
        self.store_root.mkdir(mode=0o710)
        self.params_root.mkdir(mode=0o700)
        (self.params_root / "empty.json").write_text("{}\n", encoding="utf-8")
        self.provider = TrustedResourceProvider(ROOT / "2-infra" / "ops-control")
        self.identity = SystemIdentityProvider.from_mapping(
            {
                "credentials": {
                    "ops-call-mac-fixture": {"owner_id": OWNER},
                    "ops-call-other-computer-fixture": {"owner_id": OWNER},
                    "ops-call-other-owner-fixture": {"owner_id": OTHER_OWNER},
                }
            }
        )
        self.gateway = Gateway(
            identity_provider=self.identity,
            resource_provider=self.provider,
            store_root=self.store_root,
            params_root=self.params_root,
            now=lambda: "2026-09-10T01:00:00Z",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def request(command: str, params: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": 1,
            "request_id": REQUEST_ID,
            "command": command,
            "params": params,
        }

    def create_plan(self, credential_id: str = "ops-call-mac-fixture") -> dict[str, object]:
        response = self.gateway.handle(
            self.request(
                "plan",
                {
                    "action": "ops003.fixture.read",
                    "target": "host:lab-global-primary",
                    "params_file": "empty.json",
                },
            ),
            credential_id=credential_id,
        )
        self.assertTrue(response["ok"])
        return response["data"]["plan"]  # type: ignore[index]

    def test_actions_list_is_a_normal_structured_response(self) -> None:
        response = self.gateway.handle(self.request("actions.list", {}), credential_id="ops-call-mac-fixture")
        self.assertTrue(response["ok"])
        action_ids = {item["action_id"] for item in response["data"]["actions"]}  # type: ignore[index]
        self.assertIn("ops003.fixture.read", action_ids)
        self.assertNotIn("ops-call-mac-fixture", json.dumps(response))

    def test_unregistered_credential_is_denied_without_identity_leak(self) -> None:
        response = self.gateway.handle(self.request("actions.list", {}), credential_id="not-registered")
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "precondition_failed")  # type: ignore[index]
        self.assertNotIn("not-registered", json.dumps(response))

    def test_plan_uses_bound_owner_and_rejects_identity_fields(self) -> None:
        plan = self.create_plan()
        self.assertEqual(plan["owner_id"], OWNER)
        self.assertEqual(stat.S_IMODE(self.store_root.stat().st_mode), 0o710)
        (self.params_root / "spoof.json").write_text('{"owner_id":"44444444-4444-4444-8444-444444444444"}\n', encoding="utf-8")
        response = self.gateway.handle(
            self.request(
                "plan",
                {
                    "action": "ops003.fixture.read",
                    "target": "host:lab-global-primary",
                    "params_file": "spoof.json",
                },
            ),
            credential_id="ops-call-mac-fixture",
        )
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")  # type: ignore[index]

        for field in ("owner_id", "actor", "role", "credential_id", "uid"):
            with self.subTest(field=field):
                response = self.gateway.handle(
                    self.request("actions.list", {field: OTHER_OWNER}),
                    credential_id="ops-call-mac-fixture",
                )
                self.assertFalse(response["ok"])
                self.assertEqual(response["error"]["code"], "invalid_request")  # type: ignore[index]

    def test_second_credential_can_share_owner_but_other_owner_cannot_use_plan(self) -> None:
        plan = self.create_plan()
        shared = self.gateway.handle(
            self.request("apply", {"plan_id": plan["plan_id"]}),
            credential_id="ops-call-other-computer-fixture",
        )
        self.assertEqual(shared["error"]["code"], "approval_required")  # type: ignore[index]
        denied = self.gateway.handle(
            self.request("apply", {"plan_id": plan["plan_id"]}),
            credential_id="ops-call-other-owner-fixture",
        )
        self.assertEqual(denied["error"]["code"], "precondition_failed")  # type: ignore[index]

    def test_apply_never_accepts_caller_approval_and_unknown_command_is_allowlist_denied(self) -> None:
        plan = self.create_plan()
        response = self.gateway.handle(
            self.request("apply", {"plan_id": plan["plan_id"], "approved": True}),
            credential_id="ops-call-mac-fixture",
        )
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")  # type: ignore[index]
        response = self.gateway.handle(
            self.request("status", {"target": "host:lab-global-primary"}),
            credential_id="ops-call-mac-fixture",
        )
        self.assertEqual(response["error"]["code"], "unsupported_command")  # type: ignore[index]

    def test_invalid_bytes_and_secret_sentinel_are_not_echoed(self) -> None:
        response = self.gateway.handle_bytes(b"not-json FAKE_SECRET_SENTINEL")
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_json")  # type: ignore[index]
        self.assertNotIn("FAKE_SECRET_SENTINEL", json.dumps(response))

    def test_serve_writes_one_json_response_and_uses_system_context(self) -> None:
        request = canonical_json_bytes(self.request("actions.list", {}))
        output = io.BytesIO()
        exit_code = self.gateway.serve(
            credential_id="ops-call-mac-fixture",
            stdin=io.BytesIO(request),
            stdout=output,
            environment={"OPS_CONTROL_CREDENTIAL_ID": "ops-call-mac-fixture"},
        )
        self.assertEqual(exit_code, 0)
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertTrue(json.loads(output.getvalue())["ok"])

    def test_system_apply_delegates_request_v1_through_fixed_broker(self) -> None:
        calls: list[dict[str, object]] = []

        def runner(request: dict[str, object]) -> dict[str, object]:
            calls.append(dict(request))
            return make_response(
                request["request_id"],  # type: ignore[arg-type]
                ok=True,
                data={
                    "run_id": "77777777-7777-4777-8777-777777777777",
                    "status": "unknown",
                },
                validate=False,
            )

        delegated = Gateway(
            identity_provider=self.identity,
            resource_provider=self.provider,
            store_root=self.store_root,
            params_root=self.params_root,
            delegate_apply=True,
            delegation_runner=runner,
            now=lambda: "2026-09-10T01:00:00Z",
        )
        plans_dir = self.store_root / "plans"
        plans_dir.mkdir(mode=0o750)
        Path.chmod(plans_dir, 0o2750)
        chmod_calls: list[Path] = []
        original_chmod = Path.chmod

        def track_chmod(path: Path, mode: int) -> None:
            chmod_calls.append(path)
            original_chmod(path, mode)

        with patch.object(Path, "chmod", new=track_chmod):
            planned = delegated.handle(
                self.request(
                    "plan",
                    {
                        "action": "ops005.noop",
                        "target": "host:lab-global-primary",
                        "params_file": "empty.json",
                    },
                ),
                credential_id="ops-call-mac-fixture",
            )
        self.assertTrue(planned["ok"])
        plan = planned["data"]["plan"]  # type: ignore[index]
        plan_file = self.store_root / "plans" / f"{plan['plan_id']}.json"
        self.assertEqual(stat.S_IMODE(plan_file.stat().st_mode), 0o640)
        self.assertEqual(chmod_calls, [plan_file])
        self.assertEqual(stat.S_IMODE(plans_dir.stat().st_mode), 0o2750)
        applied = delegated.handle(
            self.request("apply", {"plan_id": plan["plan_id"]}),  # type: ignore[index]
            credential_id="ops-call-mac-fixture",
        )
        self.assertTrue(applied["ok"])
        self.assertEqual(applied["data"]["status"], "unknown")  # type: ignore[index]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["command"], "apply")
        self.assertEqual(set(calls[0]["params"]), {"plan_id"})  # type: ignore[arg-type,index]
        self.assertNotIn("owner_id", json.dumps(calls[0]))


if __name__ == "__main__":
    unittest.main()
