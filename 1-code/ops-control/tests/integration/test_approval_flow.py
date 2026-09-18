from __future__ import annotations

import base64
import http.client
import json
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ops.approval.server import ApprovalHTTPServer
from ops.approval.service import ApprovalService, WebAuthnConfig
from ops.approval.store import ApprovalStore, CredentialRecord, MemoryCredentialStore
from ops.plans import FixtureResolver, PlanService, StaticIdentityProvider
from ops.registry import ActionRegistry
from ops.resources import TrustedResourceProvider
from ops.storage import AtomicJsonStore


ROOT = Path(__file__).parents[2] / ".." / ".."
OWNER = "33333333-3333-4333-8333-333333333333"
PORT = 18767
ORIGIN = f"http://localhost:{PORT}"


class ApprovalFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name) / "store"
        root.mkdir(mode=0o700)
        self.store = AtomicJsonStore(root)
        provider = TrustedResourceProvider(ROOT / "2-infra" / "ops-control")
        self.plan = PlanService(
            registry=ActionRegistry(provider),
            inventory=__import__("ops.inventory", fromlist=["Inventory"]).Inventory.from_provider(provider),
            policy=__import__("ops.inventory", fromlist=["PolicyEvaluator"]).PolicyEvaluator.from_provider(provider),
            store=self.store,
            identity_provider=StaticIdentityProvider(OWNER),
            resolver=FixtureResolver(),
            now=lambda: "2026-09-11T12:00:00Z",
        ).create_plan("ops005.noop", "host:lab-global-primary", {})
        self.credential = CredentialRecord(
            credential_ref="mac-passkey-fixture",
            owner_id=OWNER,
            credential_id=b"http-credential",
            public_key=b"http-public-key",
            sign_count=0,
            environment="trusted",
            status="active",
            created_at="2026-09-11T12:00:00Z",
        )
        credentials = MemoryCredentialStore([self.credential], environment="trusted")
        self.service = ApprovalService(
            plan_store=self.store,
            approval_store=ApprovalStore(self.store),
            credential_store=credentials,
            config=WebAuthnConfig(port=PORT, origin=ORIGIN),
            now=lambda: "2026-09-11T12:00:00Z",
            clock=lambda: datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc).timestamp(),
        )
        self.server = ApprovalHTTPServer(self.service, host="127.0.0.1", port=PORT)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, method: str, path: str, body: object | None = None, *, host: str | None = None, origin: str | None = ORIGIN) -> tuple[int, dict[str, object] | str]:
        connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=3)
        headers = {"Host": host or f"localhost:{PORT}"}
        if origin is not None:
            headers["Origin"] = origin
        encoded = None
        if body is not None:
            encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=encoded, headers=headers)
        response = connection.getresponse()
        raw = response.read().decode("utf-8")
        connection.close()
        try:
            return response.status, json.loads(raw)
        except json.JSONDecodeError:
            return response.status, raw

    def credential_payload(self) -> dict[str, object]:
        raw_id = base64.urlsafe_b64encode(self.credential.credential_id).rstrip(b"=").decode("ascii")
        return {
            "id": raw_id,
            "rawId": raw_id,
            "type": "public-key",
            "response": {"clientDataJSON": "AA", "authenticatorData": "AA", "signature": "AA", "userHandle": None},
        }

    def test_loopback_host_origin_and_server_plan_display(self) -> None:
        status, created = self.request("POST", "/sessions", {"plan_id": self.plan["plan_id"]})
        self.assertEqual(status, 200)
        self.assertTrue(created["ok"])
        session_id = created["session_id"]
        status, page = self.request("GET", f"/approval/{session_id}", origin=None)
        self.assertEqual(status, 200)
        self.assertIn("ops005.noop", page)
        self.assertIn(self.plan["plan_digest"], page)
        self.assertIn("Confirm with passkey", page)
        denied_status, denied = self.request("POST", "/sessions", {"plan_id": self.plan["plan_id"]}, host="evil.example:18767")
        self.assertEqual(denied_status, 403)
        self.assertEqual(denied["error"], "approval_boundary_denied")
        denied_status, denied = self.request("POST", f"/approval/{session_id}/options", {}, origin="http://127.0.0.1:18767")
        self.assertEqual(denied_status, 403)
        self.assertEqual(denied["error"], "approval_boundary_denied")

    def test_server_verifies_assertion_then_writes_existing_approval_v1(self) -> None:
        _, created = self.request("POST", "/sessions", {"plan_id": self.plan["plan_id"]})
        session_id = created["session_id"]
        status, options = self.request("POST", f"/approval/{session_id}/options", {})
        self.assertEqual(status, 200)
        self.assertTrue(options["options"]["userVerification"] == "required")
        with patch(
            "webauthn.verify_authentication_response",
            return_value=SimpleNamespace(credential_id=self.credential.credential_id, new_sign_count=1, user_verified=True),
        ):
            status, result = self.request(
                "POST",
                f"/approval/{session_id}/verify",
                {"challenge_token": options["challenge_token"], "credential": self.credential_payload()},
            )
        self.assertEqual(status, 200)
        self.assertTrue(result["user_verified"])
        approval = ApprovalStore(self.store).get_for_plan(self.plan["plan_id"])
        self.assertEqual(approval["plan_digest"], self.plan["plan_digest"])
        self.assertEqual(approval["owner_id"], OWNER)
        self.assertEqual(approval["approver_credential_id"], "mac-passkey-fixture")


if __name__ == "__main__":
    unittest.main()
