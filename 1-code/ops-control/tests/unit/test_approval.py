from __future__ import annotations

import base64
import json
import os
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ops.approval.service import ApprovalError, ApprovalService, WebAuthnConfig
from ops.approval.store import ApprovalStore, CredentialRecord, CredentialStoreError, FileCredentialStore, MaintenanceContext, MemoryCredentialStore
from ops.models import utc_now
from ops.plans import FixtureResolver, PlanService, StaticIdentityProvider
from ops.registry import ActionRegistry
from ops.resources import TrustedResourceProvider
from ops.storage import AtomicJsonStore


ROOT = Path(__file__).parents[2] / ".." / ".."
OWNER = "33333333-3333-4333-8333-333333333333"
OTHER_OWNER = "44444444-4444-4444-8444-444444444444"


class FakeClock:
    def __init__(self) -> None:
        self.epoch = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc).timestamp()

    def now(self) -> str:
        return datetime.fromtimestamp(self.epoch, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    def __call__(self) -> float:
        return self.epoch

    def advance(self, seconds: int) -> None:
        self.epoch += seconds


class ApprovalUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        store_root = Path(self.temp.name) / "store"
        store_root.mkdir(mode=0o700)
        self.store = AtomicJsonStore(store_root)
        provider = TrustedResourceProvider(ROOT / "2-infra" / "ops-control")
        self.clock = FakeClock()
        self.plan = PlanService(
            registry=ActionRegistry(provider),
            inventory=__import__("ops.inventory", fromlist=["Inventory"]).Inventory.from_provider(provider),
            policy=__import__("ops.inventory", fromlist=["PolicyEvaluator"]).PolicyEvaluator.from_provider(provider),
            store=self.store,
            identity_provider=StaticIdentityProvider(OWNER),
            resolver=FixtureResolver(),
            now=self.clock.now,
        ).create_plan("ops005.noop", "host:lab-global-primary", {})
        self.credentials = MemoryCredentialStore(environment="trusted")
        fixture = json.loads(
            (Path(__file__).parents[1] / "fixtures" / "approval" / "credential-record.json").read_text(encoding="utf-8")
        )
        self.record = CredentialRecord(
            credential_ref=fixture["credential_ref"],
            owner_id=fixture["owner_id"],
            credential_id=base64.urlsafe_b64decode(fixture["credential_id"] + "=" * (-len(fixture["credential_id"]) % 4)),
            public_key=base64.urlsafe_b64decode(fixture["public_key"] + "=" * (-len(fixture["public_key"]) % 4)),
            sign_count=fixture["sign_count"],
            environment=fixture["environment"],
            status=fixture["status"],
            created_at=fixture["created_at"],
            revoked_at=fixture["revoked_at"],
        )
        self.credentials.put(self.record)
        self.service = ApprovalService(
            plan_store=self.store,
            approval_store=ApprovalStore(self.store),
            credential_store=self.credentials,
            config=WebAuthnConfig(port=18766, origin="http://localhost:18766"),
            now=self.clock.now,
            clock=self.clock,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _payload(self) -> dict[str, object]:
        raw_id = base64.urlsafe_b64encode(self.record.credential_id).rstrip(b"=").decode("ascii")
        return {
            "id": raw_id,
            "rawId": raw_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": "AA",
                "authenticatorData": "AA",
                "signature": "AA",
                "userHandle": None,
            },
        }

    def test_session_only_reads_plan_and_options_bind_owner_and_rp(self) -> None:
        session = self.service.open_session(self.plan["plan_id"])
        self.assertFalse(self._approval_exists())
        options = self.service.authentication_options(session.session_id)
        self.assertEqual(options["options"]["rpId"], "localhost")
        self.assertEqual(session.plan_digest, self.plan["plan_digest"])
        page = self.service.render_html(session.session_id)
        self.assertIn("action_version", page)
        self.assertIn("plan digest", page)
        self.assertIn("Confirm with passkey", page)
        self.assertNotIn("<script>alert", page)

    def test_missing_owner_credential_and_expired_session_are_denied(self) -> None:
        self.credentials = MemoryCredentialStore(
            [
                CredentialRecord(
                    credential_ref="other-passkey",
                    owner_id=OTHER_OWNER,
                    credential_id=b"other-credential",
                    public_key=b"other-public-key",
                    sign_count=0,
                    environment="trusted",
                    status="active",
                    created_at=self.clock.now(),
                )
            ],
            environment="trusted",
        )
        self.service.credential_store = self.credentials
        session = self.service.open_session(self.plan["plan_id"])
        with self.assertRaises(ApprovalError) as missing:
            self.service.authentication_options(session.session_id)
        self.assertEqual(missing.exception.code, "approval_required")
        self.clock.advance(601)
        with self.assertRaises(ApprovalError) as expired:
            self.service.plan_for_session(session.session_id)
        self.assertEqual(expired.exception.code, "approval_expired")

    def test_invalid_assertion_consumes_challenge_and_replay_is_rejected(self) -> None:
        session = self.service.open_session(self.plan["plan_id"])
        start = self.service.authentication_options(session.session_id)
        with self.assertRaises(ApprovalError) as first:
            self.service.verify_assertion(
                session.session_id,
                challenge_token=start["challenge_token"],
                credential=self._payload(),
            )
        self.assertEqual(first.exception.code, "authentication_failed")
        with self.assertRaises(ApprovalError) as replay:
            self.service.verify_assertion(
                session.session_id,
                challenge_token=start["challenge_token"],
                credential=self._payload(),
            )
        self.assertEqual(replay.exception.code, "authentication_failed")
        self.assertFalse(self._approval_exists())

    def test_expired_challenge_is_consumed_and_cannot_be_replayed(self) -> None:
        session = self.service.open_session(self.plan["plan_id"])
        start = self.service.authentication_options(session.session_id)
        self.clock.advance(121)
        with self.assertRaises(ApprovalError) as expired:
            self.service.verify_assertion(
                session.session_id,
                challenge_token=start["challenge_token"],
                credential=self._payload(),
            )
        self.assertEqual(expired.exception.code, "approval_expired")
        with self.assertRaises(ApprovalError) as replay:
            self.service.verify_assertion(
                session.session_id,
                challenge_token=start["challenge_token"],
                credential=self._payload(),
            )
        self.assertEqual(replay.exception.code, "authentication_failed")
        self.assertFalse(self._approval_exists())

    def test_assertion_uses_fixed_origin_rp_and_user_verification(self) -> None:
        session = self.service.open_session(self.plan["plan_id"])
        start = self.service.authentication_options(session.session_id)
        with patch(
            "webauthn.verify_authentication_response",
            return_value=SimpleNamespace(credential_id=self.record.credential_id, new_sign_count=1, user_verified=True),
        ) as verify:
            self.service.verify_assertion(
                session.session_id,
                challenge_token=start["challenge_token"],
                credential=self._payload(),
            )
        call = verify.call_args.kwargs
        self.assertEqual(call["expected_origin"], "http://localhost:18766")
        self.assertEqual(call["expected_rp_id"], "localhost")
        self.assertTrue(call["require_user_verification"])

    def test_two_concurrent_valid_assertions_publish_one_approval(self) -> None:
        first = self.service.open_session(self.plan["plan_id"])
        second = self.service.open_session(self.plan["plan_id"])
        first_start = self.service.authentication_options(first.session_id)
        second_start = self.service.authentication_options(second.session_id)
        barrier = threading.Barrier(2)
        results: list[dict[str, object]] = []
        errors: list[BaseException] = []

        def worker(session_id: str, token: str) -> None:
            try:
                barrier.wait(timeout=2)
                results.append(
                    self.service.verify_assertion(
                        session_id,
                        challenge_token=token,
                        credential=self._payload(),
                    )
                )
            except BaseException as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        with patch(
            "webauthn.verify_authentication_response",
            return_value=SimpleNamespace(credential_id=self.record.credential_id, new_sign_count=0, user_verified=True),
        ):
            threads = [
                threading.Thread(target=worker, args=(first.session_id, first_start["challenge_token"])),
                threading.Thread(target=worker, args=(second.session_id, second_start["challenge_token"])),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=3)
        self.assertFalse(errors)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["approval_id"], results[1]["approval_id"])
        self.assertEqual(self._approval_count(), 1)

    def test_valid_assertion_requires_user_verification_and_re_reads_plan(self) -> None:
        session = self.service.open_session(self.plan["plan_id"])
        start = self.service.authentication_options(session.session_id)
        with patch(
            "webauthn.verify_authentication_response",
            return_value=SimpleNamespace(credential_id=self.record.credential_id, new_sign_count=1, user_verified=False),
        ):
            with self.assertRaises(ApprovalError) as denied:
                self.service.verify_assertion(
                    session.session_id,
                    challenge_token=start["challenge_token"],
                    credential=self._payload(),
                )
        self.assertEqual(denied.exception.code, "authentication_failed")
        self.assertFalse(self._approval_exists())

    def test_file_store_separates_maintenance_metadata_from_counter_updates(self) -> None:
        root = Path(self.temp.name) / "credentials"
        metadata_root = root / "metadata"
        counter_root = root / "counters"
        store = FileCredentialStore(
            root,
            environment="trusted",
            metadata_root=metadata_root,
            counter_root=counter_root,
        )
        registered = store.register(
            credential_ref="file-passkey-fixture",
            owner_id=OWNER,
            credential_id=b"file-credential",
            public_key=b"file-public-key",
            sign_count=0,
            created_at=self.clock.now(),
            maintenance=MaintenanceContext(euid=os.geteuid()),
        )
        metadata_path = metadata_root / "credentials" / f"{registered.raw_id}.json"
        self.assertEqual(metadata_path.stat().st_mode & 0o777, 0o640)
        with self.assertRaises(CredentialStoreError):
            store.register(
                credential_ref="wrong-maintenance-fixture",
                owner_id=OWNER,
                credential_id=b"another-file-credential",
                public_key=b"another-file-public-key",
                sign_count=0,
                created_at=self.clock.now(),
                maintenance=MaintenanceContext(euid=os.geteuid() + 1),
            )
        updated = store.update_sign_count(registered, 3)
        self.assertEqual(updated.sign_count, 3)
        counter_path = counter_root / f"{registered.raw_id}.json"
        counter = json.loads(counter_path.read_text(encoding="utf-8"))
        self.assertEqual(counter["sign_count"], 3)
        self.assertNotIn("public_key", counter)
        self.assertNotIn("owner_id", counter)
        self.assertEqual(store.find_by_raw_id(registered.raw_id).sign_count, 3)
        with patch.object(store.counter_store, "read_json", side_effect=RuntimeError("counter is not maintenance-readable")):
            store.revoke(
                registered.raw_id,
                revoked_at=self.clock.now(),
                maintenance=MaintenanceContext(euid=os.geteuid()),
            )
        self.assertEqual(store._read_metadata_record(registered.raw_id).status, "revoked")

    def _approval_exists(self) -> bool:
        try:
            ApprovalStore(self.store).get_for_plan(self.plan["plan_id"])
        except Exception:
            return False
        return True

    def _approval_count(self) -> int:
        directory = Path(self.temp.name) / "store" / "approvals"
        return len(list(directory.glob("*.json"))) if directory.exists() else 0


if __name__ == "__main__":
    unittest.main()
