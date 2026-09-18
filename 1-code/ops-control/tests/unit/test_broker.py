from __future__ import annotations

import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops.executor import (
    ForcedCommandError,
    clean_forced_environment,
    forced_command_options,
    parse_bound_credential,
    run_forced_command,
    validate_forced_command,
)
from ops.executor.broker import BrokerConfig, BrokerError, FixedBroker
from ops.cli import make_response
from ops.models import canonical_json_bytes


class BrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.release_root = root / "releases"
        self.release_root.mkdir(mode=0o700)
        bundle = self.release_root / "bundle-fixture"
        bundle.mkdir(mode=0o700)
        (self.release_root / "current").symlink_to(bundle, target_is_directory=True)
        self.config = BrokerConfig(
            interpreter=Path("/usr/bin/python3"),
            release_root=self.release_root,
            code_dir=root / "code",
            data_dir=root / "data",
            allowed_capabilities=("identity-boundary",),
        )
        self.broker = FixedBroker(self.config)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_fixed_invocation_resolves_release_and_scrubs_environment(self) -> None:
        invocation = self.broker.build_invocation("identity-boundary")
        self.assertEqual(invocation.release.name, "bundle-fixture")
        self.assertEqual(invocation.argv[-2:], ("--capability", "identity-boundary"))
        self.assertNotIn("PYTHONPATH", invocation.environment)
        self.assertNotIn("ANSIBLE_CONFIG", invocation.environment)
        self.assertEqual(invocation.environment["PATH"], "/usr/local/libexec/ops-control:/usr/bin:/bin")

    def test_business_dispatch_is_disabled_and_never_has_a_runner(self) -> None:
        with self.assertRaises(BrokerError):
            self.broker.dispatch("identity-boundary")
        with self.assertRaises(BrokerError):
            BrokerConfig(
                interpreter=Path("/usr/bin/python3"),
                release_root=self.release_root,
                code_dir=Path(self.temp.name) / "code",
                data_dir=Path(self.temp.name) / "data",
                allowed_capabilities=("business-write",),
            )

    def test_delegate_uses_request_v1_and_accepts_only_fixed_broker_response(self) -> None:
        request = {
            "schema_version": 1,
            "request_id": "11111111-1111-4111-8111-111111111111",
            "command": "apply",
            "params": {"plan_id": "22222222-2222-4222-8222-222222222222"},
        }
        seen: list[dict[str, object]] = []

        def runner(value: dict[str, object]) -> dict[str, object]:
            seen.append(dict(value))
            return make_response(
                request["request_id"],  # type: ignore[arg-type]
                ok=True,
                data={"run_id": "33333333-3333-4333-8333-333333333333", "status": "unknown"},
                validate=False,
            )

        result = self.broker.delegate(request, runner=runner)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(seen, [request])
        with self.assertRaises(BrokerError) as invalid:
            self.broker.delegate({**request, "params": {"plan_id": request["params"]["plan_id"], "owner_id": "x"}}, runner=runner)  # type: ignore[index]
        self.assertEqual(invalid.exception.code, "invalid_request")

    def test_delegate_keeps_structured_denial_even_when_broker_returns_nonzero(self) -> None:
        request = {
            "schema_version": 1,
            "request_id": "44444444-4444-4444-8444-444444444444",
            "command": "apply",
            "params": {"plan_id": "55555555-5555-4555-8555-555555555555"},
        }
        denial = make_response(
            request["request_id"],  # type: ignore[arg-type]
            ok=False,
            error={"code": "approval_required", "message": "denied", "details": {}},
            validate=False,
        )
        with patch(
            "subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=[],
                returncode=1,
                stdout=canonical_json_bytes(denial) + b"\n",
            ),
        ) as run:
            with self.assertRaises(BrokerError) as denied:
                self.broker.delegate(request)
        self.assertEqual(denied.exception.code, "approval_required")
        command = run.call_args.args[0]
        self.assertEqual(command, ["/usr/bin/sudo", "-n", "-u", "ops-exec", "/usr/local/libexec/ops-control/broker"])

    def test_caller_cannot_supply_any_execution_or_path_field(self) -> None:
        for field in ("executable", "argv", "systemd_unit", "cwd", "key_path", "env", "release_path", "path"):
            with self.subTest(field=field):
                with self.assertRaises(BrokerError) as raised:
                    self.broker.dispatch("identity-boundary", {field: "FAKE_SECRET_SENTINEL"})
                self.assertNotIn("FAKE_SECRET_SENTINEL", str(raised.exception))

    def test_forced_command_rejects_shell_subsystem_forwarding_and_environment(self) -> None:
        with self.assertRaises(ForcedCommandError):
            validate_forced_command(original_command="/bin/sh")
        with self.assertRaises(ForcedCommandError):
            validate_forced_command(pty_requested=True)
        with self.assertRaises(ForcedCommandError):
            validate_forced_command(subsystem="sftp")
        with self.assertRaises(ForcedCommandError):
            validate_forced_command(port_forwarding=True)
        with self.assertRaises(ForcedCommandError):
            validate_forced_command(environment={"PYTHONPATH": "FAKE_SECRET_SENTINEL"})

    def test_fixed_environment_does_not_inherit_dangerous_values(self) -> None:
        clean = clean_forced_environment(
            {
                "PATH": "/attacker/bin",
                "PYTHONPATH": "FAKE_SECRET_SENTINEL",
                "ANSIBLE_CONFIG": "/attacker/ansible.cfg",
            }
        )
        self.assertEqual(clean["PATH"], "/usr/local/libexec/ops-control:/usr/bin:/bin")
        self.assertNotIn("PYTHONPATH", clean)
        self.assertNotIn("ANSIBLE_CONFIG", clean)

    def test_forced_wrapper_rejects_inherited_ssh_features(self) -> None:
        class UnexpectedGateway:
            def serve(self, **_kwargs):
                self.called = True
                return 0

        with patch.dict(os.environ, {"SSH_TTY": "/dev/pts/fixture"}, clear=True):
            with self.assertRaises(ForcedCommandError):
                run_forced_command(UnexpectedGateway(), stdin=io.BytesIO(), stdout=io.BytesIO())

    def test_forced_key_binds_a_safe_credential_and_rejects_extra_arguments(self) -> None:
        self.assertEqual(parse_bound_credential(("--credential-id", "ops-call-mac-fixture")), "ops-call-mac-fixture")
        options = forced_command_options("ops-call-mac-fixture")
        self.assertIn(
            'command="/usr/bin/python3 -E -s /usr/local/libexec/ops-control/ops-call --credential-id ops-call-mac-fixture"',
            options,
        )
        for args in ((), ("--credential-id",), ("--credential-id", "../escape"), ("--shell", "id")):
            with self.subTest(args=args):
                with self.assertRaises(ForcedCommandError):
                    parse_bound_credential(args)

    def test_forced_wrapper_passes_key_binding_and_rejects_context_mismatch(self) -> None:
        class RecordingGateway:
            def __init__(self):
                self.kwargs = None

            def serve(self, **kwargs):
                self.kwargs = kwargs
                return 0

        gateway = RecordingGateway()
        self.assertEqual(
            run_forced_command(
                gateway,
                stdin=io.BytesIO(b"{}"),
                stdout=io.BytesIO(),
                environment={},
                credential_id="ops-call-mac-fixture",
            ),
            0,
        )
        self.assertEqual(gateway.kwargs["credential_id"], "ops-call-mac-fixture")
        self.assertEqual(
            gateway.kwargs["environment"],
            {"OPS_CONTROL_CREDENTIAL_ID": "ops-call-mac-fixture"},
        )
        with self.assertRaises(ForcedCommandError):
            run_forced_command(
                RecordingGateway(),
                stdin=io.BytesIO(b"{}"),
                stdout=io.BytesIO(),
                environment={"OPS_CONTROL_CREDENTIAL_ID": "ops-call-other-owner-fixture"},
                credential_id="ops-call-mac-fixture",
            )


if __name__ == "__main__":
    unittest.main()
