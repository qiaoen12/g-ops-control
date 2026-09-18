from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from client.transport import SSHConnectionConfig, SSHResult, SystemSSHTransport, Transport, TransportError


REQUEST = {
    "schema_version": 1,
    "request_id": "11111111-1111-4111-8111-111111111111",
    "command": "doctor",
    "params": {"offline": True},
}


class TransportTests(unittest.TestCase):
    def test_default_transport_is_inert(self) -> None:
        with self.assertRaises(TransportError) as raised:
            Transport().send(REQUEST)
        self.assertEqual(raised.exception.code, "transport_unavailable")

    def test_injected_transport_is_explicit_and_validated(self) -> None:
        seen: list[bytes] = []

        def sender(payload: bytes) -> bytes:
            seen.append(payload)
            return b'{"schema_version":1,"request_id":"11111111-1111-4111-8111-111111111111","ok":true,"data":{},"error":null,"generated_at":"2026-09-10T00:00:00Z"}'

        response = Transport(sender=sender).send(REQUEST)
        self.assertTrue(response["ok"])
        self.assertEqual(len(seen), 1)
        self.assertNotIn(b"shell", seen[0])

    def test_sender_exception_is_not_leaked(self) -> None:
        def sender(_payload: bytes) -> bytes:
            raise RuntimeError("FAKE_SECRET_SENTINEL")

        with self.assertRaises(TransportError) as raised:
            Transport(sender=sender).send(REQUEST)
        self.assertNotIn("FAKE_SECRET_SENTINEL", str(raised.exception))

    def system_transport(self, runner, **overrides) -> SystemSSHTransport:
        with tempfile.NamedTemporaryFile() as known_hosts:
            config_values = {
                "hostname": "lab.example",
                "user": "ops-call",
                "port": 2222,
                "identity_file": Path("/tmp/ops-call-fixture.key"),
                "known_hosts_file": Path(known_hosts.name),
                "connect_timeout": 1.0,
                "total_timeout": 3.0,
                "max_input_bytes": 1 << 20,
                "max_output_bytes": 1 << 20,
            }
            config_values.update(overrides)
            # The config only stores trusted path metadata; the temporary
            # file remains alive while command construction is asserted.
            return SystemSSHTransport(SSHConnectionConfig(**config_values), runner=runner)

    @staticmethod
    def response_bytes() -> bytes:
        return b'{"schema_version":1,"request_id":"11111111-1111-4111-8111-111111111111","ok":true,"data":{},"error":null,"generated_at":"2026-09-10T00:00:00Z"}'

    def test_system_transport_uses_fixed_ssh_argv_and_structured_stdin(self) -> None:
        seen: dict[str, object] = {}

        def runner(argv, input_data, timeout):
            seen["argv"] = tuple(argv)
            seen["input"] = input_data
            seen["timeout"] = timeout
            return SSHResult(0, self.response_bytes())

        transport = self.system_transport(runner)
        response = transport.send(REQUEST)
        argv = seen["argv"]
        self.assertTrue(response["ok"])
        self.assertEqual(argv[-1], "ops-call")
        self.assertEqual(argv[-2], "ops-call@lab.example")
        self.assertIn("-T", argv)
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn("ForwardAgent=no", argv)
        self.assertIn("ClearAllForwardings=yes", argv)
        self.assertNotIn("-A", argv)
        self.assertNotIn("accept-new", argv)
        self.assertNotIn("ProxyCommand", " ".join(argv))
        self.assertEqual(seen["input"], b'{"command":"doctor","params":{"offline":true},"request_id":"11111111-1111-4111-8111-111111111111","schema_version":1}')
        self.assertEqual(seen["timeout"], 3.0)

    def test_request_cannot_inject_ssh_options(self) -> None:
        called = False

        def runner(_argv, _input_data, _timeout):
            nonlocal called
            called = True
            return SSHResult(0, self.response_bytes())

        request = dict(REQUEST)
        request["params"] = {"ssh_options": ["-o", "ProxyCommand=FAKE_SECRET_SENTINEL"]}
        with self.assertRaises(TransportError):
            self.system_transport(runner).send(request)
        self.assertFalse(called)

    def test_nonzero_bad_fingerprint_and_stderr_sentinel_are_fail_closed(self) -> None:
        def runner(_argv, _input_data, _timeout):
            return SSHResult(255, b"", b"Host key verification failed FAKE_SECRET_SENTINEL")

        with self.assertRaises(TransportError) as raised:
            self.system_transport(runner).send(REQUEST)
        self.assertNotIn("FAKE_SECRET_SENTINEL", str(raised.exception))

    def test_timeout_is_fail_closed(self) -> None:
        def runner(argv, _input_data, timeout):
            raise subprocess.TimeoutExpired(cmd=list(argv), timeout=timeout)

        with self.assertRaises(TransportError):
            self.system_transport(runner).send(REQUEST)

    def test_output_limit_banner_bad_json_and_non_object_are_rejected(self) -> None:
        cases = (
            b"NOTICE\n" + self.response_bytes(),
            b"{not-json",
            b"[]",
        )
        for raw in cases:
            with self.subTest(raw=raw[:10]):
                with self.assertRaises(TransportError):
                    self.system_transport(lambda _argv, _input, _timeout, raw=raw: SSHResult(0, raw)).send(REQUEST)
        with self.assertRaises(TransportError):
            self.system_transport(
                lambda _argv, _input, _timeout: SSHResult(0, self.response_bytes()),
                max_output_bytes=16,
            ).send(REQUEST)

    def test_input_limit_and_invalid_utf8_are_rejected_without_process(self) -> None:
        with self.assertRaises(TransportError):
            self.system_transport(
                lambda _argv, _input, _timeout: SSHResult(0, self.response_bytes()),
                max_input_bytes=8,
            ).send(REQUEST)
        with self.assertRaises(TransportError):
            self.system_transport(lambda _argv, _input, _timeout: SSHResult(0, b"\xff")).send(REQUEST)


if __name__ == "__main__":
    unittest.main()
