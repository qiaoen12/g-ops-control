from __future__ import annotations

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from ops.cli import EXIT_INPUT, EXIT_OK, EXIT_PRECONDITION, main, run_doctor
from ops.resources import TrustedResourceProvider


class CliTests(unittest.TestCase):
    def invoke(self, *args: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(list(args))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_offline_doctor_emits_one_json_response_and_no_network_result(self) -> None:
        code, output, stderr = self.invoke("doctor", "--offline")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(len(output.strip().splitlines()), 1)
        response = json.loads(output)
        self.assertTrue(response["ok"])
        self.assertTrue(response["data"]["offline"])
        self.assertFalse(response["data"]["network_used"])
        self.assertEqual(response["data"]["references"]["logging_policy"], "ok")
        self.assertNotIn("OLD_VPS_ROOT", output)
        self.assertNotIn("FAKE_SECRET_SENTINEL", output)
        self.assertEqual(stderr, "")

    def test_human_rendering_uses_same_doctor_data(self) -> None:
        data, code = run_doctor()
        self.assertEqual(code, EXIT_OK)
        code, output, _ = self.invoke("doctor", "--offline", "--human")
        self.assertEqual(code, EXIT_OK)
        self.assertIn(f"schema_count: {data['schema_count']}", output)
        self.assertIn("network_used: False", output)

    def test_invalid_arguments_are_json_and_nonzero(self) -> None:
        code, output, stderr = self.invoke("doctor")
        self.assertEqual(code, EXIT_INPUT)
        response = json.loads(output)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")
        self.assertEqual(stderr, "")
        code, output, _ = self.invoke("doctor", "--offline", "--resource-root", "/tmp/unsafe")
        self.assertEqual(code, EXIT_INPUT)
        self.assertEqual(json.loads(output)["error"]["code"], "invalid_request")

    def test_unimplemented_commands_fail_without_business_result(self) -> None:
        for argv in (
            ("status",),
            ("package", "validate", "--manifest", "/tmp/params.json"),
        ):
            with self.subTest(argv=argv):
                code, output, stderr = self.invoke(*argv)
                self.assertEqual(code, EXIT_PRECONDITION)
                response = json.loads(output)
                self.assertFalse(response["ok"])
                self.assertEqual(response["data"], None)
                self.assertEqual(response["error"]["code"], "unsupported_command")
                self.assertNotIn("OLD_VPS_ROOT", output)
                self.assertEqual(stderr, "")

    def test_actions_list_loads_release_manifest_and_shows_frozen_reason(self) -> None:
        code, output, stderr = self.invoke("actions", "list")
        self.assertEqual(code, EXIT_OK)
        response = json.loads(output)
        self.assertTrue(response["ok"])
        actions = {item["action_id"]: item for item in response["data"]["actions"]}
        self.assertEqual(actions["ops003.fixture.read"]["status"], "enabled")
        self.assertEqual(actions["software.check"]["status"], "frozen")
        self.assertIn("OPS-001", actions["software.check"]["unavailable_reason"])
        self.assertNotIn("private", output.lower())
        self.assertEqual(stderr, "")

    def test_doctor_accepts_only_injected_trusted_sanitized_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            infra = Path(temp) / "ops-control"
            (infra / "policy").mkdir(parents=True)
            shutil.copyfile(Path(__file__).parents[2] / "../../2-infra/ops-control/policy/logging.yml", infra / "policy/logging.yml")
            shutil.copyfile(Path(__file__).parents[2] / "../../2-infra/ops-control/policy/credential-refs.yml", infra / "policy/credential-refs.yml")
            data, code = run_doctor(provider=TrustedResourceProvider(infra))
            self.assertEqual(code, EXIT_OK)
            self.assertEqual(data["references"]["logging_policy"], "ok")
            self.assertEqual(data["references"]["credential_refs"], "ok")


if __name__ == "__main__":
    unittest.main()
