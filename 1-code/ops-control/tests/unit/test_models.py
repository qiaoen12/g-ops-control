from __future__ import annotations

import json
import math
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from ops.models import (
    MODEL_SCHEMAS,
    ModelError,
    canonical_digest,
    canonical_json_bytes,
    is_valid_utc,
    schema_document,
    strict_json_loads,
    validate_model,
    validate_schema_documents,
)


FIXTURES = Path(__file__).parents[1] / "fixtures" / "contracts"


class ModelValidationTests(unittest.TestCase):
    def load_fixture(self, filename: str) -> dict:
        return json.loads((FIXTURES / "valid" / filename).read_text(encoding="utf-8"))

    def test_all_registered_valid_fixtures(self) -> None:
        fixture_names = {
            "Request": "request.json",
            "Response": "response.json",
            "HostProjection": "host-projection.json",
            "Observation": "observation.json",
            "SoftwareFact": "software-fact.json",
            "BackupFact": "backup-fact.json",
            "ServiceFact": "service-fact.json",
            "ActionDescriptor": "action-descriptor.json",
            "Plan": "plan.json",
            "Approval": "approval.json",
            "PerHostResult": "per-host-result.json",
            "RunSummary": "run-summary.json",
            "KnowledgeNote": "knowledge-note.json",
            "ExportManifest": "export-manifest.json",
            "OperationPackage": "operation-package.json",
            "CredentialRef": "credential-ref-shared.json",
            "CredentialRequirement": "credential-requirement.json",
            "RecoveryEvidence": "recovery-evidence.json",
            "SourceProvenance": "source-provenance.json",
            "UseRecord": "use-record.json",
            "LaunchRecord": "launch-record.json",
            "BlockerRecord": "blocker-record.json",
            "LocalFact": "local-fact.json",
            "LocalPlan": "local-plan.json",
        }
        self.assertEqual(set(fixture_names), set(MODEL_SCHEMAS))
        for model_name, filename in fixture_names.items():
            with self.subTest(model=model_name):
                validate_model(model_name, self.load_fixture(filename))

    def test_local_client_has_no_remote_connection_reference(self) -> None:
        validate_model("HostProjection", self.load_fixture("host-projection-local-client.json"))

    def test_rejects_unknown_fields_and_bad_request_values(self) -> None:
        cases = [
            ("Request", "request-unknown-field.json"),
            ("Request", "request-unknown-param.json"),
            ("Request", "request-bad-enum.json"),
            ("Request", "request-missing-field.json"),
            ("HostProjection", "host-bad-id.json"),
            ("HostProjection", "host-server-null-connection.json"),
            ("SourceProvenance", "source-secret-origin.json"),
            ("CredentialRef", "credential-secret-field.json"),
            ("Plan", "plan-unknown-field.json"),
        ]
        for model_name, filename in cases:
            with self.subTest(model=model_name, fixture=filename):
                with self.assertRaises(ModelError):
                    validate_model(model_name, json.loads((FIXTURES / "reject" / filename).read_text()))

    def test_rejects_nan_infinity_and_floats(self) -> None:
        with self.assertRaises(ModelError):
            strict_json_loads((FIXTURES / "reject" / "request-nan.json").read_text())
        request = self.load_fixture("request.json")
        request["params"]["offline"] = 1.0
        with self.assertRaises(ModelError):
            validate_model("Request", request)
        with self.assertRaises(ModelError):
            canonical_json_bytes({"value": math.inf})

    def test_rejects_semantically_invalid_utc_dates_and_times(self) -> None:
        response = self.load_fixture("response.json")
        checker = FormatChecker()
        checker.checks("date-time", raises=ValueError)(is_valid_utc)
        validator = Draft202012Validator(schema_document("Response"), format_checker=checker)
        self.assertEqual(schema_document("Response")["$defs"]["utc"]["format"], "date-time")
        for invalid in (
            "2024-02-30T12:00:00Z",
            "2023-02-29T12:00:00Z",
            "2024-01-01T24:00:00Z",
            "2024-01-01T12:60:00Z",
            "2024-01-01T12:00:60Z",
        ):
            with self.subTest(timestamp=invalid):
                candidate = dict(response)
                candidate["generated_at"] = invalid
                self.assertTrue(list(validator.iter_errors(candidate)))
                with self.assertRaises(ModelError):
                    validate_model("Response", candidate)

    def test_digest_is_key_order_independent_and_lowercase(self) -> None:
        first = {"b": {"y": 2, "x": 1}, "a": ["v", 3]}
        second = {"a": ["v", 3], "b": {"x": 1, "y": 2}}
        self.assertEqual(canonical_digest(first), canonical_digest(second))
        self.assertRegex(canonical_digest(first), r"^[0-9a-f]{64}$")

    def test_plan_and_package_digests_are_bound(self) -> None:
        plan = self.load_fixture("plan.json")
        package = self.load_fixture("operation-package.json")
        self.assertEqual(plan["plan_digest"], canonical_digest(plan, omit=("plan_digest",)))
        self.assertEqual(package["content_digest"], canonical_digest(package, omit=("package_id", "content_digest")))
        plan["resolved_params"]["software_id"] = "changed"
        with self.assertRaises(ModelError):
            validate_model("Plan", plan)
        package["typed_params"]["message"] = 42
        with self.assertRaises(ModelError):
            validate_model("OperationPackage", package)

    def test_local_fact_submit_request_uses_the_shared_schema(self) -> None:
        request = {
            "schema_version": 1,
            "request_id": "11111111-1111-4111-8111-111111111111",
            "command": "local.fact.submit",
            "params": {
                "host_id": "lab-local-client",
                "software_id": "ops-core",
                "platform": {"os": "macos", "family": "darwin", "arch": "arm64"},
                "install_kind": "package",
                "installed_version": "1.2.3",
                "source": {"kind": "file", "origin": "fixtures/local.json", "version": None, "digest": "a" * 64},
                "observed_at": "2026-09-10T00:00:00Z",
                "evidence_summary": "local read",
            },
        }
        validate_model("Request", request)

    def test_meta_schema_self_check_includes_all_objects(self) -> None:
        self.assertEqual(len(validate_schema_documents()), len(MODEL_SCHEMAS))
        for model_name in MODEL_SCHEMAS:
            with self.subTest(model=model_name):
                Draft202012Validator.check_schema(schema_document(model_name))

    def test_fixed_input_regressions_are_expressible(self) -> None:
        software = self.load_fixture("software-fact.json")
        self.assertEqual(software["source"]["kind"], "file")
        self.assertIsNone(software["source"]["version"])
        self.assertEqual(software["platform"]["os"], "linux")
        service = self.load_fixture("service-fact.json")
        self.assertEqual(service["actual_state"], "unresolved-conflict")
        windows = self.load_fixture("host-projection-local-client.json")
        self.assertEqual(windows["platform"]["os"], "windows")
        recovery = self.load_fixture("recovery-evidence.json")
        self.assertEqual(recovery["status"], "blocked")
        provenance = self.load_fixture("source-provenance.json")
        self.assertEqual(provenance["first_read_digest"], provenance["reverified_digest"])
        provenance["reverified_digest"] = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        with self.assertRaises(ModelError):
            validate_model("SourceProvenance", provenance)

    def test_safe_origin_rejects_parent_path_segments(self) -> None:
        base = self.load_fixture("source-provenance.json")
        accepted = (
            "fixtures/source.yml",
            "fixtures/source..v1.yml",
        )
        rejected = (
            "..",
            "../source.yml",
            "fixtures/../source.yml",
            "fixtures/source/..",
        )
        for origin in accepted:
            with self.subTest(origin=origin, expected="accepted"):
                candidate = {**base, "source": {**base["source"], "origin": origin}}
                validate_model("SourceProvenance", candidate)
        for origin in rejected:
            with self.subTest(origin=origin, expected="rejected"):
                candidate = {**base, "source": {**base["source"], "origin": origin}}
                with self.assertRaises(ModelError):
                    validate_model("SourceProvenance", candidate)

    def test_nested_credential_requirements_are_metadata_only(self) -> None:
        action = self.load_fixture("action-descriptor.json")
        action["credential_requirements"] = [{
            "credential_id": "inventory-private-host",
            "scope": "per-host",
            "required": True,
            "host_id": "lab-global-primary",
            "reason": "host-scoped reference",
        }]
        validate_model("ActionDescriptor", action)
        action["credential_requirements"][0]["secret"] = "FAKE_SECRET_SENTINEL"
        with self.assertRaises(ModelError):
            validate_model("ActionDescriptor", action)


if __name__ == "__main__":
    unittest.main()
