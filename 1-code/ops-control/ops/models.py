"""Strict v1 JSON models, canonicalization and digest helpers.

Models are intentionally dictionary-shaped so later consumers can pass the
validated JSON objects across process boundaries without a second protocol.
Validation is schema-first and then applies the few cross-field invariants
which JSON Schema cannot express without making the schemas unreadable.
"""

from __future__ import annotations

import copy
import importlib.resources
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping
from uuid import UUID, uuid4

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError as exc:  # pragma: no cover - exercised by doctor in a bare env
    Draft202012Validator = None  # type: ignore[assignment]
    FormatChecker = None  # type: ignore[assignment]
    _JSONSCHEMA_IMPORT_ERROR = exc
else:
    _JSONSCHEMA_IMPORT_ERROR = None


MODEL_SCHEMAS = {
    "Request": "request.v1.json",
    "Response": "response.v1.json",
    "HostProjection": "host-projection.v1.json",
    "Observation": "observation.v1.json",
    "SoftwareFact": "software-fact.v1.json",
    "BackupFact": "backup-fact.v1.json",
    "ServiceFact": "service-fact.v1.json",
    "ActionDescriptor": "action-descriptor.v1.json",
    "Plan": "plan.v1.json",
    "Approval": "approval.v1.json",
    "PerHostResult": "per-host-result.v1.json",
    "RunSummary": "run-summary.v1.json",
    "KnowledgeNote": "knowledge-note.v1.json",
    "ExportManifest": "export-manifest.v1.json",
    "OperationPackage": "operation-package.v1.json",
    "CredentialRef": "credential-ref.v1.json",
    "CredentialRequirement": "credential-requirement.v1.json",
    "RecoveryEvidence": "recovery-evidence.v1.json",
    "SourceProvenance": "source-provenance.v1.json",
    "UseRecord": "use-record.v1.json",
    "LaunchRecord": "launch-record.v1.json",
    "BlockerRecord": "blocker-record.v1.json",
    "LocalFact": "local-fact.v1.json",
    "LocalPlan": "local-plan.v1.json",
}

MAX_REQUEST_BYTES = 1 << 20

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$")
_SAFE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_UTC_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)
_SECRET_RE = re.compile(
    r"(?i)(?:-----begin .*private key-----|authorization\s*:|bearer\s+|\b(?:password|passwd|secret|token|api[_-]?key)\b\s*[:=]|sk-[a-z0-9])"
)


class ModelError(ValueError):
    """A safe validation error; messages never include raw instance values."""

    code = "invalid_request"

    def __init__(self, message: str, *, path: Iterable[Any] = ()) -> None:
        self.path = tuple(path)
        suffix = "" if not self.path else f" at {'/'.join(map(str, self.path))}"
        super().__init__(f"{message}{suffix}")


class ModelDependencyError(RuntimeError):
    code = "dependency_missing"


def new_uuid() -> str:
    return str(uuid4())


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def is_valid_utc(value: Any) -> bool:
    """Return whether a value is a strict, semantically valid UTC timestamp."""
    if not isinstance(value, str) or not _UTC_RE.fullmatch(value):
        return False
    if int(value[11:13]) > 23 or int(value[14:16]) > 59 or int(value[17:19]) > 59:
        return False
    try:
        # The regex fixes the RFC3339 surface form; fromisoformat performs the
        # calendar and clock validation (including leap-year/month lengths).
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return True


def _strict_format_checker() -> Any:
    if FormatChecker is None:  # pragma: no cover - guarded by validate_model
        return None
    checker = FormatChecker()
    # jsonschema's built-in date-time checker is intentionally syntax-focused
    # on some versions.  The common schema declares date-time, while this
    # instance binds that declaration to the strict UTC semantic predicate.
    checker.checks("date-time", raises=ValueError)(is_valid_utc)
    return checker


def is_uuid(value: Any) -> bool:
    return isinstance(value, str) and bool(_UUID_RE.fullmatch(value))


def _duplicate_key_error(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ModelError("duplicate JSON object key")
        result[key] = value
    return result


def strict_json_loads(text: str) -> Any:
    def reject_constant(value: str) -> Any:
        raise ModelError("JSON constants NaN/Infinity are not allowed")

    try:
        return json.loads(
            text,
            object_pairs_hook=_duplicate_key_error,
            parse_constant=reject_constant,
        )
    except ModelError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ModelError("malformed JSON") from exc


def _walk_json(value: Any, *, path: tuple[Any, ...] = ()) -> None:
    if isinstance(value, float):
        raise ModelError("floating-point and non-finite JSON values are not allowed", path=path)
    if isinstance(value, str) and len(value) > 8192:
        raise ModelError("free-form text exceeds 8192 characters", path=path)
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ModelError("JSON object keys must be strings", path=path)
            _walk_json(child, path=path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk_json(child, path=path + (index,))


def canonical_json_bytes(value: Any) -> bytes:
    _walk_json(value)
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ModelError("value cannot be represented as canonical JSON") from exc


def canonical_digest(value: Mapping[str, Any], *, omit: Iterable[str] = ()) -> str:
    omitted = set(omit)
    if not isinstance(value, Mapping):
        raise ModelError("digest input must be an object")
    payload = {key: copy.deepcopy(item) for key, item in value.items() if key not in omitted}
    import hashlib

    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _schema_resource(filename: str) -> str:
    try:
        return (importlib.resources.files("schema") / filename).read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError) as exc:
        raise ModelError(f"schema resource {filename} is unavailable") from exc


def _rewrite_common_refs(value: Any, common: Mapping[str, Any]) -> Any:
    """Mount common definitions into each document without expanding recursion."""
    if isinstance(value, list):
        return [_rewrite_common_refs(item, common) for item in value]
    if not isinstance(value, dict):
        return value
    rewritten: dict[str, Any] = {}
    for key, item in value.items():
        if key == "$ref" and isinstance(item, str) and item.startswith("common.v1.json#/$defs/"):
            definition = item.rsplit("/", 1)[-1]
            if definition not in common.get("$defs", {}):
                raise ModelError("schema contains an unknown common definition")
            rewritten[key] = f"#/$defs/{definition}"
        else:
            rewritten[key] = _rewrite_common_refs(item, common)
    return rewritten


def schema_document(model_name: str) -> dict[str, Any]:
    try:
        filename = MODEL_SCHEMAS[model_name]
    except KeyError as exc:
        raise ModelError(f"unknown model {model_name}") from exc
    common = strict_json_loads(_schema_resource("common.v1.json"))
    schema = strict_json_loads(_schema_resource(filename))
    resolved = _rewrite_common_refs(schema, common)
    if not isinstance(resolved, dict):
        raise ModelError("schema root must be an object")
    definitions = copy.deepcopy(common.get("$defs", {}))
    own_definitions = resolved.get("$defs")
    if isinstance(own_definitions, dict):
        definitions.update(own_definitions)
    resolved["$defs"] = definitions
    return resolved


def validate_schema_documents() -> list[str]:
    """Run the JSON Schema meta-schema self-check without network access."""
    if Draft202012Validator is None:
        raise ModelDependencyError("jsonschema is not installed")
    checked: list[str] = []
    common = strict_json_loads(_schema_resource("common.v1.json"))
    try:
        Draft202012Validator.check_schema(common)
    except Exception as exc:
        raise ModelError("common schema failed meta-schema validation") from exc
    for model_name in MODEL_SCHEMAS:
        schema = schema_document(model_name)
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as exc:  # jsonschema exposes several version-specific errors
            raise ModelError(f"schema {model_name} failed meta-schema validation") from exc
        checked.append(model_name)
    return checked


def _validate_cross_fields(model_name: str, value: Mapping[str, Any]) -> None:
    if model_name == "Response":
        if value["ok"] and value["error"] is not None:
            raise ModelError("successful response must have a null error", path=("error",))
        if not value["ok"] and value["error"] is None:
            raise ModelError("failed response must have an error", path=("error",))
    if model_name == "HostProjection":
        if value["kind"] == "server" and value["connection_ref"] is None:
            raise ModelError("server HostProjection requires a non-secret connection_ref", path=("connection_ref",))
        if value["kind"] == "local_client" and value["connection_ref"] is not None:
            raise ModelError("local_client cannot carry a remote connection_ref", path=("connection_ref",))
    if model_name == "Plan":
        targets = value["resolved_targets"]
        if targets != sorted(set(targets)):
            raise ModelError("resolved_targets must be sorted and unique", path=("resolved_targets",))
        bindings = value["target_bindings"]
        if set(bindings) != set(targets):
            raise ModelError("target_bindings must cover exactly resolved_targets", path=("target_bindings",))
        excluded_ids = [item["host_id"] for item in value["excluded"]]
        if len(excluded_ids) != len(set(excluded_ids)):
            raise ModelError("excluded host IDs must be unique", path=("excluded",))
        expected = canonical_digest(value, omit=("plan_digest",))
        if value["plan_digest"] != expected:
            raise ModelError("plan_digest does not match canonical plan content", path=("plan_digest",))
    if model_name == "LocalPlan":
        expected = canonical_digest(value, omit=("plan_digest",))
        if value["plan_digest"] != expected:
            raise ModelError("local plan_digest does not match canonical plan content", path=("plan_digest",))
    if model_name == "RunSummary":
        counts = value["counts"]
        if sum(counts.values()) != value["target_count"]:
            raise ModelError("run result counts must equal target_count", path=("counts",))
        if value["hosts"] != sorted(set(value["hosts"])):
            raise ModelError("hosts must be sorted and unique", path=("hosts",))
        if len(value["hosts"]) != value["target_count"]:
            raise ModelError("hosts must contain target_count hosts", path=("hosts",))
    if model_name == "OperationPackage":
        paths = [item["path"] for item in value["script_files"]]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ModelError("script_files must be sorted and unique", path=("script_files",))
        expected = canonical_digest(value, omit=("package_id", "content_digest"))
        if value["content_digest"] != expected:
            raise ModelError("content_digest does not match canonical package content", path=("content_digest",))
        try:
            parameter_validator = Draft202012Validator(value["parameter_schema"])
            parameter_errors = list(parameter_validator.iter_errors(value["typed_params"]))
        except Exception as exc:
            raise ModelError("operation package parameter_schema is invalid", path=("parameter_schema",)) from exc
        if parameter_errors:
            raise ModelError("typed_params do not match parameter_schema", path=("typed_params",))
    if model_name == "ActionDescriptor":
        try:
            Draft202012Validator.check_schema(value["parameter_schema"])
        except Exception as exc:
            raise ModelError("action parameter_schema is invalid", path=("parameter_schema",)) from exc
    if model_name in {"UseRecord", "BlockerRecord"}:
        if model_name == "UseRecord" and value["resolved_targets"] != sorted(set(value["resolved_targets"])):
            raise ModelError("resolved_targets must be sorted and unique", path=("resolved_targets",))
        if model_name == "BlockerRecord" and value["lock_groups"] != sorted(set(value["lock_groups"])):
            raise ModelError("lock_groups must be sorted and unique", path=("lock_groups",))
    if model_name == "SourceProvenance":
        if value["pre_first_read_snapshot"] == "unavailable" and value["first_read_at"] is None:
            raise ModelError("first_read_at is required when recording a provenance check")
        if value["first_read_digest"] is not None and value["first_read_digest"] != value["source"]["digest"]:
            raise ModelError("first_read_digest does not match source digest", path=("first_read_digest",))
        if value["reverified_digest"] is not None and value["reverified_digest"] != value["source"]["digest"]:
            raise ModelError("reverified_digest does not match source digest", path=("reverified_digest",))
    if model_name in {"Observation", "SoftwareFact", "BackupFact", "KnowledgeNote", "RecoveryEvidence"}:
        source = value.get("source")
        if isinstance(source, Mapping):
            origin = source.get("origin")
            if isinstance(origin, str) and any(
                marker in origin.lower() for marker in ("token", "password", "secret", "authorization", "cookie")
            ):
                raise ModelError("source origin contains secret-like material", path=("source", "origin"))


def validate_model(model_name: str, value: Any) -> Any:
    """Validate and return a JSON-compatible model object.

    The returned object is the caller's object; no mutation is performed.
    Error messages intentionally contain only a schema path and safe reason.
    """
    _walk_json(value)
    if not isinstance(value, dict):
        raise ModelError("model root must be an object")
    if Draft202012Validator is None:
        raise ModelDependencyError("jsonschema is not installed")
    schema = schema_document(model_name)
    validator = Draft202012Validator(schema, format_checker=_strict_format_checker())
    errors = sorted(validator.iter_errors(value), key=lambda item: list(item.absolute_path))
    if errors:
        error = errors[0]
        path = tuple(error.absolute_path)
        keyword = str(error.validator)
        raise ModelError(f"schema validation failed ({keyword})", path=path)
    if model_name == "Request" and len(canonical_json_bytes(value)) > MAX_REQUEST_BYTES:
        raise ModelError("request exceeds the 1MiB JSON limit")
    _validate_cross_fields(model_name, value)
    return value


def validate_source(source: Mapping[str, Any]) -> Mapping[str, Any]:
    validate_model("SourceProvenance", {  # validates the shared source shape through a small wrapper
        "schema_version": 1,
        "source": dict(source),
        "first_read_at": utc_now(),
        "reverified_at": utc_now(),
        "pre_first_read_snapshot": "unavailable",
        "first_read_digest": source.get("digest"),
        "reverified_digest": source.get("digest"),
    })
    return source


def safe_relative_reference(value: Any) -> bool:
    return isinstance(value, str) and bool(_SAFE_REF_RE.fullmatch(value)) and ".." not in value.split("/")


__all__ = [
    "MODEL_SCHEMAS",
    "MAX_REQUEST_BYTES",
    "ModelDependencyError",
    "ModelError",
    "canonical_digest",
    "canonical_json_bytes",
    "is_uuid",
    "is_valid_utc",
    "new_uuid",
    "schema_document",
    "strict_json_loads",
    "utc_now",
    "validate_model",
    "validate_schema_documents",
    "validate_source",
]
