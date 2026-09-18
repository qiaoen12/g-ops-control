"""Allowlist-first security event logging.

There is intentionally no raw-event fallback.  A caller must supply only
fields registered in the infra policy, and secret-looking values are rejected
before anything reaches a sink.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TextIO

from .models import is_uuid, is_valid_utc, utc_now


class LogError(RuntimeError):
    code = "log_rejected"


_SAFE_VALUE_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,256}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$")
_SECRET_RE = re.compile(
    r"(?i)(?:-----begin .*private key-----|authorization\s*:|bearer\s+|\b(?:password|passwd|secret|token|api[_-]?key)\b\s*[:=]|sk-[a-z0-9]|fake_secret_sentinel|ops_test_secret_sentinel)"
)


def _load_yaml(path: Path) -> Mapping[str, Any]:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - doctor reports this in bare envs
        raise LogError("YAML dependency is unavailable") from exc
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise LogError("logging policy could not be parsed") from exc
    if not isinstance(value, dict):
        raise LogError("logging policy root must be an object")
    return value


def load_logging_policy(path: Path) -> dict[str, Any]:
    policy = dict(_load_yaml(Path(path)))
    if policy.get("schema_version") != 1:
        raise LogError("logging policy schema_version must be 1")
    fields = policy.get("fields")
    if not isinstance(fields, dict) or not fields:
        raise LogError("logging policy must declare fields")
    for name, definition in fields.items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name):
            raise LogError("logging policy contains an unsafe field name")
        if not isinstance(definition, dict) or definition.get("type") not in {"id", "uuid", "utc", "bool"}:
            raise LogError("logging policy contains an unsupported field definition")
    return policy


def _contains_secret(value: Any) -> bool:
    if isinstance(value, str):
        return bool(_SECRET_RE.search(value))
    if isinstance(value, Mapping):
        return any(
            _contains_secret(key) or _contains_secret(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_contains_secret(child) for child in value)
    return False


class SecurityLogger:
    """Validate and optionally emit one safe, structured event at a time."""

    def __init__(self, policy_path: Path, *, sink: TextIO | None = None) -> None:
        self.policy_path = Path(policy_path)
        self.policy = load_logging_policy(self.policy_path)
        self.sink = sink
        self.events: list[dict[str, Any]] = []

    def _validate_field(self, name: str, value: Any, definition: Mapping[str, Any]) -> None:
        kind = definition.get("type")
        if kind == "bool":
            if not isinstance(value, bool):
                raise LogError("logging field has the wrong type")
            return
        if not isinstance(value, str) or not _SAFE_VALUE_RE.fullmatch(value):
            raise LogError("logging field contains unsafe text")
        if kind == "id" and not _SAFE_ID_RE.fullmatch(value):
            raise LogError("logging field is not a safe ID")
        if kind == "uuid" and not is_uuid(value):
            raise LogError("logging field is not a UUID")
        if kind == "utc":
            if value != value.strip() or not is_valid_utc(value):
                raise LogError("logging field is not a UTC timestamp")

    def emit(self, event: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(event, Mapping) or _contains_secret(event):
            raise LogError("event contains a secret or unsafe value")
        fields = self.policy["fields"]
        unknown = set(event) - set(fields)
        if unknown:
            raise LogError("event contains an unregistered field")
        if "event" not in event or "stage" not in event or "generated_at" not in event:
            raise LogError("event is missing registered safety fields")
        clean = dict(event)
        for name, value in clean.items():
            definition = fields.get(name)
            if not isinstance(definition, Mapping):
                raise LogError("event field is not registered")
            self._validate_field(name, value, definition)
        if clean["generated_at"] != clean["generated_at"].strip():
            raise LogError("event timestamp is not canonical")
        line = json.dumps(clean, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if self.sink is not None:
            try:
                self.sink.write(line + "\n")
                self.sink.flush()
            except (OSError, UnicodeError) as exc:
                raise LogError("safe log sink failed") from exc
        self.events.append(clean)
        return clean

    def event(self, *, event: str, stage: str, request_id: str | None = None, error_code: str | None = None, **ids: Any) -> dict[str, Any]:
        """Convenience constructor; only allowlisted keyword names survive."""
        payload: dict[str, Any] = {"event": event, "stage": stage, "generated_at": utc_now()}
        if request_id is not None:
            payload["request_id"] = request_id
        if error_code is not None:
            payload["error_code"] = error_code
        payload.update(ids)
        return self.emit(payload)


__all__ = ["LogError", "SecurityLogger", "load_logging_policy"]
