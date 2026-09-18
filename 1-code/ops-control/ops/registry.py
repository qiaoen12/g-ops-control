"""Trusted, frozen-by-default action registry for OPS-003.

The registry is deliberately boring: a release manifest is the only index,
and every descriptor/adapter is resolved below the trusted package resource
root.  Directory contents are never treated as an allowlist.  The registry
does not import or execute adapters; their bytes are only hashed into a plan
bundle.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

try:
    import yaml
except ImportError:  # pragma: no cover - doctor reports the dependency
    yaml = None  # type: ignore[assignment]

from jsonschema import Draft202012Validator

from .models import ModelError, canonical_digest, validate_model
from .resources import ResourceError, TrustedResourceProvider


class RegistryError(ValueError):
    """A safe registry error suitable for a structured Response."""

    code = "unknown_action"

    def __init__(self, message: str, *, code: str | None = None, action_id: str | None = None) -> None:
        self.action_id = action_id
        if code is not None:
            self.code = code
        super().__init__(message)


_PROTECTED_PARAMETER_KEYS = frozenset(
    {
        "adapter",
        "adapter_ref",
        "approved",
        "become",
        "command",
        "environment",
        "extra_vars",
        "force_parallel",
        "module",
        "path",
        "playbook",
        "plugin",
        "private_key",
        "raw_extra_vars",
        "role",
        "root",
        "ssh_key",
        "transport",
        "auto_upgrade_allowed",
    }
)
_SAFE_ACTION_ID = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$")


def _yaml_load(path: Path) -> Any:
    if yaml is None:
        raise RegistryError("YAML dependency is unavailable", code="dependency_missing")

    class UniqueLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader: Any, node: Any, deep: bool = False) -> dict[Any, Any]:
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in mapping:
                raise RegistryError("YAML contains a duplicate mapping key", code="invalid_request")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    UniqueLoader.add_constructor(  # type: ignore[arg-type]
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping,
    )
    try:
        return yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueLoader)
    except RegistryError:
        raise
    except Exception as exc:
        raise RegistryError("action resource is not valid YAML", code="source_unavailable") from exc


def _mapping(value: Any, message: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RegistryError(message, code="invalid_request")
    return value


def _safe_manifest_status(value: Any) -> str:
    if value in {"enabled", "frozen"}:
        return str(value)
    if isinstance(value, bool):
        return "enabled" if value else "frozen"
    raise RegistryError("manifest action status is invalid", code="invalid_request")


def _scan_parameter_schema(value: Any) -> None:
    """Reject request-controlled escape hatches in every schema branch."""
    if isinstance(value, Mapping):
        properties = value.get("properties")
        if isinstance(properties, Mapping):
            for key, child in properties.items():
                if isinstance(key, str) and key.lower() in _PROTECTED_PARAMETER_KEYS:
                    raise RegistryError("action parameter schema contains a protected field", code="action_frozen")
                _scan_parameter_schema(child)
        items = value.get("items")
        if items is not None:
            _scan_parameter_schema(items)
        for key in ("enum", "const"):
            candidate = value.get(key)
            if candidate is not None:
                _scan_parameter_schema(candidate)
    elif isinstance(value, list):
        for child in value:
            _scan_parameter_schema(child)


def _parameter_summary(schema: Mapping[str, Any]) -> dict[str, Any]:
    properties = schema.get("properties")
    names = sorted(str(key) for key in properties) if isinstance(properties, Mapping) else []
    required = schema.get("required")
    required_names = sorted(str(item) for item in required) if isinstance(required, list) else []
    return {"type": schema.get("type"), "properties": names, "required": required_names}


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class RegisteredAction:
    """A descriptor plus release-controlled status and immutable source hashes."""

    action_id: str
    descriptor: dict[str, Any] | None
    status: str
    reason: str | None
    descriptor_digest: str | None
    adapter_digest: str | None
    adapter_ref: str | None
    descriptor_ref: str | None

    @property
    def enabled(self) -> bool:
        return self.status == "enabled" and self.descriptor is not None

    @property
    def frozen(self) -> bool:
        return not self.enabled

    def public(self) -> dict[str, Any]:
        descriptor = self.descriptor or {}
        schema = descriptor.get("parameter_schema") if isinstance(descriptor, Mapping) else None
        return {
            "action_id": self.action_id,
            "action_version": descriptor.get("action_version") if descriptor else None,
            "mode": descriptor.get("mode") if descriptor else None,
            "status": "enabled" if self.enabled else "frozen",
            "enabled": self.enabled,
            "frozen": not self.enabled,
            "target_kinds": descriptor.get("target_kinds", []) if descriptor else [],
            "platform_constraints": descriptor.get("platform_constraints", []) if descriptor else [],
            "parameter_schema": _parameter_summary(schema) if isinstance(schema, Mapping) else {},
            "unavailable_reason": self.reason,
        }


class ActionRegistry:
    """Load only actions named by the trusted release manifest."""

    def __init__(self, provider: TrustedResourceProvider, *, manifest: Path | None = None) -> None:
        self.provider = provider
        self.manifest = manifest or provider.action_manifest_path()
        self._actions: dict[str, RegisteredAction] | None = None

    @classmethod
    def from_package(cls) -> "ActionRegistry":
        return cls(TrustedResourceProvider.from_package())

    def _read_adapter(self, adapter_ref: str) -> tuple[Path, str]:
        if not isinstance(adapter_ref, str) or not adapter_ref or ".." in adapter_ref.split("/"):
            raise RegistryError("adapter reference is not a safe relative path", code="action_frozen")
        normalized = adapter_ref[len("actions/") :] if adapter_ref.startswith("actions/") else adapter_ref
        if not normalized.startswith("adapters/"):
            raise RegistryError("adapter reference is outside the adapter allowlist", code="action_frozen")
        try:
            path = self.provider.action_adapter_path(normalized)
            raw = path.read_bytes()
        except (ResourceError, OSError) as exc:
            raise RegistryError("adapter source is unavailable", code="action_frozen") from exc
        if not raw:
            raise RegistryError("adapter source is empty", code="action_frozen")
        return path, _sha256_bytes(raw)

    def _load_one(self, entry: Mapping[str, Any]) -> RegisteredAction:
        action_id = entry.get("action_id")
        if not isinstance(action_id, str) or not _SAFE_ACTION_ID.fullmatch(action_id):
            raise RegistryError("manifest action_id is invalid", code="invalid_request")
        manifest_status = _safe_manifest_status(entry.get("status", entry.get("enabled")))
        manifest_reason = entry.get("reason")
        if manifest_reason is not None and not isinstance(manifest_reason, str):
            raise RegistryError("manifest action reason is invalid", code="invalid_request")
        descriptor_ref = entry.get("descriptor", entry.get("path"))
        if not isinstance(descriptor_ref, str) or not descriptor_ref.endswith(".yml"):
            raise RegistryError("manifest descriptor is invalid", code="invalid_request")
        descriptor: dict[str, Any] | None = None
        descriptor_digest: str | None = None
        adapter_digest: str | None = None
        adapter_ref: str | None = None
        reason = manifest_reason if manifest_status == "frozen" else None
        try:
            descriptor_path = self.provider.action_descriptor_path(descriptor_ref)
            descriptor_value = _yaml_load(descriptor_path)
            if not isinstance(descriptor_value, dict):
                raise RegistryError("action descriptor is not an object", code="action_frozen")
            validate_model("ActionDescriptor", descriptor_value)
            if descriptor_value.get("action_id") != action_id:
                raise RegistryError("manifest and descriptor action IDs differ", code="action_frozen")
            _scan_parameter_schema(descriptor_value["parameter_schema"])
            adapter_ref = descriptor_value.get("adapter_ref")
            _adapter_path, adapter_digest = self._read_adapter(adapter_ref)
            descriptor = dict(descriptor_value)
            descriptor_digest = canonical_digest(descriptor)
            if manifest_status == "enabled":
                if not descriptor.get("enabled"):
                    reason = manifest_reason or "descriptor is disabled"
                elif descriptor.get("mode") != "read":
                    reason = manifest_reason or "only read actions may be enabled in OPS-003"
                elif descriptor.get("recovery_requirement") != "none":
                    reason = manifest_reason or "enabled action requires recovery evidence"
                elif descriptor.get("reentrancy") != "read_only":
                    reason = manifest_reason or "enabled action must be read-only"
                else:
                    # The enabled adapter is intentionally a fixture marker,
                    # not a playbook/role/plugin.  It is hashed but never run.
                    marker = _adapter_path.read_text(encoding="utf-8")
                    if "kind: fixture" not in marker or "operation: read-only-noop" not in marker:
                        reason = manifest_reason or "enabled adapter is not an OPS-003 read/no-op fixture"
            if reason is None and manifest_status == "frozen":
                reason = "frozen by release manifest"
        except RegistryError as exc:
            if manifest_status == "enabled":
                reason = str(exc)
            else:
                reason = manifest_reason or str(exc)
        except (ModelError, ResourceError, OSError, UnicodeError) as exc:
            reason = str(exc) if manifest_status == "enabled" else manifest_reason or "descriptor is unavailable or invalid"

        status = "enabled" if manifest_status == "enabled" and reason is None and descriptor is not None else "frozen"
        if status == "frozen" and reason is None:
            reason = "frozen by release manifest"
        return RegisteredAction(
            action_id=action_id,
            descriptor=descriptor,
            status=status,
            reason=reason,
            descriptor_digest=descriptor_digest,
            adapter_digest=adapter_digest,
            adapter_ref=adapter_ref,
            descriptor_ref=descriptor_ref,
        )

    def load(self) -> "ActionRegistry":
        if self._actions is not None:
            return self
        value = _yaml_load(self.manifest)
        document = _mapping(value, "action manifest must be an object")
        if document.get("schema_version") != 1:
            raise RegistryError("action manifest schema_version is unsupported", code="invalid_request")
        entries = document.get("actions")
        if not isinstance(entries, list) or not entries:
            raise RegistryError("action manifest must register at least one action", code="invalid_request")
        actions: dict[str, RegisteredAction] = {}
        for raw_entry in entries:
            entry = _mapping(raw_entry, "manifest action entry must be an object")
            action = self._load_one(entry)
            if action.action_id in actions:
                raise RegistryError("action manifest contains a duplicate action", code="invalid_request")
            actions[action.action_id] = action
        self._actions = actions
        return self

    def reload(self) -> "ActionRegistry":
        """Drop cached descriptors before an execution gate rechecks sources."""
        self._actions = None
        return self.load()

    def list_actions(self) -> list[RegisteredAction]:
        self.load()
        assert self._actions is not None
        return [self._actions[key] for key in sorted(self._actions)]

    def list_public(self) -> list[dict[str, Any]]:
        return [action.public() for action in self.list_actions()]

    def get(self, action_id: str) -> RegisteredAction:
        self.load()
        assert self._actions is not None
        action = self._actions.get(action_id)
        if action is None:
            raise RegistryError("requested action is not registered", code="unknown_action", action_id=action_id)
        if not action.enabled:
            raise RegistryError(
                action.reason or "action is frozen",
                code="action_frozen",
                action_id=action_id,
            )
        return action


def load_registry(provider: TrustedResourceProvider | None = None) -> ActionRegistry:
    return (ActionRegistry(provider or TrustedResourceProvider.from_package())).load()


def list_actions(provider: TrustedResourceProvider | None = None) -> list[dict[str, Any]]:
    return load_registry(provider).list_public()


__all__ = ["ActionRegistry", "RegisteredAction", "RegistryError", "list_actions", "load_registry"]
