"""Offline inventory projection, target resolution and policy evaluation."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

try:
    import yaml
except ImportError:  # pragma: no cover - doctor reports the dependency
    yaml = None  # type: ignore[assignment]

from .models import canonical_digest, validate_model
from .resources import ResourceError, TrustedResourceProvider


class InventoryError(ValueError):
    """A fail-closed target or inventory error."""

    code = "precondition_failed"

    def __init__(self, message: str, *, code: str | None = None, details: Mapping[str, Any] | None = None) -> None:
        if code is not None:
            self.code = code
        self.details = dict(details or {})
        super().__init__(message)


class PolicyError(InventoryError):
    code = "policy_denied"


_TARGET_RE = re.compile(r"^(host|group):([A-Za-z0-9._][A-Za-z0-9._-]{0,63})$")
_HOST_VAR_KEYS = frozenset({"ansible_host", "ansible_port", "ansible_user"})
_SECRET_VAR_MARKERS = ("password", "private", "secret", "token", "key")


def _load_yaml(path: Path) -> Any:
    if yaml is None:
        raise InventoryError("YAML dependency is unavailable", code="dependency_missing")
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise InventoryError("trusted inventory resource is unavailable", code="source_unavailable") from exc


def _require_mapping(value: Any, message: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise InventoryError(message, code="source_unavailable")
    return value


def _safe_id(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$", value):
        raise InventoryError(f"{label} is invalid", code="source_unavailable")
    return value


@dataclass(frozen=True)
class HostRecord:
    """A sanitized management projection plus an internal connection digest."""

    host_id: str
    projection: dict[str, Any]
    connection: dict[str, Any] | None
    connection_digest: str

    @property
    def kind(self) -> str:
        return str(self.projection["kind"])

    @property
    def platform(self) -> dict[str, Any]:
        return dict(self.projection["platform"])

    @property
    def groups(self) -> tuple[str, ...]:
        return tuple(self.projection.get("groups", []))

    @property
    def lifecycle(self) -> str:
        return str(self.projection["lifecycle"])

    @property
    def machine_class(self) -> str | None:
        value = self.projection.get("machine_class")
        return str(value) if value is not None else None

    def public_binding(self, policy_digest: str) -> dict[str, Any]:
        return {
            "connection_digest": self.connection_digest,
            "platform": self.platform,
            "policy_digest": policy_digest,
        }


@dataclass(frozen=True)
class TargetResolution:
    """A frozen target expansion; it contains no future group reference."""

    requested: tuple[str, ...]
    hosts: tuple[HostRecord, ...]
    inventory_digest: str

    @property
    def resolved_targets(self) -> list[str]:
        return [host.host_id for host in self.hosts]


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str | None = None
    rule_id: str | None = None


class Inventory:
    """Load the sanitized management projection and lab connection inventory."""

    def __init__(
        self,
        hosts: Mapping[str, HostRecord],
        *,
        groups: Mapping[str, Sequence[str]],
        inventory_digest: str,
        provider: TrustedResourceProvider | None = None,
    ) -> None:
        self.hosts = dict(hosts)
        self.groups = {name: tuple(sorted(set(members))) for name, members in groups.items()}
        self.inventory_digest = inventory_digest
        self._provider = provider

    @classmethod
    def from_provider(cls, provider: TrustedResourceProvider) -> "Inventory":
        try:
            management = _require_mapping(_load_yaml(provider.path("inventory/management.yml")), "management inventory must be an object")
            connection_path = provider.path("ansible/inventories/lab/hosts.ini")
        except ResourceError as exc:
            raise InventoryError("trusted inventory resource is unavailable", code="source_unavailable") from exc
        if management.get("schema_version") != 1:
            raise InventoryError("management inventory schema_version is unsupported", code="source_unavailable")
        raw_hosts = _require_mapping(management.get("hosts"), "management inventory hosts are invalid")
        connections, ini_groups = _parse_hosts_ini(connection_path)
        hosts: dict[str, HostRecord] = {}
        normalized_management: dict[str, Any] = {}
        for raw_host_id, raw_value in raw_hosts.items():
            host_id = _safe_id(raw_host_id, label="management host_id")
            data = dict(_require_mapping(raw_value, "management host projection is invalid"))
            data.setdefault("schema_version", 1)
            data["host_id"] = host_id
            data.setdefault("groups", [])
            data.setdefault("policy_refs", [])
            data.setdefault("services", {})
            data.setdefault("connection_ref", None if data.get("kind") == "local_client" else f"connection:{host_id}")
            if data.get("kind") == "local_client":
                data["connection_ref"] = None
            else:
                # HostProjection requires a non-secret reference even for
                # retired projections that have no active connection facts.
                data["connection_ref"] = f"connection:{host_id}"
            for field in ("groups", "policy_refs"):
                values = data.get(field)
                if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
                    raise InventoryError("management projection list is invalid", code="source_unavailable")
                data[field] = sorted(set(values))
            if not isinstance(data.get("services"), Mapping):
                raise InventoryError("management projection services are invalid", code="source_unavailable")
            try:
                validate_model("HostProjection", data)
            except Exception as exc:
                raise InventoryError("management projection failed schema validation", code="source_unavailable") from exc
            connection = connections.get(host_id)
            connection_digest = canonical_digest(
                {"host_id": host_id, "connection": connection, "connection_ref": data["connection_ref"]}
            )
            hosts[host_id] = HostRecord(
                host_id=host_id,
                projection=data,
                connection=dict(connection) if connection is not None else None,
                connection_digest=connection_digest,
            )
            normalized_management[host_id] = {
                key: value for key, value in data.items() if key != "host_id"
            }

        # Only management metadata defines target groups.  INI groups are
        # checked as a connection consistency signal but never used to create
        # new targets.  This prevents an unreviewed host from entering a plan.
        for host_id in connections:
            if host_id not in hosts:
                raise InventoryError("connection inventory contains an unregistered host", code="context_conflict")
        groups: dict[str, list[str]] = {}
        for host_id, record in hosts.items():
            for group in record.groups:
                groups.setdefault(group, []).append(host_id)
        normalized_connections = {
            host_id: connections.get(host_id) for host_id in sorted(hosts) if host_id in connections
        }
        inventory_digest = canonical_digest(
            {"management": normalized_management, "connections": normalized_connections, "ini_groups": ini_groups}
        )
        return cls(hosts, groups=groups, inventory_digest=inventory_digest, provider=provider)

    def reload(self) -> "Inventory":
        """Reload connection and management facts for an execution gate."""
        if self._provider is None:
            return self
        return type(self).from_provider(self._provider)

    def parse_target(self, target: str) -> tuple[str, str]:
        if not isinstance(target, str):
            raise InventoryError("target must be host:ID or group:NAME", code="invalid_request")
        match = _TARGET_RE.fullmatch(target)
        if match is None:
            raise InventoryError("target must be host:ID or group:NAME", code="invalid_request")
        return match.group(1), match.group(2)

    def _expand_one(self, target: str) -> list[HostRecord]:
        kind, name = self.parse_target(target)
        if kind == "host":
            record = self.hosts.get(name)
            if record is None:
                raise InventoryError("target host is unknown", code="unknown_target", details={"target": target})
            return [record]
        if name not in self.groups:
            raise InventoryError("target group is unknown", code="unknown_target", details={"target": target})
        members = self.groups[name]
        if not members:
            raise InventoryError("target group has no registered members", code="unknown_target", details={"target": target})
        return [self.hosts[host_id] for host_id in members]

    def resolve_targets(self, targets: str | Sequence[str]) -> TargetResolution:
        if isinstance(targets, str):
            requested = (targets,)
        else:
            requested = tuple(targets)
        if not requested:
            raise InventoryError("at least one target is required", code="unknown_target")
        resolved: dict[str, HostRecord] = {}
        for target in requested:
            for record in self._expand_one(target):
                resolved[record.host_id] = record
        if not resolved:
            raise InventoryError("target expansion is empty", code="unknown_target")
        records = [resolved[key] for key in sorted(resolved)]
        for record in records:
            if record.lifecycle == "retired":
                raise InventoryError(
                    "retired target is not eligible for a plan",
                    code="unsupported_target",
                    details={"host_id": record.host_id, "reason": "retired"},
                )
            if record.projection.get("ledger_vs_facts") == "conflict":
                raise InventoryError(
                    "target facts are in unresolved conflict",
                    code="context_conflict",
                    details={"host_id": record.host_id, "reason": "ledger_vs_facts"},
                )
            if record.kind not in {"server", "local_client"}:
                raise InventoryError("target kind is unsupported", code="unsupported_target")
        return TargetResolution(requested=requested, hosts=tuple(records), inventory_digest=self.inventory_digest)


def _parse_hosts_ini(path: Path) -> tuple[dict[str, dict[str, Any]], dict[str, tuple[str, ...]]]:
    connections: dict[str, dict[str, Any]] = {}
    groups: dict[str, list[str]] = {}
    current_group: str | None = None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise InventoryError("lab connection inventory is unavailable", code="source_unavailable") from exc
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_group = line[1:-1].strip()
            if current_group.endswith(":children"):
                current_group = None
            elif current_group:
                groups.setdefault(current_group, [])
            continue
        if current_group is None:
            continue
        try:
            tokens = shlex.split(line, comments=True, posix=True)
        except ValueError as exc:
            raise InventoryError("lab connection inventory has invalid syntax", code="source_unavailable") from exc
        if not tokens:
            continue
        host_id = tokens[0]
        _safe_id(host_id, label="lab inventory host_id")
        groups.setdefault(current_group, []).append(host_id)
        values: dict[str, Any] = {}
        for token in tokens[1:]:
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            if any(marker in key.lower() for marker in _SECRET_VAR_MARKERS) and key not in _HOST_VAR_KEYS:
                raise InventoryError("lab inventory contains a secret-like variable", code="source_unavailable")
            if key not in _HOST_VAR_KEYS:
                continue
            if key == "ansible_port":
                try:
                    parsed: Any = int(value)
                except ValueError as exc:
                    raise InventoryError("lab inventory port is invalid", code="source_unavailable") from exc
                if parsed < 1 or parsed > 65535:
                    raise InventoryError("lab inventory port is invalid", code="source_unavailable")
                values[key] = parsed
            else:
                if not value or any(character in value for character in "\r\n"):
                    raise InventoryError("lab inventory connection value is invalid", code="source_unavailable")
                values[key] = value
        if not values:
            # Non-primary group sections list membership only.  Connection
            # facts are required only on host lines carrying ansible_* vars.
            continue
        if not {"ansible_host", "ansible_port", "ansible_user"}.issubset(values):
            raise InventoryError("lab inventory host is missing connection fields", code="source_unavailable")
        existing = connections.get(host_id)
        if existing is not None and existing != values:
            raise InventoryError("lab inventory has conflicting host facts", code="context_conflict")
        connections[host_id] = values
    return connections, {name: tuple(sorted(set(members))) for name, members in groups.items()}


class PolicyEvaluator:
    """Deny-wins evaluator for the fixed, sanitized policy projection."""

    def __init__(
        self,
        *,
        rules: Sequence[Mapping[str, Any]],
        machine_classes: Mapping[str, Any],
        digest: str,
        provider: TrustedResourceProvider | None = None,
    ) -> None:
        self.rules = [dict(rule) for rule in rules]
        self.machine_classes = dict(machine_classes)
        self.digest = digest
        self._provider = provider

    @classmethod
    def from_provider(cls, provider: TrustedResourceProvider) -> "PolicyEvaluator":
        try:
            special = _require_mapping(_load_yaml(provider.path("policy/special-rules.yml")), "special policy is invalid")
            classes = _require_mapping(_load_yaml(provider.path("policy/machine-classes.yml")), "machine class policy is invalid")
            credentials = _load_yaml(provider.path("policy/credential-refs.yml"))
        except ResourceError as exc:
            raise InventoryError("trusted policy resource is unavailable", code="source_unavailable") from exc
        rules = special.get("rules")
        if not isinstance(rules, list) or not all(isinstance(rule, Mapping) for rule in rules):
            raise InventoryError("special policy rules are invalid", code="source_unavailable")
        digest = canonical_digest({"special": special, "classes": classes, "credentials": credentials})
        return cls(rules=rules, machine_classes=classes, digest=digest, provider=provider)

    def reload(self) -> "PolicyEvaluator":
        if self._provider is None:
            return self
        return type(self).from_provider(self._provider)

    @staticmethod
    def _context_value(host: HostRecord, key: str, params: Mapping[str, Any], context: Mapping[str, Any]) -> Any:
        if key == "host_id":
            return host.host_id
        if key == "kind":
            return host.kind
        if key == "lifecycle":
            return host.lifecycle
        if key == "machine_class":
            return host.machine_class
        if key == "groups_contains":
            return host.groups
        if key == "ledger_vs_facts":
            return host.projection.get("ledger_vs_facts")
        if key == "service_expected":
            return [item.get("expected_state") for item in host.projection.get("services", {}).values()]
        if key in context:
            return context[key]
        if key in params:
            return params[key]
        # Missing safety controls must fail closed in inherited rules.  In
        # particular, an omitted force_parallel must still match the primary
        # primary/standby mutex rule rather than silently allowing mixed roles.
        if key in {"approved", "force_parallel"}:
            return False
        return None

    @classmethod
    def _matches(cls, when: Mapping[str, Any], host: HostRecord, action_id: str, params: Mapping[str, Any], context: Mapping[str, Any]) -> bool:
        for key, expected in when.items():
            if key == "action":
                actual: Any = action_id
            else:
                actual = cls._context_value(host, str(key), params, context)
            if expected == "any":
                continue
            if key == "groups_contains":
                if expected not in actual:
                    return False
            elif key == "service_expected":
                if expected not in actual:
                    return False
            elif actual != expected:
                return False
        return True

    def evaluate(
        self,
        host: HostRecord,
        action_id: str,
        params: Mapping[str, Any],
        *,
        context: Mapping[str, Any] | None = None,
    ) -> PolicyDecision:
        evaluation_context = dict(context or {})
        matches = [rule for rule in self.rules if self._matches(rule.get("when", {}), host, action_id, params, evaluation_context)]
        denies = [rule for rule in matches if rule.get("expect") == "deny"]
        if denies:
            rule = denies[0]
            return PolicyDecision(False, str(rule.get("correction") or rule.get("note") or "policy rule denied"), str(rule.get("id")))
        allows = [rule for rule in matches if rule.get("expect") == "allow"]
        if allows:
            return PolicyDecision(True, rule_id=str(allows[0].get("id")))
        return PolicyDecision(True)

    def evaluate_batch(
        self,
        hosts: Sequence[HostRecord],
        action_id: str,
        params: Mapping[str, Any],
    ) -> list[PolicyDecision]:
        primary = any("aether_primary_hosts" in host.groups for host in hosts)
        standby = any("aether_standby_hosts" in host.groups for host in hosts)
        context = {"mixed_roles": primary and standby}
        return [self.evaluate(host, action_id, params, context=context) for host in hosts]


def inventory_from_package() -> Inventory:
    return Inventory.from_provider(TrustedResourceProvider.from_package())


def load_inventory(provider: TrustedResourceProvider | None = None) -> Inventory:
    return Inventory.from_provider(provider or TrustedResourceProvider.from_package())


def resolve_targets(targets: str | Sequence[str], *, inventory: Inventory | None = None) -> TargetResolution:
    return (inventory or load_inventory()).resolve_targets(targets)


__all__ = [
    "HostRecord",
    "Inventory",
    "InventoryError",
    "PolicyDecision",
    "PolicyError",
    "PolicyEvaluator",
    "TargetResolution",
    "inventory_from_package",
    "load_inventory",
    "resolve_targets",
]
