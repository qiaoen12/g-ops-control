"""Immutable offline Plan creation for OPS-003."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from jsonschema import Draft202012Validator

from .inventory import HostRecord, Inventory, InventoryError, PolicyEvaluator
from .models import (
    ModelError,
    canonical_digest,
    canonical_json_bytes,
    is_uuid,
    new_uuid,
    validate_model,
    validate_source,
    utc_now,
)
from .registry import ActionRegistry, RegisteredAction, RegistryError
from .resources import TrustedResourceProvider
from .storage import AtomicJsonStore, RecordNotFound, StorageError


class PlanError(ValueError):
    """A structured, fail-closed Plan creation error."""

    code = "precondition_failed"

    def __init__(self, message: str, *, code: str | None = None, details: Mapping[str, Any] | None = None) -> None:
        if code is not None:
            self.code = code
        self.details = dict(details or {})
        super().__init__(message)


class IdentityProvider(Protocol):
    def owner_id(self) -> str:
        """Return the trusted service-side owner UUID."""


@dataclass(frozen=True)
class StaticIdentityProvider:
    """Explicit test seam; the request and CLI cannot supply this value."""

    value: str

    def owner_id(self) -> str:
        if not is_uuid(self.value):
            raise PlanError("trusted owner identity is invalid", code="precondition_failed")
        return self.value


class LocalFixtureIdentityProvider(StaticIdentityProvider):
    """Offline CLI identity marker, not a production identity implementation."""


@dataclass(frozen=True)
class ResolverResult:
    version: str
    source: dict[str, Any]
    digest: str


class VersionResolver(Protocol):
    def resolve(self, action: RegisteredAction, *, requested_version: str = "latest") -> ResolverResult:
        """Resolve a version through a trusted read-only source."""


class FixtureResolver:
    """Deterministic resolver for injected, sanitized fixtures.

    A mapping may provide ``version``, ``source`` and ``digest`` per action.
    No network lookup or current-time-derived version is attempted.
    """

    def __init__(self, resolutions: Mapping[str, Mapping[str, Any]] | None = None) -> None:
        self.resolutions = {str(key): dict(value) for key, value in (resolutions or {}).items()}

    def resolve(self, action: RegisteredAction, *, requested_version: str = "latest") -> ResolverResult:
        configured = self.resolutions.get(action.action_id)
        if configured is None:
            version = action.descriptor.get("action_version") if action.descriptor else None
            source_origin = action.adapter_ref or "actions/unknown"
            source_digest = action.adapter_digest
            if not isinstance(version, str) or not version or not isinstance(source_digest, str):
                raise PlanError("trusted resolver has no reliable result", code="source_unavailable")
            source = {
                "kind": "file",
                "origin": source_origin,
                "version": version,
                "digest": source_digest,
            }
        else:
            version = configured.get("version")
            source = configured.get("source")
            if requested_version != "latest" and version != requested_version:
                raise PlanError("requested version is unavailable", code="source_unavailable")
            if not isinstance(version, str) or not version or not isinstance(source, Mapping):
                raise PlanError("trusted resolver result is incomplete", code="source_unavailable")
            source = dict(source)
            if configured.get("digest") is not None:
                source["digest"] = configured["digest"]
        try:
            validate_source(source)
        except Exception as exc:
            raise PlanError("trusted resolver returned invalid source metadata", code="source_unavailable") from exc
        digest = source["digest"]
        if not isinstance(digest, str):
            raise PlanError("trusted resolver returned no digest", code="source_unavailable")
        return ResolverResult(version=version, source=source, digest=digest)


class FileFixtureResolver(FixtureResolver):
    """Resolver name used by the CLI to make the fixture boundary explicit."""


_PROTECTED_KEYS = frozenset(
    {
        "adapter",
        "adapter_ref",
        "api_key",
        "approval",
        "approval_id",
        "approver_credential_id",
        "approved",
        "actor",
        "auth",
        "authorization",
        "become",
        "command",
        "argv",
        "cwd",
        "credential",
        "credential_id",
        "env",
        "environment",
        "executable",
        "extra_vars",
        "force_parallel",
        "identity",
        "inventory",
        "module",
        "owner",
        "owner_id",
        "path",
        "playbook",
        "plugin",
        "plugin_path",
        "private_key",
        "principal",
        "raw_extra_vars",
        "remote_command",
        "role",
        "root",
        "run_as",
        "service",
        "shell",
        "shell_command",
        "ssh_key",
        "subject",
        "systemd",
        "transport",
        "uid",
        "user",
        "username",
        "key_path",
        "key",
        "password",
        "passwd",
        "pythonpath",
        "secret",
        "token",
        "ansible_config",
        "auto_upgrade_allowed",
    }
)


def _reject_protected_keys(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if isinstance(key, str) and key.lower() in _PROTECTED_KEYS:
                raise PlanError("request contains a protected execution field", code="invalid_request")
            _reject_protected_keys(child)
    elif isinstance(value, list):
        for child in value:
            _reject_protected_keys(child)


def _safe_expiry(created_at: str, ttl_seconds: int) -> str:
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= 86400:
        raise PlanError("plan TTL is invalid", code="invalid_request")
    try:
        parsed = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PlanError("plan clock returned an invalid timestamp", code="storage_failed") from exc
    return (parsed + timedelta(seconds=ttl_seconds)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _validate_params(schema: Mapping[str, Any], params: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(params, Mapping):
        raise PlanError("plan parameters must be an object", code="invalid_request")
    params_copy = copy.deepcopy(dict(params))
    _reject_protected_keys(params_copy)
    try:
        validator = Draft202012Validator(schema)
        errors = sorted(validator.iter_errors(params_copy), key=lambda error: list(error.absolute_path))
    except Exception as exc:
        raise PlanError("action parameter schema is invalid", code="action_frozen") from exc
    if errors:
        raise PlanError("plan parameters do not match the action schema", code="invalid_request")
    try:
        canonical_json_bytes(params_copy)
    except ModelError as exc:
        raise PlanError("plan parameters are not canonical JSON", code="invalid_request") from exc
    return params_copy


def _source_digest(source: Mapping[str, Any]) -> str:
    digest = source.get("digest")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise PlanError("resolver source digest is invalid", code="source_unavailable")
    return digest


def _bundle_digest(action: RegisteredAction, resolution: ResolverResult) -> str:
    descriptor = action.descriptor
    if descriptor is None or not action.descriptor_digest or not action.adapter_digest:
        raise PlanError("action bundle is incomplete", code="action_frozen")
    return canonical_digest(
        {
            "action_descriptor": descriptor,
            "descriptor_digest": action.descriptor_digest,
            "adapter_digest": action.adapter_digest,
            "resolved_version": resolution.version,
            "resolved_source": resolution.source,
            "resolved_source_digest": resolution.digest,
        }
    )


def _policy_digest(
    policy: PolicyEvaluator,
    inventory: Inventory,
    action: RegisteredAction,
    resolved_params: Mapping[str, Any],
    hosts: Sequence[HostRecord],
) -> str:
    return canonical_digest(
        {
            "policy_source_digest": policy.digest,
            "inventory_source_digest": inventory.inventory_digest,
            "action_descriptor_digest": action.descriptor_digest,
            "action_id": action.action_id,
            "resolved_params": resolved_params,
            "target_snapshots": [
                {
                    "host_id": host.host_id,
                    "projection": host.projection,
                    "connection_digest": host.connection_digest,
                }
                for host in hosts
            ],
        }
    )


def _recovery_refs(
    store: AtomicJsonStore,
    refs: Sequence[str],
    *,
    owner_id: str,
    hosts: Sequence[HostRecord],
) -> list[str]:
    normalized = sorted(set(refs))
    if len(normalized) != len(refs):
        raise PlanError("recovery evidence references must be unique", code="invalid_request")
    if not normalized:
        raise PlanError("recovery evidence is required for this action", code="precondition_failed")
    host_ids = {host.host_id for host in hosts}
    covered: set[str] = set()
    for ref in normalized:
        if not isinstance(ref, str) or not ref or ".." in ref.split("/") or ref.startswith("/"):
            raise PlanError("recovery evidence reference is unsafe", code="invalid_request")
        try:
            evidence = store.read_record(ref, "RecoveryEvidence")
        except (RecordNotFound, StorageError, ModelError) as exc:
            raise PlanError("recovery evidence is unavailable", code="source_unavailable") from exc
        if evidence.get("owner_id") != owner_id or evidence.get("status") != "verified":
            raise PlanError("recovery evidence does not satisfy the plan", code="precondition_failed")
        observed = evidence.get("host_id")
        if observed in host_ids:
            covered.add(observed)
    if covered != host_ids:
        raise PlanError("recovery evidence does not cover every target", code="precondition_failed")
    return normalized


class PlanService:
    """Create immutable Plans without any executor or transport dependency."""

    def __init__(
        self,
        *,
        registry: ActionRegistry,
        inventory: Inventory,
        policy: PolicyEvaluator,
        store: AtomicJsonStore,
        identity_provider: IdentityProvider,
        resolver: VersionResolver | None = None,
        now: Callable[[], str] = utc_now,
    ) -> None:
        self.registry = registry
        self.inventory = inventory
        self.policy = policy
        self.store = store
        self.identity_provider = identity_provider
        self.resolver = resolver or FixtureResolver()
        self.now = now

    def create_plan(
        self,
        action_id: str,
        target: str | Sequence[str],
        params: Mapping[str, Any],
        *,
        ttl_seconds: int = 1800,
        recovery_evidence_refs: Sequence[str] = (),
        requested_version: str = "latest",
    ) -> dict[str, Any]:
        try:
            action = self.registry.get(action_id)
        except RegistryError as exc:
            raise PlanError(str(exc), code=exc.code, details={"action_id": action_id}) from exc
        descriptor = action.descriptor
        if descriptor is None:
            raise PlanError("action descriptor is unavailable", code="action_frozen")
        resolved_params = _validate_params(descriptor["parameter_schema"], params)
        try:
            resolution = self.inventory.resolve_targets(target)
        except InventoryError as exc:
            raise PlanError(str(exc), code=exc.code, details=exc.details) from exc
        allowed_kinds = set(descriptor.get("target_kinds", []))
        invalid_kinds = [host.host_id for host in resolution.hosts if host.kind not in allowed_kinds]
        if invalid_kinds:
            raise PlanError(
                "target batch contains an unsupported target kind",
                code="unsupported_target",
                details={"host_ids": invalid_kinds},
            )

        decisions = self.policy.evaluate_batch(resolution.hosts, action_id, resolved_params)
        excluded: list[dict[str, str]] = []
        included: list[HostRecord] = []
        for host, decision in zip(resolution.hosts, decisions, strict=True):
            platform = host.platform.get("os")
            constraints = descriptor.get("platform_constraints", [])
            if constraints and platform not in constraints:
                excluded.append({"host_id": host.host_id, "reason": f"platform_not_supported:{platform}"})
                continue
            if not decision.allowed:
                if decision.rule_id == "primary-standby-mutex":
                    raise PlanError(
                        "primary and standby targets cannot share this plan",
                        code="policy_denied",
                        details={"rule_id": decision.rule_id},
                    )
                excluded.append({"host_id": host.host_id, "reason": f"policy_denied:{decision.rule_id or 'fixed-rule'}"})
                continue
            included.append(host)
        if not included:
            raise PlanError(
                "all requested targets are excluded; no executable plan was created",
                code="precondition_failed",
                details={"excluded": excluded},
            )

        try:
            owner_id = self.identity_provider.owner_id()
        except PlanError:
            raise
        except Exception as exc:
            raise PlanError("trusted owner identity is unavailable", code="precondition_failed") from exc
        if not is_uuid(owner_id):
            raise PlanError("trusted owner identity is invalid", code="precondition_failed")
        recovery_refs: list[str] = []
        if descriptor.get("recovery_requirement") != "none" or descriptor.get("mode") in {"write", "elevated"}:
            recovery_refs = _recovery_refs(self.store, recovery_evidence_refs, owner_id=owner_id, hosts=included)
        try:
            resolved = self.resolver.resolve(action, requested_version=requested_version)
        except PlanError:
            raise
        except Exception as exc:
            raise PlanError("trusted resolver failed", code="source_unavailable") from exc
        _source_digest(resolved.source)
        bundle_digest = _bundle_digest(action, resolved)
        policy_digest = _policy_digest(self.policy, self.inventory, action, resolved_params, included)
        created_at = self.now()
        expires_at = _safe_expiry(created_at, ttl_seconds)
        excluded = sorted(excluded, key=lambda item: item["host_id"])
        plan: dict[str, Any] = {
            "schema_version": 1,
            "plan_id": new_uuid(),
            "owner_id": owner_id,
            "created_at": created_at,
            "expires_at": expires_at,
            "recovery_generation": new_uuid(),
            "action_id": action_id,
            "action_version": resolved.version,
            "bundle_id": f"bundle-{bundle_digest[:56]}",
            "policy_digest": policy_digest,
            "resolved_targets": sorted(host.host_id for host in included),
            "excluded": excluded,
            "target_bindings": {
                host.host_id: host.public_binding(policy_digest) for host in sorted(included, key=lambda item: item.host_id)
            },
            "resolved_params": resolved_params,
            # OPS-002 has no separate action-source field.  package_digest is
            # the immutable bundle/source digest for this offline plan.
            "package_digest": bundle_digest,
            "impact": {
                "summary": "read-only offline fixture plan" if descriptor["mode"] == "read" else "write plan blocked before execution",
                "service_interruption": descriptor["mode"] != "read",
                "data_risk": descriptor["mode"] != "read",
                "restart_required": False,
            },
            "recovery_evidence_refs": recovery_refs,
            "verification": sorted(set(descriptor.get("postchecks", []))),
            "elevated": descriptor["mode"] == "elevated",
            "max_runtime_seconds": descriptor["timeout_seconds"],
        }
        plan["plan_digest"] = canonical_digest(plan)
        try:
            validate_model("Plan", plan)
            relative = self.store.record_path("plans", plan["plan_id"])
            self.store.write_immutable_record(relative, "Plan", plan)
        except (ModelError, StorageError) as exc:
            raise PlanError("immutable plan write failed", code="storage_failed") from exc
        return plan


def create_plan(
    action_id: str,
    target: str | Sequence[str],
    params: Mapping[str, Any],
    *,
    registry: ActionRegistry,
    inventory: Inventory,
    policy: PolicyEvaluator,
    store: AtomicJsonStore,
    identity_provider: IdentityProvider,
    resolver: VersionResolver | None = None,
    now: Callable[[], str] = utc_now,
    ttl_seconds: int = 1800,
    recovery_evidence_refs: Sequence[str] = (),
    requested_version: str = "latest",
) -> dict[str, Any]:
    return PlanService(
        registry=registry,
        inventory=inventory,
        policy=policy,
        store=store,
        identity_provider=identity_provider,
        resolver=resolver,
        now=now,
    ).create_plan(
        action_id,
        target,
        params,
        ttl_seconds=ttl_seconds,
        recovery_evidence_refs=recovery_evidence_refs,
        requested_version=requested_version,
    )


def default_plan_store(
    root: Path | None = None,
    *,
    enforce_private: bool = True,
    create: bool = True,
) -> AtomicJsonStore:
    base = Path(root) if root is not None else Path.cwd() / "_cache" / "ops-control"
    if create:
        try:
            base.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise PlanError("plan store is unavailable", code="storage_failed") from exc
    elif not base.exists():
        raise PlanError("pre-created plan store is unavailable", code="storage_failed")
    if enforce_private:
        try:
            base.chmod(0o700)
        except OSError as exc:
            raise PlanError("plan store permissions could not be secured", code="storage_failed") from exc
    return AtomicJsonStore(base)


def default_plan_service(
    provider: TrustedResourceProvider | None = None,
    *,
    store_root: Path | None = None,
    identity_provider: IdentityProvider | None = None,
    resolver: VersionResolver | None = None,
    now: Callable[[], str] = utc_now,
    store_private: bool = True,
    create_store: bool = True,
) -> PlanService:
    provider = provider or TrustedResourceProvider.from_package()
    from .inventory import Inventory

    return PlanService(
        registry=ActionRegistry(provider),
        inventory=Inventory.from_provider(provider),
        policy=PolicyEvaluator.from_provider(provider),
        store=default_plan_store(store_root, enforce_private=store_private, create=create_store),
        identity_provider=identity_provider or LocalFixtureIdentityProvider("33333333-3333-4333-8333-333333333333"),
        resolver=resolver or FileFixtureResolver(),
        now=now,
    )


PlanManager = PlanService


__all__ = [
    "FileFixtureResolver",
    "FixtureResolver",
    "IdentityProvider",
    "LocalFixtureIdentityProvider",
    "PlanError",
    "PlanManager",
    "PlanService",
    "ResolverResult",
    "StaticIdentityProvider",
    "VersionResolver",
    "create_plan",
    "default_plan_service",
    "default_plan_store",
]
