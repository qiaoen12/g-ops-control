"""Single execution-before-start gate for OPS-005/007 consumers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from .inventory import InventoryError, PolicyEvaluator
from .models import ModelError, is_uuid, utc_now, validate_model
from .plans import (
    IdentityProvider,
    PlanError,
    ResolverResult,
    _bundle_digest,
    _policy_digest,
)
from .registry import ActionRegistry, RegistryError
from .storage import AtomicJsonStore, RecordNotFound, StorageError


class GateError(ValueError):
    """A structured denial; no executor is called on any path."""

    code = "precondition_failed"

    def __init__(self, message: str, *, code: str | None = None, details: Mapping[str, Any] | None = None) -> None:
        if code is not None:
            self.code = code
        self.details = dict(details or {})
        super().__init__(message)


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise GateError("stored time is invalid", code="storage_failed") from exc
    if parsed.tzinfo is None:
        raise GateError("stored time is not UTC", code="storage_failed")
    return parsed.astimezone(timezone.utc)


def _resolve(resolver: Any, action: Any) -> ResolverResult:
    try:
        return resolver.resolve(action, requested_version="latest")
    except TypeError:
        # Keep a narrow compatibility seam for a resolver written against the
        # original OPS-003 design note.  It still receives the trusted action,
        # never a caller-provided path or URL.
        return resolver.resolve(action)


def _approval_check(
    approval: Mapping[str, Any] | None,
    *,
    plan: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    if approval is None:
        raise GateError("plan approval is required", code="approval_required")
    try:
        validate_model("Approval", dict(approval))
    except Exception as exc:
        raise GateError("approval record is invalid", code="approval_required") from exc
    if approval.get("plan_id") != plan.get("plan_id") or approval.get("plan_digest") != plan.get("plan_digest"):
        raise GateError("approval does not match the immutable plan", code="approval_required")
    if approval.get("owner_id") != plan.get("owner_id"):
        raise GateError("approval owner does not match the plan owner", code="approval_required")
    approved_at = _parse_time(str(approval["approved_at"]))
    start_before = _parse_time(str(approval["start_before"]))
    if start_before <= approved_at or approved_at > now or start_before <= now:
        raise GateError("approval is expired or not yet valid", code="approval_expired")
    if approval["max_runtime_seconds"] < plan["max_runtime_seconds"]:
        raise GateError("approval runtime is shorter than the plan", code="approval_required")
    return dict(approval)


def _check_recovery(
    store: AtomicJsonStore,
    plan: Mapping[str, Any],
    *,
    now: datetime,
    max_age: timedelta = timedelta(days=1),
) -> None:
    refs = plan.get("recovery_evidence_refs", [])
    if not isinstance(refs, list):
        raise GateError("recovery evidence references are invalid", code="storage_failed")
    if not refs:
        raise GateError("recovery evidence is required", code="precondition_failed")
    expected_hosts = set(plan.get("resolved_targets", []))
    covered_hosts: set[str] = set()
    for ref in refs:
        if not isinstance(ref, str) or not ref or ".." in ref.split("/") or ref.startswith("/"):
            raise GateError("recovery evidence reference is unsafe", code="storage_failed")
        try:
            evidence = store.read_record(ref, "RecoveryEvidence")
        except (RecordNotFound, StorageError, ModelError) as exc:
            raise GateError("recovery evidence is unavailable", code="precondition_failed") from exc
        if evidence.get("owner_id") != plan.get("owner_id") or evidence.get("status") != "verified":
            raise GateError("recovery evidence is not verified for this plan", code="precondition_failed")
        if evidence.get("artifact_digest") is None:
            raise GateError("recovery evidence has no immutable artifact", code="precondition_failed")
        host_id = evidence.get("host_id")
        if host_id not in expected_hosts:
            raise GateError("recovery evidence targets do not match the plan", code="precondition_failed")
        covered_hosts.add(host_id)
        observed = _parse_time(str(evidence.get("observed_at")))
        if observed > now or now - observed > max_age:
            raise GateError("recovery evidence is expired", code="precondition_failed")
    if covered_hosts != expected_hosts:
        raise GateError("recovery evidence does not cover every target", code="precondition_failed")


class ExecutionGate:
    """Re-read and validate a Plan without importing an executor."""

    def __init__(
        self,
        *,
        store: AtomicJsonStore,
        registry: ActionRegistry,
        inventory: Any,
        policy: PolicyEvaluator,
        identity_provider: IdentityProvider,
        resolver: Any,
        now: Callable[[], str] = utc_now,
        approval_provider: Any | None = None,
    ) -> None:
        self.store = store
        self.registry = registry
        self.inventory = inventory
        self.policy = policy
        self.identity_provider = identity_provider
        self.resolver = resolver
        self.now = now
        self.approval_provider = approval_provider

    def validate_for_gateway_start(self, plan_id: str) -> dict[str, Any]:
        """Validate a gateway start using only the trusted Approval provider.

        The ordinary ``validate_for_start`` method keeps the explicit
        OPS-003 approval seam for trusted tests and later consumers.  Gateway
        code uses this narrower method so an Approval can never cross the
        Request boundary or be supplied by a caller.
        """

        if self.approval_provider is None:
            raise GateError("trusted Approval provider is unavailable", code="approval_required")
        # Bind the caller's trusted identity before looking up Approval.  A
        # missing Approval must not hide an owner mismatch from the boundary.
        if not isinstance(plan_id, str) or not is_uuid(plan_id):
            raise GateError("plan_id is invalid", code="invalid_request")
        try:
            relative = self.store.record_path("plans", plan_id)
            plan = self.store.read_record(relative, "Plan")
            validate_model("Plan", plan)
            current_owner = self.identity_provider.owner_id()
        except (RecordNotFound, StorageError, ModelError) as exc:
            raise GateError("immutable plan is unavailable or invalid", code="storage_failed") from exc
        except Exception as exc:
            raise GateError("trusted current owner is unavailable", code="precondition_failed") from exc
        if plan["owner_id"] != current_owner:
            raise GateError("plan owner is not the trusted current owner", code="precondition_failed")
        try:
            approval = self.approval_provider.get_for_plan(plan_id)
        except Exception as exc:
            # ApprovalStore deliberately exposes no distinction between a
            # missing and malformed trusted record to the ordinary gateway.
            raise GateError("trusted Approval is unavailable", code="approval_required") from exc
        return self.validate_for_start(plan_id, approval=approval)

    def validate_for_start(
        self,
        plan_id: str,
        *,
        approval: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(plan_id, str) or not is_uuid(plan_id):
            raise GateError("plan_id is invalid", code="invalid_request")
        try:
            relative = self.store.record_path("plans", plan_id)
            plan = self.store.read_record(relative, "Plan")
        except (RecordNotFound, StorageError, ModelError) as exc:
            raise GateError("immutable plan is unavailable or invalid", code="storage_failed") from exc
        try:
            validate_model("Plan", plan)
        except Exception as exc:
            raise GateError("immutable plan failed validation", code="storage_failed") from exc
        if plan.get("plan_id") != plan_id:
            raise GateError("immutable plan path binding is invalid", code="storage_failed")
        if set(plan["resolved_targets"]) & {item["host_id"] for item in plan["excluded"]}:
            raise GateError("plan mixes resolved and excluded targets", code="storage_failed")
        try:
            current_owner = self.identity_provider.owner_id()
        except Exception as exc:
            raise GateError("trusted current owner is unavailable", code="precondition_failed") from exc
        if plan["owner_id"] != current_owner:
            raise GateError("plan owner is not the trusted current owner", code="precondition_failed")
        now = _parse_time(self.now())
        plan_expires = _parse_time(plan["expires_at"])
        if plan_expires <= now:
            raise GateError("plan has expired", code="plan_stale")

        try:
            # The gate is the first consumer that must observe descriptor and
            # adapter changes; do not rely on a registry cache from Plan
            # creation.
            self.registry.reload()
            action = self.registry.get(plan["action_id"])
        except RegistryError as exc:
            raise GateError("action is no longer enabled", code="plan_stale", details={"action_id": plan["action_id"]}) from exc
        if action.descriptor is None:
            raise GateError("action descriptor is unavailable", code="plan_stale")
        try:
            resolution = _resolve(self.resolver, action)
            current_bundle = _bundle_digest(action, resolution)
        except Exception as exc:
            raise GateError("trusted action resolver is unavailable", code="plan_stale") from exc
        if resolution.version != plan["action_version"] or current_bundle != plan["package_digest"] or not plan["bundle_id"].endswith(current_bundle[:56]):
            raise GateError("action version or bundle changed", code="plan_stale")

        current_inventory = self.inventory.reload() if hasattr(self.inventory, "reload") else self.inventory
        current_policy = self.policy.reload() if hasattr(self.policy, "reload") else self.policy
        host_specs = [f"host:{host_id}" for host_id in plan["resolved_targets"]]
        try:
            current_targets = current_inventory.resolve_targets(host_specs)
        except InventoryError as exc:
            raise GateError("plan target facts are no longer valid", code="plan_stale", details=exc.details) from exc
        if current_targets.resolved_targets != plan["resolved_targets"]:
            raise GateError("resolved target set changed", code="plan_stale")
        if any(host.kind not in set(action.descriptor.get("target_kinds", [])) for host in current_targets.hosts):
            raise GateError("resolved target kind changed", code="plan_stale")
        decisions = current_policy.evaluate_batch(current_targets.hosts, plan["action_id"], plan["resolved_params"])
        if any(not decision.allowed for decision in decisions):
            raise GateError("target policy no longer allows the plan", code="plan_stale")
        current_policy_digest = _policy_digest(
            current_policy,
            current_inventory,
            action,
            plan["resolved_params"],
            current_targets.hosts,
        )
        if current_policy_digest != plan["policy_digest"]:
            raise GateError("policy or inventory source changed", code="plan_stale")
        for host in current_targets.hosts:
            binding = plan["target_bindings"].get(host.host_id)
            if binding != host.public_binding(current_policy_digest):
                raise GateError("connection or target binding changed", code="plan_stale", details={"host_id": host.host_id})

        mode = action.descriptor.get("mode")
        if mode in {"write", "elevated"} or action.descriptor.get("recovery_requirement") != "none":
            _check_recovery(self.store, plan, now=now)
        checked_approval = _approval_check(approval, plan=plan, now=now)
        # This return value is evidence for a future executor.  It deliberately
        # contains no transport, SSH, Ansible, or callable execution object.
        return {
            "plan_id": plan["plan_id"],
            "plan_digest": plan["plan_digest"],
            "owner_id": plan["owner_id"],
            "action_id": plan["action_id"],
            "bundle_id": plan["bundle_id"],
            "max_runtime_seconds": plan["max_runtime_seconds"],
            "resolved_targets": list(plan["resolved_targets"]),
            "approval_id": checked_approval["approval_id"],
            "checked_at": self.now(),
            "executor_calls": 0,
        }


def validate_for_start(
    plan_id: str,
    *,
    store: AtomicJsonStore,
    registry: ActionRegistry,
    inventory: Any,
    policy: PolicyEvaluator,
    identity_provider: IdentityProvider,
    resolver: Any,
    approval: Mapping[str, Any] | None = None,
    now: Callable[[], str] = utc_now,
) -> dict[str, Any]:
    return ExecutionGate(
        store=store,
        registry=registry,
        inventory=inventory,
        policy=policy,
        identity_provider=identity_provider,
        resolver=resolver,
        now=now,
    ).validate_for_start(plan_id, approval=approval)


PreflightGate = ExecutionGate


__all__ = ["ExecutionGate", "GateError", "PreflightGate", "validate_for_start"]
