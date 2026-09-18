"""Fixed cross-UID broker boundary for OPS-004.

The broker is intentionally a boundary description and deny-by-default
dispatcher in this release. It can resolve a maintenance-selected release
and construct the one fixed invocation used by a later executor, but it does
not start a business action, Ansible, systemd, or an arbitrary test runner.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


class BrokerError(ValueError):
    """A safe fixed-broker denial."""

    code = "precondition_failed"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        if code is not None:
            self.code = code
        super().__init__(message)


_SAFE_ID = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$")
_FORBIDDEN_KEYS = frozenset(
    {
        "ansible_config",
        "ansible_cfg",
        "argv",
        "callback",
        "callback_dir",
        "code_dir",
        "command",
        "cwd",
        "data_dir",
        "env",
        "environment",
        "executable",
        "extra_vars",
        "inventory",
        "inventory_path",
        "key",
        "key_path",
        "password",
        "path",
        "plugin",
        "plugin_path",
        "pythonpath",
        "release",
        "release_id",
        "release_path",
        "remote_command",
        "root",
        "service",
        "secret",
        "shell",
        "shell_command",
        "shell_fragment",
        "systemd",
        "systemd_unit",
        "target",
        "token",
        "unit",
    }
)
_FORBIDDEN_ENV_KEYS = frozenset(
    {
        "ANSIBLE_CONFIG",
        "ANSIBLE_INVENTORY",
        "ANSIBLE_CALLBACK_PLUGINS",
        "ANSIBLE_CONFIG_FILE",
        "PYTHONPATH",
        "PYTHONHOME",
        "LD_PRELOAD",
        "BASH_ENV",
        "ENV",
        "CDPATH",
        "IFS",
    }
)
_SAFE_PROBE_CAPABILITIES = frozenset({"identity-boundary"})
FIXED_BROKER_ENTRYPOINT = Path("/usr/local/libexec/ops-control/broker")
FIXED_BROKER_PATH = "/usr/local/libexec/ops-control:/usr/bin:/bin"
FIXED_BROKER_SERVICE_USER = "ops-exec"
FIXED_SUDO_PATH = Path("/usr/bin/sudo")
MAX_BROKER_REQUEST_BYTES = 1 << 20


def _trusted_absolute_path(value: Path, *, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or "\x00" in str(path) or any(part == ".." for part in path.parts):
        raise BrokerError(f"trusted broker {label} path is invalid")
    return path


@dataclass(frozen=True)
class BrokerConfig:
    """Maintenance-owned broker inputs; no field is request-controlled."""

    interpreter: Path
    release_root: Path
    code_dir: Path
    data_dir: Path
    release_id: str | None = None
    broker_entrypoint: Path = FIXED_BROKER_ENTRYPOINT
    allowed_capabilities: tuple[str, ...] = ()
    production: bool = True

    def __post_init__(self) -> None:
        for name in ("interpreter", "release_root", "code_dir", "data_dir", "broker_entrypoint"):
            object.__setattr__(self, name, Path(getattr(self, name)))
        for name, value in (
            ("interpreter", self.interpreter),
            ("release root", self.release_root),
            ("code", self.code_dir),
            ("data", self.data_dir),
            ("broker entrypoint", self.broker_entrypoint),
        ):
            _trusted_absolute_path(Path(value), label=name)
        if self.release_id is not None and not _SAFE_ID.fullmatch(self.release_id):
            raise BrokerError("trusted broker release is invalid")
        if not isinstance(self.production, bool):
            raise BrokerError("trusted broker mode is invalid")
        normalized = tuple(self.allowed_capabilities)
        if len(set(normalized)) != len(normalized) or any(not _SAFE_ID.fullmatch(item) for item in normalized):
            raise BrokerError("trusted broker capability allowlist is invalid")
        if self.production and any(item not in _SAFE_PROBE_CAPABILITIES for item in normalized):
            raise BrokerError("business broker capabilities are disabled in OPS-004")
        object.__setattr__(self, "allowed_capabilities", normalized)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "BrokerConfig":
        if not isinstance(value, Mapping):
            raise BrokerError("trusted broker configuration is invalid")
        allowed = {
            "interpreter",
            "release_root",
            "code_dir",
            "data_dir",
            "release_id",
            "broker_entrypoint",
            "allowed_capabilities",
            "production",
        }
        if set(value) - allowed:
            raise BrokerError("trusted broker configuration contains an unsupported field")
        try:
            return cls(
                interpreter=Path(value["interpreter"]),
                release_root=Path(value["release_root"]),
                code_dir=Path(value["code_dir"]),
                data_dir=Path(value["data_dir"]),
                release_id=value.get("release_id"),
                broker_entrypoint=Path(value.get("broker_entrypoint", FIXED_BROKER_ENTRYPOINT)),
                allowed_capabilities=tuple(value.get("allowed_capabilities", ())),
                production=value.get("production", True),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise BrokerError("trusted broker configuration is invalid") from exc

    def release_path(self) -> Path:
        """Resolve only the maintenance-selected release, never a request path."""

        release_name = self.release_id or "current"
        target = self.release_root / release_name
        root = self.release_root.resolve(strict=False)
        resolved = target.resolve(strict=False)
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise BrokerError("trusted broker release escapes its root") from exc
        if target.is_symlink() and not resolved.exists():
            raise BrokerError("trusted broker release is unavailable")
        if not resolved.exists() or not resolved.is_dir():
            raise BrokerError("trusted broker release is unavailable")
        return resolved


@dataclass(frozen=True)
class BrokerInvocation:
    """An inspection-only fixed invocation description."""

    executable: Path
    argv: tuple[str, ...]
    cwd: Path
    environment: dict[str, str]
    release: Path


def clean_broker_environment(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a fixed environment with Python/Ansible escape hatches absent."""

    # The source environment is deliberately not copied. These values are
    # fixed by the broker and are not inherited from ops-call.
    _ = os.environ if environ is None else environ
    return {
        "PATH": FIXED_BROKER_PATH,
        "LANG": "C",
        "LC_ALL": "C",
    }


def scrub_environment(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Compatibility alias for the fixed environment builder."""

    return clean_broker_environment(environ)


def _reject_caller_fields(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if isinstance(key, str) and key.lower() in _FORBIDDEN_KEYS:
                raise BrokerError("broker request contains a protected execution field")
            _reject_caller_fields(child)
    elif isinstance(value, list):
        for child in value:
            _reject_caller_fields(child)


class FixedBroker:
    """A fixed, deny-by-default cross-UID broker.

    ``delegate`` is the OPS-005 privilege boundary used by the production
    Gateway.  It accepts the existing Request v1 object and invokes only the
    root-owned broker entrypoint as ``ops-exec``.  The old ``dispatch`` seam
    remains the OPS-004 business-deny path.
    """

    def __init__(self, config: BrokerConfig) -> None:
        if not isinstance(config, BrokerConfig):
            raise BrokerError("trusted broker configuration is invalid")
        self.config = config

    def _validate_capability(self, capability: str) -> None:
        if not isinstance(capability, str) or not _SAFE_ID.fullmatch(capability):
            raise BrokerError("broker capability is invalid")
        if capability not in self.config.allowed_capabilities:
            raise BrokerError("broker capability is not allowlisted")

    def build_invocation(self, capability: str) -> BrokerInvocation:
        self._validate_capability(capability)
        release = self.config.release_path()
        environment = clean_broker_environment()
        executable = Path(self.config.interpreter)
        entrypoint = Path(self.config.broker_entrypoint)
        return BrokerInvocation(
            executable=executable,
            argv=(str(executable), str(entrypoint), "--capability", capability),
            cwd=Path(self.config.code_dir),
            environment=environment,
            release=release,
        )

    build_command = build_invocation
    build_argv = build_invocation

    def delegate(
        self,
        request: Mapping[str, Any],
        *,
        runner: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
        timeout_seconds: int = 60,
    ) -> dict[str, Any]:
        """Run one fixed OPS-005 apply through the ops-exec boundary.

        The optional runner is an explicit unit-test seam.  Production uses
        the absolute sudo path and the argument-free root-owned broker; no
        executable, user, argv, release, environment, or Approval can come
        from the Request.
        """

        if not isinstance(request, Mapping):
            raise BrokerError("broker request is invalid", code="invalid_request")
        if self.config.broker_entrypoint != FIXED_BROKER_ENTRYPOINT:
            raise BrokerError("broker entrypoint is not the fixed system boundary")
        try:
            from ..models import canonical_json_bytes, validate_model

            value = dict(request)
            validate_model("Request", value)
            if value.get("command") != "apply":
                raise BrokerError("broker only accepts an apply Request", code="unsupported_command")
            params = value.get("params")
            if not isinstance(params, Mapping) or set(params) != {"plan_id"}:
                raise BrokerError("broker apply parameters are invalid", code="invalid_request")
            _reject_caller_fields(params)
            payload = canonical_json_bytes(value) + b"\n"
        except BrokerError:
            raise
        except Exception as exc:
            # Do not expose model paths or caller-controlled values across the
            # privilege boundary.
            raise BrokerError("broker request is invalid", code="invalid_request") from exc

        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or timeout_seconds < 1:
            raise BrokerError("broker timeout is invalid", code="invalid_request")

        if runner is not None:
            try:
                response = dict(runner(value))
            except BrokerError:
                raise
            except Exception as exc:
                raise BrokerError("fixed broker response is unavailable", code="result_unknown") from exc
        else:
            import subprocess
            from ..models import strict_json_loads

            try:
                completed = subprocess.run(
                    [
                        str(FIXED_SUDO_PATH),
                        "-n",
                        "-u",
                        FIXED_BROKER_SERVICE_USER,
                        str(FIXED_BROKER_ENTRYPOINT),
                    ],
                    input=payload,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    cwd="/",
                    env=clean_broker_environment(),
                    timeout=timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise BrokerError("fixed broker response is unavailable", code="result_unknown") from exc
            except OSError as exc:
                raise BrokerError("fixed broker is unavailable", code="result_unknown") from exc
            if len(completed.stdout) > MAX_BROKER_REQUEST_BYTES or not completed.stdout:
                raise BrokerError("fixed broker response is unavailable", code="result_unknown")
            try:
                response = strict_json_loads(completed.stdout.decode("utf-8"))
            except Exception as exc:
                raise BrokerError("fixed broker response is invalid", code="result_unknown") from exc

        if not isinstance(response, Mapping):
            raise BrokerError("fixed broker response is invalid", code="result_unknown")
        envelope = dict(response)
        try:
            if envelope.get("request_id") != value.get("request_id"):
                raise BrokerError("fixed broker response is not bound to the request", code="result_unknown")
            # Response v1 deliberately has an empty-object extension slot.  We
            # validate its envelope without inventing a second result schema.
            from ..models import validate_model

            envelope_for_validation = dict(envelope)
            envelope_for_validation["data"] = {}
            validate_model("Response", envelope_for_validation)
        except BrokerError:
            raise
        except Exception as exc:
            raise BrokerError("fixed broker response is invalid", code="result_unknown") from exc
        if not envelope.get("ok"):
            error = envelope.get("error")
            code = error.get("code") if isinstance(error, Mapping) else None
            if not isinstance(code, str) or not code:
                code = "result_unknown"
            raise BrokerError("fixed broker denied the request", code=code)
        if runner is None and completed.returncode != 0:
            # A successful response with a failing process status is not a
            # trustworthy completion signal (the broker may have died after
            # changing state), so fail closed as unknown.
            raise BrokerError("fixed broker response is unavailable", code="result_unknown")
        data = envelope.get("data")
        if not isinstance(data, Mapping):
            raise BrokerError("fixed broker response data is invalid", code="result_unknown")
        return dict(data)

    def inspect(self, capability: str = "identity-boundary") -> dict[str, Any]:
        """Return a non-executing boundary description for an allowed probe."""

        invocation = self.build_invocation(capability)
        return {
            "capability": capability,
            "executed": False,
            "executor_calls": 0,
            "release": str(invocation.release),
            "argv": list(invocation.argv),
            "environment_keys": sorted(invocation.environment),
        }

    def dispatch(self, capability: str, request: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Reject business execution; no runner or shell exists in this release."""

        if request is not None:
            if not isinstance(request, Mapping):
                raise BrokerError("broker request is invalid")
            _reject_caller_fields(request)
        # Resolve the fixed invocation before denying so malformed capability
        # and protected caller fields fail closed with the same boundary as a
        # later executor, without starting a process.
        self.build_invocation(capability)
        raise BrokerError("business broker dispatch is disabled before OPS-005/007")

    run = dispatch
    execute = dispatch


def system_ops005_broker() -> FixedBroker:
    """Return the maintenance-selected client for the system broker rule."""

    return FixedBroker(
        BrokerConfig(
            interpreter=Path("/usr/bin/python3"),
            release_root=Path("/opt/ops-control/releases"),
            code_dir=Path("/opt/ops-control/current"),
            data_dir=Path("/var/lib/ops-control"),
            broker_entrypoint=FIXED_BROKER_ENTRYPOINT,
            allowed_capabilities=("ops005.noop",),
            production=False,
        )
    )


class PlanOwnerIdentityProvider:
    """Bind the executor gate to the immutable Plan it is asked to run.

    The ops-call Gateway performs the authenticated credential/owner check
    before invoking the fixed broker.  The broker then re-reads the Plan and
    derives the only owner value it may use from that immutable record; no
    owner field is accepted in the Request v1 payload.
    """

    def __init__(self, store: Any, plan_id: str) -> None:
        self.store = store
        self.plan_id = plan_id

    def owner_id(self) -> str:
        from ..models import is_uuid

        if not is_uuid(self.plan_id):
            raise BrokerError("delegated plan ID is invalid", code="invalid_request")
        try:
            plan = self.store.read_record(self.store.record_path("plans", self.plan_id), "Plan")
        except Exception as exc:
            raise BrokerError("delegated plan is unavailable", code="storage_failed") from exc
        owner_id = plan.get("owner_id")
        if not isinstance(owner_id, str) or not is_uuid(owner_id):
            raise BrokerError("delegated plan owner is invalid", code="storage_failed")
        return owner_id


def run_delegated_apply(
    request: Mapping[str, Any],
    *,
    store_root: Path,
    resource_provider: Any | None = None,
    now: Callable[[], str] | None = None,
) -> dict[str, Any]:
    """Execute one already-bound Request v1 inside the ops-exec UID."""

    from ..cli import make_response
    from ..gates import ExecutionGate
    from ..models import utc_now, validate_model
    from ..plans import FixtureResolver, default_plan_service
    from ..resources import TrustedResourceProvider
    from ..results import ResultService
    from ..storage import AtomicJsonStore
    from ..approval.store import ApprovalStore, TrustedApprovalProvider
    from .launch import ExactlyOnceLauncher, Ops005NoopServiceManager, default_ops005_broker

    value = dict(request)
    validate_model("Request", value)
    if value.get("command") != "apply" or not isinstance(value.get("params"), Mapping):
        raise BrokerError("delegated broker accepts only apply", code="unsupported_command")
    params = value["params"]
    if set(params) != {"plan_id"}:
        raise BrokerError("delegated apply parameters are invalid", code="invalid_request")
    plan_id = params["plan_id"]
    store = AtomicJsonStore(Path(store_root))
    identity = PlanOwnerIdentityProvider(store, str(plan_id))
    provider = resource_provider or TrustedResourceProvider.from_package()
    clock = now or utc_now
    service = default_plan_service(
        provider,
        store_root=Path(store_root),
        identity_provider=identity,
        resolver=FixtureResolver(),
        now=clock,
        store_private=False,
        create_store=False,
    )
    gate = ExecutionGate(
        store=service.store,
        registry=service.registry,
        inventory=service.inventory,
        policy=service.policy,
        identity_provider=identity,
        resolver=service.resolver,
        now=clock,
        approval_provider=TrustedApprovalProvider(ApprovalStore(service.store)),
    )
    launcher = ExactlyOnceLauncher(
        store=service.store,
        gate=gate,
        broker=default_ops005_broker(store_root=Path(store_root)),
        service_manager=Ops005NoopServiceManager(),
        result_service=ResultService(service.store, now=clock),
        now=clock,
    )
    outcome = launcher.apply(str(plan_id))
    return make_response(value["request_id"], ok=True, data=outcome.data(), validate=False)


def _emit_broker_response(response: Mapping[str, Any]) -> int:
    from ..models import canonical_json_bytes

    sys.stdout.buffer.write(canonical_json_bytes(dict(response)) + b"\n")
    sys.stdout.buffer.flush()
    return 0 if response.get("ok") else 1


def main(argv: list[str] | None = None) -> int:
    """Root-owned argument-free entrypoint run as ``ops-exec`` by sudo."""

    from ..cli import _error, make_response
    from ..models import canonical_json_bytes, new_uuid, strict_json_loads

    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        return _emit_broker_response(
            make_response(
                new_uuid(),
                ok=False,
                error=_error("invalid_request", "fixed broker request denied", reason="broker_has_no_cli_options"),
            )
        )
    try:
        raw = sys.stdin.buffer.read(MAX_BROKER_REQUEST_BYTES + 1)
        if len(raw) > MAX_BROKER_REQUEST_BYTES:
            raise BrokerError("broker request exceeds the limit", code="invalid_request")
        request = strict_json_loads(raw.decode("utf-8"))
        if not isinstance(request, Mapping):
            raise BrokerError("broker request must be an object", code="invalid_request")
        request_value = dict(request)
        from ..models import validate_model

        validate_model("Request", request_value)
        request_id = request_value.get("request_id") if isinstance(request_value.get("request_id"), str) else new_uuid()
        response = run_delegated_apply(request_value, store_root=Path("/var/lib/ops-control"))
    except Exception as exc:
        code = getattr(exc, "code", "precondition_failed")
        response = make_response(
            request_id if "request_id" in locals() else new_uuid(),
            ok=False,
            error=_error(code, "fixed broker request denied", reason=code),
        )
    return _emit_broker_response(response)

Broker = FixedBroker
BrokerPolicy = BrokerConfig


__all__ = [
    "Broker",
    "BrokerConfig",
    "BrokerError",
    "BrokerInvocation",
    "BrokerPolicy",
    "FIXED_BROKER_ENTRYPOINT",
    "FIXED_BROKER_SERVICE_USER",
    "FIXED_SUDO_PATH",
    "FixedBroker",
    "MAX_BROKER_REQUEST_BYTES",
    "PlanOwnerIdentityProvider",
    "clean_broker_environment",
    "main",
    "run_delegated_apply",
    "scrub_environment",
    "system_ops005_broker",
]
