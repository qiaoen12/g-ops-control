"""The single structured application entry point for OPS-004.

The gateway accepts a validated OPS Request and a system-authenticated
credential context supplied by the forced-command wrapper. It never trusts
identity fields in JSON, never accepts an Approval from the caller, and only
dispatches the small set of commands implemented by OPS-002/003.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, TextIO

try:
    import yaml
except ImportError:  # pragma: no cover - doctor reports this dependency
    yaml = None  # type: ignore[assignment]

from .approval.store import ApprovalStore, TrustedApprovalProvider
from .cli import EXIT_INPUT, EXIT_OK, _error, make_response, run_doctor
from .gates import ExecutionGate, GateError
from .inventory import InventoryError
from .models import (
    ModelDependencyError,
    ModelError,
    canonical_json_bytes,
    is_uuid,
    new_uuid,
    safe_relative_reference,
    strict_json_loads,
    validate_model,
)
from .plans import PlanError, PlanService, default_plan_service
from .registry import ActionRegistry, RegistryError
from .results import ResultError, ResultService
from .resources import ResourceError, TrustedResourceProvider
from .storage import AtomicJsonStore, RecordNotFound, StorageError
from .executor.broker import BrokerError, FixedBroker, system_ops005_broker
from .executor.launch import ExactlyOnceLauncher, LaunchError, Ops005NoopServiceManager, default_ops005_broker


SYSTEM_IDENTITY_PATH = Path("/etc/ops-control/identity.yml")
SYSTEM_STORE_ROOT = Path("/var/lib/ops-control")
SYSTEM_PARAMS_ROOT = SYSTEM_STORE_ROOT / "request-input"
SYSTEM_CREDENTIAL_ENV = "OPS_CONTROL_CREDENTIAL_ID"
MAX_IDENTITY_BYTES = 64 * 1024
MAX_REQUEST_BYTES = 1 << 20

_SAFE_ID = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$")
_IDENTITY_OVERRIDE_KEYS = frozenset(
    {
        "account",
        "actor",
        "approval",
        "approval_id",
        "approved",
        "approver",
        "approver_credential_id",
        "as_user",
        "auth",
        "authorization",
        "credential",
        "credential_id",
        "identity",
        "key",
        "owner",
        "owner_id",
        "principal",
        "role",
        "run_as",
        "subject",
        "password",
        "passwd",
        "private_key",
        "secret",
        "token",
        "uid",
        "user",
        "username",
    }
)
_ALLOWED_COMMANDS = frozenset({"doctor", "actions.list", "plan", "apply", "result"})


class IdentityError(ValueError):
    """A safe, structured identity lookup failure."""

    code = "precondition_failed"


class GatewayError(ValueError):
    """A safe gateway failure; raw request values are never included."""

    code = "precondition_failed"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        if code is not None:
            self.code = code
        super().__init__(message)


def _yaml_load(path: Path) -> Any:
    if yaml is None:
        raise IdentityError("identity configuration dependency is unavailable")

    class UniqueLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader: Any, node: Any, deep: bool = False) -> dict[Any, Any]:
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in result:
                raise IdentityError("identity configuration contains duplicate keys")
            result[key] = loader.construct_object(value_node, deep=deep)
        return result

    UniqueLoader.add_constructor(  # type: ignore[arg-type]
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping,
    )
    try:
        return yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueLoader)
    except IdentityError:
        raise
    except Exception as exc:
        raise IdentityError("identity configuration is unavailable") from exc


def _validate_credential_id(value: Any) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise IdentityError("credential identity is invalid")
    return value


class BoundSystemIdentityProvider:
    """An immutable owner provider bound to one authenticated credential."""

    def __init__(self, credential_id: str, owner_id: str) -> None:
        self.credential_id = credential_id
        self._owner_id = owner_id

    def owner_id(self) -> str:
        return self._owner_id


class SystemIdentityProvider:
    """Read-only credential-to-owner mapping maintained outside the app.

    The mapping contains stable non-secret IDs and UUIDs only. A request can
    never add, edit, or select this mapping; the authenticated credential is
    bound by the SSH forced-command context before the gateway dispatches.
    """

    def __init__(
        self,
        mappings: Mapping[str, str],
        *,
        authenticated_credential_id: str | None = None,
    ) -> None:
        normalized: dict[str, str] = {}
        for credential_id, owner_id in mappings.items():
            credential = _validate_credential_id(credential_id)
            if not is_uuid(owner_id):
                raise IdentityError("identity owner is invalid")
            if credential in normalized:
                raise IdentityError("identity mapping contains a duplicate credential")
            normalized[credential] = owner_id
        if not normalized:
            raise IdentityError("identity mapping is empty")
        if authenticated_credential_id is not None:
            authenticated_credential_id = _validate_credential_id(authenticated_credential_id)
        self._mappings = dict(normalized)
        self._authenticated_credential_id = authenticated_credential_id

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any], *, authenticated_credential_id: str | None = None) -> "SystemIdentityProvider":
        if not isinstance(value, Mapping):
            raise IdentityError("identity configuration must be an object")
        if "credentials" in value:
            unknown_top_level = set(value) - {"schema_version", "credentials"}
            if unknown_top_level:
                raise IdentityError("identity configuration contains an unsupported field")
        raw_credentials: Any = value.get("credentials", value)
        mappings: dict[str, str] = {}
        if isinstance(raw_credentials, Mapping):
            for credential_id, raw_owner in raw_credentials.items():
                if isinstance(raw_owner, Mapping):
                    if set(raw_owner) != {"owner_id"}:
                        raise IdentityError("identity mapping entry contains an unsupported field")
                    owner_id = raw_owner.get("owner_id")
                else:
                    owner_id = raw_owner
                if not isinstance(credential_id, str) or not isinstance(owner_id, str):
                    raise IdentityError("identity mapping entry is invalid")
                if credential_id in mappings:
                    raise IdentityError("identity mapping contains a duplicate credential")
                mappings[credential_id] = owner_id
        elif isinstance(raw_credentials, list):
            for entry in raw_credentials:
                if not isinstance(entry, Mapping):
                    raise IdentityError("identity mapping entry is invalid")
                if set(entry) != {"credential_id", "owner_id"}:
                    raise IdentityError("identity mapping entry contains an unsupported field")
                credential_id = entry.get("credential_id")
                owner_id = entry.get("owner_id")
                if not isinstance(credential_id, str) or not isinstance(owner_id, str) or credential_id in mappings:
                    raise IdentityError("identity mapping entry is invalid")
                mappings[credential_id] = owner_id
        else:
            raise IdentityError("identity credentials must be an object or list")
        return cls(mappings, authenticated_credential_id=authenticated_credential_id)

    @classmethod
    def from_file(
        cls,
        path: Path,
        *,
        authenticated_credential_id: str | None = None,
        require_private: bool = True,
    ) -> "SystemIdentityProvider":
        target = Path(path)
        try:
            info = target.lstat()
            parent_info = target.parent.lstat()
        except OSError as exc:
            raise IdentityError("identity configuration is unavailable") from exc
        if target.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size > MAX_IDENTITY_BYTES:
            raise IdentityError("identity configuration is not a bounded regular file")
        if target.parent.is_symlink() or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_mode & 0o022:
            raise IdentityError("identity configuration parent is not trusted")
        # A dedicated group-read mapping (0640) is the minimum equivalent of
        # a private file when the gateway runs as ops-call; other users and
        # every group write/execute bit remain forbidden.
        if require_private and info.st_mode & 0o037:
            raise IdentityError("identity configuration permissions are too broad")
        value = _yaml_load(target)
        if not isinstance(value, Mapping) or value.get("schema_version") != 1:
            raise IdentityError("identity configuration schema is unsupported")
        return cls.from_mapping(value, authenticated_credential_id=authenticated_credential_id)

    @classmethod
    def from_provider(cls, provider: TrustedResourceProvider) -> "SystemIdentityProvider":
        return cls.from_file(provider.identity_mapping_path())

    def bind(self, credential_id: str | None = None) -> BoundSystemIdentityProvider:
        credential = credential_id or self._authenticated_credential_id
        if credential is None:
            raise IdentityError("authenticated credential is unavailable")
        credential = _validate_credential_id(credential)
        owner_id = self._mappings.get(credential)
        if owner_id is None:
            raise IdentityError("credential is not registered")
        return BoundSystemIdentityProvider(credential, owner_id)

    def owner_id(self, credential_id: str | None = None) -> str:
        """Return an owner for an explicitly bound system credential."""

        return self.bind(credential_id).owner_id()

    def credential_id_from_environment(self, environ: Mapping[str, str] | None = None) -> str:
        values = os.environ if environ is None else environ
        credential = values.get(SYSTEM_CREDENTIAL_ENV)
        return _validate_credential_id(credential)

    def owner_for(self, credential_id: str) -> str:
        """Read one mapping entry without exposing the mapping as a model."""

        return self.bind(credential_id).owner_id()


def _reject_identity_overrides(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if isinstance(key, str) and key.lower() in _IDENTITY_OVERRIDE_KEYS:
                raise GatewayError("request contains an identity or approval override", code="invalid_request")
            _reject_identity_overrides(child)
    elif isinstance(value, list):
        for child in value:
            _reject_identity_overrides(child)


def _request_id(value: Any) -> str:
    if isinstance(value, Mapping) and is_uuid(value.get("request_id")):
        return str(value["request_id"])
    return new_uuid()


class Gateway:
    """Bounded Request → Response dispatcher for the forced-command entry."""

    def __init__(
        self,
        *,
        identity_provider: SystemIdentityProvider | Mapping[str, Any],
        resource_provider: TrustedResourceProvider | None = None,
        store_root: Path | None = None,
        params_root: Path | None = None,
        plan_service_factory: Callable[[BoundSystemIdentityProvider], PlanService] | None = None,
        gate_factory: Callable[[BoundSystemIdentityProvider], ExecutionGate] | None = None,
        launcher_factory: Callable[[BoundSystemIdentityProvider], ExactlyOnceLauncher] | None = None,
        delegate_apply: bool | None = None,
        delegation_broker: FixedBroker | None = None,
        delegation_runner: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
        now: Callable[[], str] | None = None,
        max_request_bytes: int = MAX_REQUEST_BYTES,
    ) -> None:
        if isinstance(identity_provider, SystemIdentityProvider):
            self.identity_provider = identity_provider
        elif isinstance(identity_provider, Mapping):
            self.identity_provider = SystemIdentityProvider.from_mapping(identity_provider)
        else:
            raise IdentityError("identity provider is invalid")
        self.resource_provider = resource_provider or TrustedResourceProvider.from_package()
        self.store_root = Path(store_root) if store_root is not None else SYSTEM_STORE_ROOT
        self.params_root = Path(params_root) if params_root is not None else SYSTEM_PARAMS_ROOT
        if not isinstance(max_request_bytes, int) or isinstance(max_request_bytes, bool) or max_request_bytes < 1:
            raise GatewayError("request limit is invalid", code="precondition_failed")
        self.max_request_bytes = max_request_bytes
        self._plan_service_factory = plan_service_factory
        self._gate_factory = gate_factory
        self._launcher_factory = launcher_factory
        self._delegate_apply = self.store_root == SYSTEM_STORE_ROOT if delegate_apply is None else delegate_apply
        self._delegation_broker = delegation_broker or (system_ops005_broker() if self._delegate_apply else None)
        self._delegation_runner = delegation_runner
        self._now = now

    @classmethod
    def from_system(
        cls,
        *,
        identity_path: Path = SYSTEM_IDENTITY_PATH,
        resource_provider: TrustedResourceProvider | None = None,
        store_root: Path = SYSTEM_STORE_ROOT,
        params_root: Path = SYSTEM_PARAMS_ROOT,
    ) -> "Gateway":
        return cls(
            identity_provider=SystemIdentityProvider.from_file(identity_path),
            resource_provider=resource_provider,
            store_root=store_root,
            params_root=params_root,
            delegate_apply=True,
        )

    def _plan_service(self, identity: BoundSystemIdentityProvider) -> PlanService:
        if self._plan_service_factory is not None:
            return self._plan_service_factory(identity)
        kwargs: dict[str, Any] = {
            "store_root": self.store_root,
            "identity_provider": identity,
            # The system layout is installed by ops-maint. Gateway is a
            # non-root reader/writer of its designated child records and must
            # neither chmod nor create the shared parent at request time.
            "store_private": False,
            "create_store": False,
        }
        if self._now is not None:
            kwargs["now"] = self._now
        return default_plan_service(self.resource_provider, **kwargs)

    def _gate(self, identity: BoundSystemIdentityProvider) -> ExecutionGate:
        if self._gate_factory is not None:
            return self._gate_factory(identity)
        service = self._plan_service(identity)
        return ExecutionGate(
            store=service.store,
            registry=service.registry,
            inventory=service.inventory,
            policy=service.policy,
            identity_provider=identity,
            resolver=service.resolver,
            now=self._now or service.now,
            approval_provider=TrustedApprovalProvider(ApprovalStore(service.store)),
        )

    def _launcher(self, identity: BoundSystemIdentityProvider) -> ExactlyOnceLauncher:
        if self._delegate_apply and self._launcher_factory is None:
            raise GatewayError("production apply must use the fixed cross-UID broker", code="source_unavailable")
        if self._launcher_factory is not None:
            return self._launcher_factory(identity)
        service = self._plan_service(identity)
        return ExactlyOnceLauncher(
            store=service.store,
            gate=self._gate(identity),
            broker=default_ops005_broker(store_root=self.store_root),
            service_manager=Ops005NoopServiceManager(),
            result_service=ResultService(service.store, now=self._now or service.now),
            now=self._now or service.now,
        )

    @staticmethod
    def _publish_plan_projection(service: PlanService, plan: Mapping[str, Any]) -> None:
        """Expose an immutable Plan to the approval/executor read group."""

        try:
            relative = service.store.record_path("plans", str(plan["plan_id"]))
            target = service.store.safe_path(relative)
            info = target.lstat()
            parent_info = target.parent.lstat()
            if target.is_symlink() or not stat.S_ISREG(info.st_mode):
                raise OSError("plan projection target is not a regular file")
            if target.parent.is_symlink() or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_mode & 0o022:
                raise OSError("plan projection parent is not trusted")
            # Keep owner-only write while granting only group read.  The
            # deployment-provisioned parent owns the dedicated reader group
            # and setgid bit.  Do not chmod that parent from ops-call: on Unix
            # an unprivileged owner who is not a member of the directory group
            # can have setgid cleared as a side effect, causing later Plan
            # files to inherit the private caller group instead.
            target.chmod((stat.S_IMODE(info.st_mode) & 0o700) | 0o040)
        except (OSError, StorageError, KeyError, TypeError) as exc:
            raise GatewayError("immutable plan read projection is unavailable", code="storage_failed") from exc

    def _assert_plan_owner(self, identity: BoundSystemIdentityProvider, plan_id: str) -> None:
        if not isinstance(plan_id, str) or not is_uuid(plan_id):
            raise GatewayError("plan ID is invalid", code="invalid_request")
        service = self._plan_service(identity)
        try:
            plan = service.store.read_record(service.store.record_path("plans", plan_id), "Plan")
        except (RecordNotFound, StorageError, ModelError) as exc:
            raise GatewayError("immutable plan is unavailable", code="storage_failed") from exc
        try:
            owner_id = identity.owner_id()
        except Exception as exc:
            raise GatewayError("trusted current owner is unavailable", code="precondition_failed") from exc
        if plan.get("owner_id") != owner_id:
            raise GatewayError("plan owner is not the trusted current owner", code="precondition_failed")

    def _delegate(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if self._delegation_broker is None:
            raise GatewayError("fixed cross-UID broker is unavailable", code="source_unavailable")
        try:
            return self._delegation_broker.delegate(request, runner=self._delegation_runner)
        except BrokerError as exc:
            raise GatewayError("fixed broker denied the request", code=exc.code) from exc

    def _read_params(self, reference: str) -> dict[str, Any]:
        if not safe_relative_reference(reference):
            raise PlanError("request params reference is not safe", code="invalid_request")
        try:
            store = AtomicJsonStore(self.params_root, max_bytes=1 << 20)
            value = store.read_json(reference)
        except (RecordNotFound, StorageError) as exc:
            raise PlanError("request params are unavailable", code="source_unavailable") from exc
        if not isinstance(value, dict):
            raise PlanError("request params must be an object", code="invalid_request")
        return value

    def _dispatch(self, request: Mapping[str, Any], identity: BoundSystemIdentityProvider) -> tuple[dict[str, Any], bool]:
        command = request["command"]
        params = request["params"]
        if command not in _ALLOWED_COMMANDS:
            raise GatewayError("command is not enabled by the gateway", code="unsupported_command")
        if command == "doctor":
            data, exit_code = run_doctor(provider=self.resource_provider)
            if exit_code != EXIT_OK:
                raise GatewayError("offline doctor could not complete", code="source_unavailable")
            return data, True
        if command == "actions.list":
            return {"actions": ActionRegistry(self.resource_provider).list_public()}, False
        if command == "plan":
            plan_params = self._read_params(params["params_file"])
            service = self._plan_service(identity)
            plan = service.create_plan(
                params["action"],
                params["target"],
                plan_params,
            )
            if self._delegate_apply:
                self._publish_plan_projection(service, plan)
            return {"plan": plan}, False
        if command == "apply":
            if self._delegate_apply:
                self._assert_plan_owner(identity, params["plan_id"])
                return self._delegate(request), False
            outcome = self._launcher(identity).apply(params["plan_id"])
            return outcome.data(), False
        if command == "result":
            service = self._plan_service(identity)
            result = ResultService(service.store, now=self._now or service.now).get(params["run_id"])
            if result.get("owner_id") != identity.owner_id():
                raise GatewayError("result belongs to another owner", code="precondition_failed")
            return {"result": result}, False
        raise GatewayError("command is not enabled by the gateway", code="unsupported_command")

    def handle(self, request: Mapping[str, Any], *, credential_id: str | None = None) -> dict[str, Any]:
        request_id = _request_id(request)
        try:
            if not isinstance(request, Mapping):
                raise GatewayError("request must be an object", code="invalid_request")
            request_value = dict(request)
            validate_model("Request", request_value)
            _reject_identity_overrides(request_value["params"])
            identity = self.identity_provider.bind(credential_id)
            data, doctor_data = self._dispatch(request_value, identity)
            return make_response(request_id, ok=True, data=data, validate=doctor_data)
        except (
            GatewayError,
            IdentityError,
            ModelError,
            ModelDependencyError,
            ResourceError,
            RegistryError,
            InventoryError,
            PlanError,
            GateError,
            LaunchError,
            ResultError,
        ) as exc:
            code = getattr(exc, "code", "precondition_failed")
            # Keep the public error vocabulary aligned with the v1 schema and
            # do not include exception text, paths, credentials, or secrets.
            return make_response(
                request_id,
                ok=False,
                error=_error(code, "gateway request denied", reason=code),
            )
        except Exception:
            return make_response(
                request_id,
                ok=False,
                error=_error("storage_failed", "gateway request failed internally", reason="storage_failed"),
            )

    def handle_bytes(self, raw: bytes, *, credential_id: str | None = None) -> dict[str, Any]:
        if not isinstance(raw, bytes) or len(raw) > self.max_request_bytes:
            return make_response(
                new_uuid(),
                ok=False,
                error=_error("invalid_request", "gateway request denied", reason="request_limit"),
            )
        try:
            request = strict_json_loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ModelError):
            return make_response(
                new_uuid(),
                ok=False,
                error=_error("invalid_json", "gateway request denied", reason="invalid_json"),
            )
        if not isinstance(request, Mapping):
            return make_response(
                new_uuid(),
                ok=False,
                error=_error("invalid_request", "gateway request denied", reason="request_object_required"),
            )
        return self.handle(request, credential_id=credential_id)

    def serve(
        self,
        *,
        credential_id: str | None = None,
        stdin: TextIO | Any | None = None,
        stdout: TextIO | Any | None = None,
        environment: Mapping[str, str] | None = None,
        original_command: str | None = None,
        pty_requested: bool = False,
        subsystem: str | None = None,
        agent_forwarding: bool = False,
        x11_forwarding: bool = False,
        port_forwarding: bool = False,
    ) -> int:
        """Serve exactly one bounded Request from stdin and one Response."""

        from .executor import clean_forced_environment, validate_forced_command

        response_id = new_uuid()
        try:
            clean_environment = clean_forced_environment(environment)
            session_environment = os.environ if environment is None else environment
            validate_forced_command(
                original_command=(
                    original_command
                    if original_command is not None
                    else session_environment.get("SSH_ORIGINAL_COMMAND")
                ),
                environment=environment,
                pty_requested=pty_requested or bool(session_environment.get("SSH_TTY")),
                subsystem=subsystem,
                agent_forwarding=agent_forwarding or bool(session_environment.get("SSH_AUTH_SOCK")),
                x11_forwarding=x11_forwarding or bool(session_environment.get("DISPLAY")),
                port_forwarding=port_forwarding,
            )
            context_credential = clean_environment.get(SYSTEM_CREDENTIAL_ENV)
            if credential_id is not None and context_credential is not None and credential_id != context_credential:
                raise GatewayError("credential context does not match", code="precondition_failed")
            if credential_id is None:
                credential_id = self.identity_provider.credential_id_from_environment(clean_environment)
            source = sys.stdin if stdin is None else stdin
            output = sys.stdout if stdout is None else stdout
            raw_source = getattr(source, "buffer", source)
            raw = raw_source.read(self.max_request_bytes + 1)
            if isinstance(raw, str):
                raw = raw.encode("utf-8")
            response = self.handle_bytes(raw, credential_id=credential_id)
            response_id = response.get("request_id", response_id)
            output_target = getattr(output, "buffer", output)
            encoded = canonical_json_bytes(response) + b"\n"
            try:
                output_target.write(encoded)
            except TypeError:
                output.write(encoded.decode("utf-8"))
            output.flush()
            return EXIT_OK if response.get("ok") else 1
        except Exception:
            response = make_response(
                response_id,
                ok=False,
                error=_error("precondition_failed", "gateway request denied", reason="forced_command_boundary"),
            )
            output = sys.stdout if stdout is None else stdout
            output_target = getattr(output, "buffer", output)
            encoded = canonical_json_bytes(response) + b"\n"
            try:
                output_target.write(encoded)
            except TypeError:
                output.write(encoded.decode("utf-8"))
            output.flush()
            return 1


def main(argv: Sequence[str] | None = None) -> int:
    """Forced-command entry point; it accepts no command-line options."""

    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        response = make_response(
            new_uuid(),
            ok=False,
            error=_error("invalid_request", "gateway request denied", reason="gateway_has_no_cli_options"),
        )
        sys.stdout.write(canonical_json_bytes(response).decode("utf-8") + "\n")
        return EXIT_INPUT
    try:
        gateway = Gateway.from_system()
    except (IdentityError, ResourceError, OSError):
        response = make_response(
            new_uuid(),
            ok=False,
            error=_error("source_unavailable", "gateway request denied", reason="trusted_configuration_unavailable"),
        )
        sys.stdout.write(canonical_json_bytes(response).decode("utf-8") + "\n")
        return 1
    return gateway.serve()


__all__ = [
    "BoundSystemIdentityProvider",
    "Gateway",
    "GatewayError",
    "IdentityError",
    "SYSTEM_CREDENTIAL_ENV",
    "SYSTEM_IDENTITY_PATH",
    "SYSTEM_PARAMS_ROOT",
    "SYSTEM_STORE_ROOT",
    "SystemIdentityProvider",
    "main",
]
