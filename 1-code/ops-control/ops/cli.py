"""Strict offline CLI shell for the OPS-002 contracts."""

from __future__ import annotations

import argparse
import importlib.util
import json
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .models import (
    ModelDependencyError,
    ModelError,
    MODEL_SCHEMAS,
    canonical_json_bytes,
    new_uuid,
    strict_json_loads,
    validate_model,
    validate_schema_documents,
)
from client.approval import ApprovalClientError, LoopbackApprovalClient
from .gates import GateError
from .inventory import InventoryError
from .plans import PlanError, default_plan_service
from .registry import RegistryError, ActionRegistry
from .resources import ResourceError, TrustedResourceProvider
from .results import ResultError
from .executor.launch import LaunchError


EXIT_OK = 0
EXIT_INPUT = 2
EXIT_AUTH = 3
EXIT_PRECONDITION = 4
EXIT_FAILURE = 5


def _error(code: str, message: str, *, reason: str | None = None, hint: str | None = None) -> dict[str, Any]:
    details: dict[str, Any] = {}
    if reason is not None:
        details["reason"] = reason
    if hint is not None:
        details["hint"] = hint
    return {"code": code, "message": message, "details": details}


def make_response(
    request_id: str,
    *,
    ok: bool,
    data: dict[str, Any] | None = None,
    error: dict[str, Any] | None = None,
    validate: bool = True,
) -> dict[str, Any]:
    response = {
        "schema_version": 1,
        "request_id": request_id,
        "ok": ok,
        "data": data,
        "error": error,
        "generated_at": _utc_now(),
    }
    if ok and error is not None:
        raise ValueError("successful response cannot carry an error")
    if not ok and error is None:
        raise ValueError("failed response must carry an error")
    if validate:
        try:
            validate_model("Response", response)
        except ModelDependencyError:
            # A bare interpreter can still report dependency_missing as JSON.
            # The doctor result is explicit about the missing validator.
            pass
    else:
        # OPS-002's published v1 envelope has an empty-object extension slot,
        # while its frozen schema only describes doctor_data.  Validate all
        # envelope fields against that schema before attaching the
        # command-specific, still JSON-only data object.
        envelope = dict(response)
        envelope["data"] = {}
        try:
            validate_model("Response", envelope)
        except ModelDependencyError:
            pass
    return response


def _utc_now() -> str:
    from .models import utc_now

    return utc_now()


def render_human(response: dict[str, Any]) -> str:
    """Render the same response object, without performing a second lookup."""
    status = "OK" if response.get("ok") else "ERROR"
    lines = [f"{status} request={response.get('request_id', 'unknown')}"]
    data = response.get("data")
    if isinstance(data, dict):
        for key in sorted(data):
            value = data[key]
            if isinstance(value, dict):
                value = ", ".join(f"{child}={value[child]}" for child in sorted(value))
            lines.append(f"{key}: {value}")
    error = response.get("error")
    if isinstance(error, dict):
        lines.append(f"error: {error.get('code', 'unknown')} — {error.get('message', 'request failed')}")
    return "\n".join(lines)


class _Parser(argparse.ArgumentParser):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("add_help", False)
        kwargs.setdefault("allow_abbrev", False)
        kwargs.setdefault("exit_on_error", False)
        super().__init__(*args, **kwargs)


def _add_parser(parent: argparse._SubParsersAction[Any], name: str) -> _Parser:
    return parent.add_parser(name)


def _build_parser() -> _Parser:
    parser = _Parser(prog="ops")
    commands = parser.add_subparsers(dest="top_command", required=True, parser_class=_Parser)

    doctor = _add_parser(commands, "doctor")
    doctor.add_argument("--offline", action="store_true", required=True)

    status = _add_parser(commands, "status")
    status.add_argument("--target")

    inspect = _add_parser(commands, "inspect")
    inspect.add_argument("--target", required=True)
    inspect.add_argument("--kind", choices=["health", "software", "backup", "all"], required=True)

    actions = _add_parser(commands, "actions")
    actions_commands = actions.add_subparsers(dest="actions_command", required=True)
    _add_parser(actions_commands, "list")

    plan = _add_parser(commands, "plan")
    plan.add_argument("action")
    plan.add_argument("--target", required=True)
    plan.add_argument("--params-file", required=True)

    approval = _add_parser(commands, "approval")
    approval_commands = approval.add_subparsers(dest="approval_command", required=True)
    approval_open = _add_parser(approval_commands, "open")
    approval_open.add_argument("plan_id")

    apply = _add_parser(commands, "apply")
    apply.add_argument("plan_id")

    result = _add_parser(commands, "result")
    result.add_argument("run_id")

    logs = _add_parser(commands, "logs")
    logs.add_argument("run_id")
    logs.add_argument("--host")
    log_page = logs.add_mutually_exclusive_group()
    log_page.add_argument("--tail", type=int)
    log_page.add_argument("--cursor")

    knowledge = _add_parser(commands, "knowledge")
    knowledge_commands = knowledge.add_subparsers(dest="knowledge_command", required=True)
    knowledge_list = _add_parser(knowledge_commands, "list")
    knowledge_list.add_argument("--software", required=True)
    knowledge_list.add_argument("--host")
    knowledge_note = _add_parser(knowledge_commands, "add-note")
    knowledge_note.add_argument("--run", required=True)
    knowledge_note.add_argument("--host", required=True)
    knowledge_note.add_argument("--file", required=True)

    context = _add_parser(commands, "context")
    context_commands = context.add_subparsers(dest="context_command", required=True)
    _add_parser(context_commands, "export")
    context_pull = _add_parser(context_commands, "pull")
    context_pull.add_argument("--destination", required=True)
    context_pull.add_argument("--export")

    package = _add_parser(commands, "package")
    package_commands = package.add_subparsers(dest="package_command", required=True)
    package_validate = _add_parser(package_commands, "validate")
    package_validate.add_argument("--manifest", required=True)
    package_upload = _add_parser(package_commands, "upload")
    package_upload.add_argument("--manifest", required=True)
    package_upload.add_argument("--directory", required=True)
    package_show = _add_parser(package_commands, "show")
    package_show.add_argument("package_id")

    local = _add_parser(commands, "local")
    local_commands = local.add_subparsers(dest="local_command", required=True)
    local_software = _add_parser(local_commands, "software")
    local_software_commands = local_software.add_subparsers(dest="local_software_command", required=True)
    _add_parser(local_software_commands, "list")
    local_check = _add_parser(local_software_commands, "check")
    local_check.add_argument("software_id")
    local_plan = _add_parser(local_software_commands, "plan")
    local_plan.add_argument("software_id")
    local_plan.add_argument("--version", required=True)
    local_apply = _add_parser(local_software_commands, "apply")
    local_apply.add_argument("local_plan_id")

    return parser


def _resource_status(provider: TrustedResourceProvider, relative: str, *, parse_yaml: bool) -> str:
    try:
        path = provider.path(relative)
        if parse_yaml:
            try:
                import yaml
            except ImportError:
                return "invalid"
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict) or value.get("schema_version") != 1:
                return "invalid"
            if relative == "policy/logging.yml":
                from .logs import load_logging_policy

                load_logging_policy(path)
            elif relative == "policy/credential-refs.yml":
                stores = value.get("stores")
                if not isinstance(stores, list) or not stores:
                    return "invalid"
                for store in stores:
                    if not isinstance(store, dict) or not isinstance(store.get("name"), str) or not isinstance(store.get("fields"), list):
                        return "invalid"
            elif relative == "inventory/management.yml":
                if not isinstance(value.get("hosts"), dict):
                    return "invalid"
        else:
            path.read_text(encoding="utf-8")
        return "ok"
    except ResourceError:
        return "unavailable"
    except Exception:
        return "invalid"


def run_doctor(*, provider: TrustedResourceProvider | None = None) -> tuple[dict[str, Any], int]:
    """Perform only local dependency/schema/reference checks."""
    dependencies = {
        "jsonschema": "ok" if importlib.util.find_spec("jsonschema") is not None else "missing",
        "yaml": "ok" if importlib.util.find_spec("yaml") is not None else "missing",
    }
    schema_count = len(MODEL_SCHEMAS)
    schema_valid = False
    schema_error: str | None = None
    if dependencies["jsonschema"] == "ok":
        try:
            validate_schema_documents()
            schema_valid = True
        except Exception:
            schema_error = "schema meta-validation failed"
    else:
        schema_error = "jsonschema dependency is missing"

    if provider is None:
        try:
            provider = TrustedResourceProvider.from_package()
        except ResourceError:
            provider = None
    if provider is None:
        logging_status = "unavailable"
        credential_status = "unavailable"
        management_status = "unavailable"
    else:
        logging_status = _resource_status(provider, "policy/logging.yml", parse_yaml=True)
        credential_status = _resource_status(provider, "policy/credential-refs.yml", parse_yaml=True)
        management_status = _resource_status(provider, "inventory/management.yml", parse_yaml=True)

    py_version = ".".join(map(str, sys.version_info[:3]))
    py_compatible = sys.version_info >= (3, 12)
    data: dict[str, Any] = {
        "offline": True,
        "python_version": py_version,
        "python_compatible": py_compatible,
        "schema_count": schema_count,
        "schema_valid": schema_valid,
        "references": {
            "logging_policy": logging_status,
            "credential_refs": credential_status,
            "management_metadata": management_status,
        },
        "dependencies": dependencies,
        "network_used": False,
    }
    if not py_compatible:
        return data, EXIT_PRECONDITION
    if any(status == "invalid" for status in (logging_status, credential_status, management_status)):
        return data, EXIT_INPUT
    if not schema_valid or any(status != "ok" for status in dependencies.values()):
        return data, EXIT_INPUT
    return data, EXIT_OK


def _namespace_command(namespace: argparse.Namespace) -> str:
    top = namespace.top_command
    if top == "actions":
        return "actions.list"
    if top == "approval":
        return "approval.open"
    if top == "knowledge":
        return f"knowledge.{namespace.knowledge_command}"
    if top == "context":
        return f"context.{namespace.context_command}"
    if top == "package":
        return f"package.{namespace.package_command}"
    if top == "local":
        return f"local.software.{namespace.local_software_command}"
    return top


def _unsupported_response(request_id: str, command: str) -> tuple[dict[str, Any], int]:
    return (
        make_response(
            request_id,
            ok=False,
            error=_error("unsupported_command", f"{command} is not implemented in OPS-002", reason="future_issue"),
        ),
        EXIT_PRECONDITION,
    )


def _read_params_file(path_value: str) -> dict[str, Any]:
    """Read one bounded JSON params object; never retain its filesystem path."""
    if not isinstance(path_value, str) or not path_value:
        raise PlanError("params file is required", code="invalid_request")
    path = Path(path_value)
    try:
        info = path.lstat()
    except OSError as exc:
        raise PlanError("params file is unavailable", code="source_unavailable") from exc
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size > (1 << 20):
        raise PlanError("params file is not a bounded regular file", code="invalid_request")
    try:
        value = strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ModelError) as exc:
        raise PlanError("params file is not valid JSON", code="invalid_json") from exc
    if not isinstance(value, dict):
        raise PlanError("params file must contain an object", code="invalid_request")
    return value


def _run_parsed(namespace: argparse.Namespace, request_id: str) -> tuple[dict[str, Any], int]:
    command = _namespace_command(namespace)
    if command == "doctor":
        data, exit_code = run_doctor()
        if exit_code == EXIT_OK:
            return make_response(request_id, ok=True, data=data), exit_code
        if data["dependencies"]["jsonschema"] != "ok" or data["dependencies"]["yaml"] != "ok":
            error_code = "dependency_missing"
            message = "offline doctor found a missing runtime dependency"
        elif not data["schema_valid"]:
            error_code = "storage_failed"
            message = "offline doctor found invalid schema resources"
        else:
            error_code = "source_unavailable"
            message = "offline doctor could not resolve a required sanitized reference"
        return make_response(request_id, ok=False, data=data, error=_error(error_code, message)), exit_code
    if command == "actions.list":
        provider = TrustedResourceProvider.from_package()
        actions = ActionRegistry(provider).list_public()
        return make_response(request_id, ok=True, data={"actions": actions}, validate=False), EXIT_OK
    if command == "plan":
        provider = TrustedResourceProvider.from_package()
        params = _read_params_file(namespace.params_file)
        service = default_plan_service(provider)
        plan = service.create_plan(namespace.action, namespace.target, params)
        return make_response(request_id, ok=True, data={"plan": plan}, validate=False), EXIT_OK
    if command == "approval.open":
        try:
            link = LoopbackApprovalClient().open(namespace.plan_id)
            LoopbackApprovalClient().open_browser(link)
        except ApprovalClientError as exc:
            return (
                make_response(request_id, ok=False, error=_error(exc.code, "approval session could not be opened", reason=exc.code)),
                EXIT_PRECONDITION,
            )
        return (
            make_response(
                request_id,
                ok=True,
                data={"session_id": link.session_id, "url": link.url, "expires_at": link.expires_at},
                validate=False,
            ),
            EXIT_OK,
        )
    if command == "apply":
        from .approval.store import ApprovalStore, TrustedApprovalProvider
        from .executor.launch import ExactlyOnceLauncher, Ops005NoopServiceManager, default_ops005_broker
        from .gates import ExecutionGate
        from .results import ResultService

        provider = TrustedResourceProvider.from_package()
        service = default_plan_service(provider)
        gate = ExecutionGate(
            store=service.store,
            registry=service.registry,
            inventory=service.inventory,
            policy=service.policy,
            identity_provider=service.identity_provider,
            resolver=service.resolver,
            now=service.now,
            approval_provider=TrustedApprovalProvider(ApprovalStore(service.store)),
        )
        launcher = ExactlyOnceLauncher(
            store=service.store,
            gate=gate,
            broker=default_ops005_broker(store_root=service.store.root),
            service_manager=Ops005NoopServiceManager(),
            result_service=ResultService(service.store, now=service.now),
            now=service.now,
        )
        outcome = launcher.apply(namespace.plan_id)
        return make_response(request_id, ok=True, data=outcome.data(), validate=False), EXIT_OK
    if command == "result":
        from .results import ResultService

        provider = TrustedResourceProvider.from_package()
        service = default_plan_service(provider)
        result = ResultService(service.store, now=service.now).get(namespace.run_id)
        if result.get("owner_id") != service.identity_provider.owner_id():
            raise PlanError("run result belongs to another owner", code="precondition_failed")
        return make_response(request_id, ok=True, data={"result": result}, validate=False), EXIT_OK
    return _unsupported_response(request_id, command)


def _parse(argv: Sequence[str]) -> tuple[argparse.Namespace | None, bool, str | None]:
    human = False
    filtered: list[str] = []
    for argument in argv:
        if argument == "--human":
            human = True
        else:
            filtered.append(argument)
    try:
        return _build_parser().parse_args(filtered), human, None
    except (argparse.ArgumentError, SystemExit, ValueError):
        return None, human, "command arguments are invalid"


def _emit(response: dict[str, Any], *, human: bool) -> None:
    output = render_human(response) if human else canonical_json_bytes(response).decode("utf-8")
    sys.stdout.write(output + "\n")


def main(argv: Sequence[str] | None = None) -> int:
    request_id = new_uuid()
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "gateway":
        # The gateway owns its own one-Request/one-Response stdio contract and
        # accepts no CLI options.  Keep this import lazy to avoid a cycle:
        # gateway reuses the response helpers above.
        from .gateway import main as gateway_main

        return gateway_main(args[1:])
    namespace, human, parse_error = _parse(args)
    if parse_error is not None or namespace is None:
        response = make_response(request_id, ok=False, error=_error("invalid_request", parse_error or "invalid command"))
        _emit(response, human=human)
        return EXIT_INPUT
    try:
        response, exit_code = _run_parsed(namespace, request_id)
    except (
        ModelError,
        ModelDependencyError,
        ResourceError,
        RegistryError,
        InventoryError,
        PlanError,
        ApprovalClientError,
        GateError,
        LaunchError,
        ResultError,
    ) as exc:
        # The public response contains only a stable code and safe message.
        code = getattr(exc, "code", "storage_failed")
        details = getattr(exc, "details", {})
        reason = details.get("reason") if isinstance(details, dict) else None
        response = make_response(
            request_id,
            ok=False,
            error=_error(code, "offline command could not complete", reason=reason or code),
        )
        exit_code = EXIT_INPUT
    except Exception:
        response = make_response(request_id, ok=False, error=_error("storage_failed", "offline command failed internally"))
        exit_code = EXIT_FAILURE
        sys.stderr.write("ops: internal failure\n")
    _emit(response, human=human)
    return exit_code


__all__ = [
    "EXIT_AUTH",
    "EXIT_FAILURE",
    "EXIT_INPUT",
    "EXIT_OK",
    "EXIT_PRECONDITION",
    "main",
    "make_response",
    "render_human",
    "run_doctor",
]
