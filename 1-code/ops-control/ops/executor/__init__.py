"""Forced-command boundary helpers for the OPS-004 deployment.

This module validates the SSH session boundary and produces a minimal fixed
environment for the gateway. It does not provide a shell, a subsystem, a
forwarder, or a generic command runner.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Mapping
from typing import Any, Sequence


SYSTEM_CREDENTIAL_ENV = "OPS_CONTROL_CREDENTIAL_ID"
FORCED_COMMAND_PATH = "/usr/local/libexec/ops-control/ops-call"
FIXED_REMOTE_COMMAND = "ops-call"
BOUND_CREDENTIAL_OPTION = "--credential-id"
FIXED_WRAPPER_INTERPRETER = "/usr/bin/python3"
FIXED_PATH = "/usr/local/libexec/ops-control:/usr/bin:/bin"
_SAFE_ID = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$")
_ALLOWED_CONTEXT_ENV = frozenset({SYSTEM_CREDENTIAL_ENV})


class ForcedCommandError(RuntimeError):
    """A session failed the SSH forced-command boundary."""

    code = "precondition_failed"


def validate_forced_command(
    *,
    original_command: str | None = None,
    environment: Mapping[str, str] | None = None,
    env: Mapping[str, str] | None = None,
    pty_requested: bool = False,
    subsystem: str | None = None,
    agent_forwarding: bool = False,
    x11_forwarding: bool = False,
    port_forwarding: bool = False,
) -> None:
    """Reject every client-controlled SSH feature outside JSON stdin.

    The optional ``environment`` argument represents the environment values
    supplied by the SSH client, not the full server process environment. The
    wrapper ignores inherited process variables and only preserves the one
    server-side credential marker.
    """

    if env is not None:
        if environment is not None:
            raise ForcedCommandError("duplicate client environment input")
        environment = env
    if original_command not in (None, "", FIXED_REMOTE_COMMAND):
        raise ForcedCommandError("client command is not allowed")
    if pty_requested:
        raise ForcedCommandError("PTY is not allowed")
    if subsystem not in (None, ""):
        raise ForcedCommandError("SSH subsystem is not allowed")
    if agent_forwarding or x11_forwarding or port_forwarding:
        raise ForcedCommandError("SSH forwarding is not allowed")
    if environment is not None:
        if not isinstance(environment, Mapping):
            raise ForcedCommandError("client environment is not allowed")
        unknown = set(environment) - _ALLOWED_CONTEXT_ENV
        if unknown:
            raise ForcedCommandError("client environment is not allowed")
        credential = environment.get(SYSTEM_CREDENTIAL_ENV)
        if credential is not None and (not isinstance(credential, str) or not _SAFE_ID.fullmatch(credential)):
            raise ForcedCommandError("server credential context is invalid")


def _validate_bound_credential(value: Any) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise ForcedCommandError("bound credential context is invalid")
    return value


def parse_bound_credential(argv: Sequence[str]) -> str:
    """Parse the one credential binding installed in a root-owned key line."""

    args = list(argv)
    if len(args) != 2 or args[0] != BOUND_CREDENTIAL_OPTION:
        raise ForcedCommandError("forced command binding is invalid")
    return _validate_bound_credential(args[1])


def clean_forced_environment(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a fixed environment with Python/Ansible search paths removed.

    ``OPS_CONTROL_CREDENTIAL_ID`` is retained only as a server-side test seam
    or as the context handed off by the fixed wrapper. It is never copied
    from arbitrary client environment values.
    """

    source = os.environ if environ is None else environ
    clean = {
        "PATH": FIXED_PATH,
        "LANG": "C",
        "LC_ALL": "C",
    }
    credential = source.get(SYSTEM_CREDENTIAL_ENV)
    if credential is not None:
        if not isinstance(credential, str) or not _SAFE_ID.fullmatch(credential):
            raise ForcedCommandError("server credential context is invalid")
        clean[SYSTEM_CREDENTIAL_ENV] = credential
    return clean


def forced_command_options(credential_id: str) -> tuple[str, ...]:
    """SSH authorized-key options for one fixed, maintenance-bound key."""

    credential_id = _validate_bound_credential(credential_id)

    return (
        "restrict",
        "no-pty",
        "no-agent-forwarding",
        "no-X11-forwarding",
        "no-port-forwarding",
        "no-user-rc",
        f'command="{FIXED_WRAPPER_INTERPRETER} -E -s {FORCED_COMMAND_PATH} {BOUND_CREDENTIAL_OPTION} {credential_id}"',
    )


def run_forced_command(
    gateway: Any,
    *,
    stdin: Any,
    stdout: Any,
    environment: Mapping[str, str] | None = None,
    credential_id: str | None = None,
    original_command: str | None = None,
    pty_requested: bool = False,
    subsystem: str | None = None,
    agent_forwarding: bool = False,
    x11_forwarding: bool = False,
    port_forwarding: bool = False,
) -> int:
    """Run an already-constructed gateway after boundary validation."""

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
    context = clean_forced_environment(environment) if environment is not None else {}
    context_credential = context.get(SYSTEM_CREDENTIAL_ENV)
    if credential_id is not None:
        credential_id = _validate_bound_credential(credential_id)
        if context_credential is not None and credential_id != context_credential:
            raise ForcedCommandError("bound credential context does not match")
    elif context_credential is not None:
        credential_id = _validate_bound_credential(context_credential)
    else:
        raise ForcedCommandError("bound credential context is unavailable")
    gateway_environment = {SYSTEM_CREDENTIAL_ENV: credential_id}
    return gateway.serve(
        credential_id=credential_id,
        stdin=stdin,
        stdout=stdout,
        environment=gateway_environment,
        original_command="",
        pty_requested=False,
        subsystem=None,
    )


forced_command = run_forced_command


def _emit_boundary_error(*, code: str, reason: str) -> int:
    from ..cli import EXIT_INPUT, make_response
    from ..models import canonical_json_bytes, new_uuid

    response = make_response(
        new_uuid(),
        ok=False,
        error={"code": code, "message": "gateway request denied", "details": {"reason": reason}},
    )
    sys.stdout.write(canonical_json_bytes(response).decode("utf-8") + "\n")
    sys.stdout.flush()
    return EXIT_INPUT


def main(argv: Sequence[str] | None = None) -> int:
    """Run the fixed wrapper entry point installed by an independent maintainer."""

    args = list(sys.argv[1:] if argv is None else argv)
    try:
        credential_id = parse_bound_credential(args)
    except ForcedCommandError:
        return _emit_boundary_error(code="invalid_request", reason="forced_command_binding")

    try:
        from ..gateway import Gateway, IdentityError
        from ..resources import ResourceError

        gateway = Gateway.from_system()
    except (IdentityError, ResourceError, OSError):
        return _emit_boundary_error(code="source_unavailable", reason="trusted_configuration_unavailable")
    try:
        return run_forced_command(
            gateway,
            credential_id=credential_id,
            stdin=sys.stdin,
            stdout=sys.stdout,
        )
    except ForcedCommandError:
        return _emit_boundary_error(code="precondition_failed", reason="forced_command_boundary")


__all__ = [
    "FIXED_PATH",
    "FIXED_REMOTE_COMMAND",
    "FORCED_COMMAND_PATH",
    "BOUND_CREDENTIAL_OPTION",
    "FIXED_WRAPPER_INTERPRETER",
    "ForcedCommandError",
    "SYSTEM_CREDENTIAL_ENV",
    "clean_forced_environment",
    "forced_command",
    "forced_command_options",
    "main",
    "parse_bound_credential",
    "run_forced_command",
    "validate_forced_command",
]
