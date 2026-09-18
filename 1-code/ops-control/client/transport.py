"""Bounded system SSH transport for the OPS control protocol.

The transport deliberately has two separate seams:

* :class:`Transport` remains the small byte-oriented injection seam used by
  OPS-002 tests; and
* :class:`SystemSSHTransport` is the only implementation that starts the
  system ``ssh`` executable. Its destination, key, known-hosts file and
  remote gateway are all fixed when the trusted configuration is built.

No value from a Request is ever interpolated into the SSH command line.
"""

from __future__ import annotations

import math
import re
import subprocess
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ops.models import (
    ModelDependencyError,
    ModelError,
    canonical_json_bytes,
    strict_json_loads,
    validate_model,
)


class TransportError(RuntimeError):
    """A fail-closed transport error with no subprocess detail."""

    code = "transport_unavailable"


class SSHConfigProvider(Protocol):
    """A maintenance-owned source of one fixed SSH connection."""

    def connection(self) -> "SSHConnectionConfig":
        ...


@dataclass(frozen=True)
class SSHConnectionConfig:
    """Trusted connection material used to build one immutable SSH command.

    This object is constructed by maintenance code or an explicit test
    fixture. It is never constructed from a Request or a CLI parameter.
    ``known_hosts_file`` defaults to the system-wide file so strict host-key
    checking remains enabled even when a fixture does not need a custom path.
    """

    hostname: str
    user: str
    port: int = 22
    identity_file: Path | None = None
    known_hosts_file: Path = Path("/etc/ssh/ssh_known_hosts")
    connect_timeout: float = 10.0
    total_timeout: float = 30.0
    max_input_bytes: int = 1 << 20
    max_output_bytes: int = 1 << 20
    ssh_executable: str = "/usr/bin/ssh"

    def __post_init__(self) -> None:
        if not isinstance(self.hostname, str) or not _SAFE_HOST.fullmatch(self.hostname):
            raise TransportError("trusted SSH hostname is invalid")
        if not isinstance(self.user, str) or not _SAFE_USER.fullmatch(self.user):
            raise TransportError("trusted SSH user is invalid")
        if not isinstance(self.port, int) or isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            raise TransportError("trusted SSH port is invalid")
        for name, value in (
            ("connect timeout", self.connect_timeout),
            ("total timeout", self.total_timeout),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise TransportError(f"trusted SSH {name} is invalid")
        if self.total_timeout < self.connect_timeout:
            raise TransportError("trusted SSH total timeout is shorter than connect timeout")
        for name, value in (
            ("input", self.max_input_bytes),
            ("output", self.max_output_bytes),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise TransportError(f"trusted SSH {name} limit is invalid")
        _trusted_path(self.known_hosts_file, label="known-hosts")
        if self.identity_file is not None:
            _trusted_path(self.identity_file, label="identity")
        if not isinstance(self.ssh_executable, str) or not self.ssh_executable:
            raise TransportError("trusted SSH executable is invalid")
        if "\x00" in self.ssh_executable or any(char.isspace() for char in self.ssh_executable):
            raise TransportError("trusted SSH executable is invalid")

    @property
    def username(self) -> str:
        """Compatibility spelling for callers that use ``username``."""

        return self.user

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "SSHConnectionConfig":
        """Build a config from maintenance data, never from a Request."""

        if not isinstance(value, Mapping):
            raise TransportError("trusted SSH configuration is invalid")
        allowed = {
            "hostname",
            "host",
            "user",
            "username",
            "port",
            "identity_file",
            "key_path",
            "known_hosts_file",
            "known_hosts",
            "connect_timeout",
            "total_timeout",
            "max_input_bytes",
            "max_output_bytes",
            "ssh_executable",
        }
        if set(value) - allowed:
            raise TransportError("trusted SSH configuration contains an unsupported field")
        try:
            hostname = value.get("hostname", value.get("host"))
            user = value.get("user", value.get("username"))
            known_hosts = value.get("known_hosts_file", value.get("known_hosts"))
            identity = value.get("identity_file", value.get("key_path"))
            return cls(
                hostname=hostname,
                user=user,
                port=value.get("port", 22),
                identity_file=Path(identity) if identity is not None else None,
                known_hosts_file=Path(known_hosts) if known_hosts is not None else Path("/etc/ssh/ssh_known_hosts"),
                connect_timeout=value.get("connect_timeout", 10.0),
                total_timeout=value.get("total_timeout", 30.0),
                max_input_bytes=value.get("max_input_bytes", 1 << 20),
                max_output_bytes=value.get("max_output_bytes", 1 << 20),
                ssh_executable=value.get("ssh_executable", "/usr/bin/ssh"),
            )
        except (TypeError, ValueError) as exc:
            raise TransportError("trusted SSH configuration is invalid") from exc


@dataclass(frozen=True)
class StaticSSHConfigProvider:
    """Explicit fixture/provider seam for a fixed connection."""

    config: SSHConnectionConfig

    def connection(self) -> SSHConnectionConfig:
        return self.config


@dataclass(frozen=True)
class SSHResult:
    """The bounded subset of a completed system process we consume."""

    returncode: int
    stdout: bytes
    stderr: bytes = b""


class SSHRunner(Protocol):
    """Test seam matching ``(argv, stdin, timeout)``."""

    def __call__(self, argv: Sequence[str], input_data: bytes, timeout: float) -> Any:
        ...


_SAFE_HOST = re.compile(r"^(?!-)[A-Za-z0-9][A-Za-z0-9.:-]{0,253}$")
_SAFE_USER = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_REMOTE_GATEWAY = ("ops-call",)
_SSH_CLIENT_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
_IDENTITY_OVERRIDE_KEYS = frozenset(
    {
        "argv",
        "command",
        "cwd",
        "env",
        "environment",
        "host",
        "hostname",
        "identity",
        "identity_file",
        "key",
        "key_path",
        "known_hosts",
        "known_hosts_file",
        "localcommand",
        "option",
        "options",
        "port",
        "proxycommand",
        "remote_command",
        "ssh_option",
        "ssh_options",
        "user",
        "username",
    }
)


def _trusted_path(value: Path, *, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or "\x00" in str(path):
        raise TransportError(f"trusted SSH {label} path is invalid")
    return path


def _reject_request_overrides(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if isinstance(key, str) and key.lower() in _IDENTITY_OVERRIDE_KEYS:
                raise TransportError("request contains an SSH configuration override")
            _reject_request_overrides(child)
    elif isinstance(value, list):
        for child in value:
            _reject_request_overrides(child)


def _result_from_process(value: Any) -> SSHResult:
    if isinstance(value, SSHResult):
        result = value
    elif isinstance(value, tuple) and len(value) in {2, 3}:
        result = SSHResult(
            returncode=int(value[0]),
            stdout=value[1],
            stderr=value[2] if len(value) == 3 else b"",
        )
    else:
        try:
            result = SSHResult(
                returncode=int(value.returncode),
                stdout=value.stdout,
                stderr=getattr(value, "stderr", b"") or b"",
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise TransportError("SSH process result is invalid") from exc
    if isinstance(result.stdout, str):
        result = SSHResult(result.returncode, result.stdout.encode("utf-8"), result.stderr)
    if isinstance(result.stderr, str):
        result = SSHResult(result.returncode, result.stdout, result.stderr.encode("utf-8"))
    if not isinstance(result.stdout, bytes) or not isinstance(result.stderr, bytes):
        raise TransportError("SSH process result is invalid")
    return result


def _run_system_ssh(argv: Sequence[str], input_data: bytes, timeout: float, *, max_output_bytes: int) -> SSHResult:
    """Run fixed argv while terminating a process that exceeds stdout bounds."""

    try:
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=dict(_SSH_CLIENT_ENV),
            shell=False,
        )
    except (OSError, ValueError) as exc:
        raise TransportError("SSH transport could not start") from exc

    chunks: list[bytes] = []
    output_size = 0
    output_too_large = threading.Event()
    writer_done = threading.Event()
    reader_done = threading.Event()

    def write_stdin() -> None:
        try:
            assert process.stdin is not None
            process.stdin.write(input_data)
            process.stdin.close()
        except (BrokenPipeError, OSError, ValueError):
            try:
                if process.stdin is not None:
                    process.stdin.close()
            except (OSError, ValueError):
                pass
        finally:
            writer_done.set()

    def read_stdout() -> None:
        nonlocal output_size
        try:
            assert process.stdout is not None
            while True:
                chunk = process.stdout.read(65536)
                if not chunk:
                    return
                output_size += len(chunk)
                if output_size > max_output_bytes:
                    output_too_large.set()
                    try:
                        process.kill()
                    except OSError:
                        pass
                    return
                chunks.append(chunk)
        except (OSError, ValueError):
            return
        finally:
            reader_done.set()

    writer = threading.Thread(target=write_stdin, name="ops-control-ssh-stdin", daemon=True)
    reader = threading.Thread(target=read_stdout, name="ops-control-ssh-stdout", daemon=True)
    writer.start()
    reader.start()
    deadline = time.monotonic() + timeout
    timed_out = False
    while process.poll() is None:
        if output_too_large.is_set():
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            try:
                process.kill()
            except OSError:
                pass
            break
        try:
            process.wait(timeout=min(remaining, 0.1))
        except subprocess.TimeoutExpired:
            continue
    if timed_out or output_too_large.is_set():
        try:
            process.kill()
        except OSError:
            pass
    wait_timeout = 1.0 if output_too_large.is_set() else max(0.1, deadline - time.monotonic())
    try:
        process.wait(timeout=wait_timeout)
    except subprocess.TimeoutExpired as exc:
        try:
            process.kill()
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            pass
        raise TransportError("SSH transport timed out") from exc
    writer.join(timeout=1)
    reader.join(timeout=1)
    if timed_out:
        raise TransportError("SSH transport timed out")
    if output_too_large.is_set():
        raise TransportError("SSH response exceeds the transport output limit")
    if not writer_done.is_set() or not reader_done.is_set():
        raise TransportError("SSH transport did not close cleanly")
    return SSHResult(process.returncode or 0, b"".join(chunks))


class SystemSSHTransport:
    """System ``ssh`` transport with a fixed target and forced gateway."""

    def __init__(self, config: SSHConnectionConfig | SSHConfigProvider, *, runner: SSHRunner | None = None) -> None:
        if hasattr(config, "connection"):
            config = config.connection()  # type: ignore[assignment]
        if not isinstance(config, SSHConnectionConfig):
            raise TransportError("trusted SSH configuration is invalid")
        self.config = config
        self._runner = runner

    @classmethod
    def from_provider(cls, provider: SSHConfigProvider, *, runner: SSHRunner | None = None) -> "SystemSSHTransport":
        return cls(provider, runner=runner)

    def command(self) -> tuple[str, ...]:
        """Return the complete argv, useful for review and unit tests."""

        config = self.config
        connect_seconds = max(1, math.ceil(config.connect_timeout))
        args: list[str] = [
            config.ssh_executable,
            "-F",
            "/dev/null",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "RequestTTY=no",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            f"ConnectTimeout={connect_seconds}",
            "-p",
            str(config.port),
            "-o",
            f"UserKnownHostsFile={config.known_hosts_file}",
        ]
        if config.identity_file is not None:
            args.extend(("-i", str(config.identity_file), "-o", "IdentitiesOnly=yes"))
        args.extend((f"{config.user}@{config.hostname}", *_REMOTE_GATEWAY))
        return tuple(args)

    # Common aliases make the fixed command easy to inspect without exposing a
    # second, differently behaving implementation.
    argv = command
    build_command = command

    def send(self, request: Mapping[str, Any]) -> dict[str, Any]:
        try:
            request_value = dict(request)
        except (TypeError, ValueError) as exc:
            raise TransportError("request is invalid") from exc
        try:
            validate_model("Request", request_value)
            _reject_request_overrides(request_value.get("params", {}))
            payload = canonical_json_bytes(request_value)
        except (ModelDependencyError, ModelError, TypeError, ValueError) as exc:
            raise TransportError("request is invalid") from exc
        if len(payload) > self.config.max_input_bytes:
            raise TransportError("request exceeds the transport input limit")

        try:
            if self._runner is None:
                result = _run_system_ssh(
                    self.command(),
                    payload,
                    self.config.total_timeout,
                    max_output_bytes=self.config.max_output_bytes,
                )
            else:
                result = _result_from_process(self._runner(self.command(), payload, self.config.total_timeout))
        except TransportError:
            raise
        except subprocess.TimeoutExpired as exc:
            raise TransportError("SSH transport timed out") from exc
        except Exception as exc:
            raise TransportError("SSH transport failed") from exc
        if result.returncode != 0:
            # stderr is intentionally not copied into an exception or a
            # Response. This keeps host-key and secret diagnostics out of the
            # application protocol.
            raise TransportError("SSH transport returned a non-zero status")
        if len(result.stdout) > self.config.max_output_bytes:
            raise TransportError("SSH response exceeds the transport output limit")
        try:
            text = result.stdout.decode("utf-8")
            parsed = strict_json_loads(text)
        except (UnicodeDecodeError, ModelError) as exc:
            raise TransportError("SSH response is not one valid JSON object") from exc
        if not isinstance(parsed, dict):
            raise TransportError("SSH response is not a JSON object")
        try:
            validate_model("Response", parsed)
        except ModelError as exc:
            raise TransportError("SSH response failed schema validation") from exc
        return parsed


class Transport:
    """OPS-002 byte injection seam, retained for explicit unit fixtures."""

    def __init__(
        self,
        *,
        sender: Callable[[bytes], bytes | Mapping[str, Any]] | None = None,
        config: SSHConnectionConfig | SSHConfigProvider | None = None,
        provider: SSHConfigProvider | None = None,
        runner: SSHRunner | None = None,
    ) -> None:
        if sender is not None and (config is not None or provider is not None):
            raise TransportError("transport cannot mix injected and system modes")
        if config is not None and provider is not None:
            raise TransportError("transport has duplicate system configuration")
        self._sender = sender
        system_config = provider if provider is not None else config
        self._system = SystemSSHTransport(system_config, runner=runner) if system_config is not None else None

    @classmethod
    def from_provider(cls, provider: SSHConfigProvider, *, runner: SSHRunner | None = None) -> "Transport":
        return cls(provider=provider, runner=runner)

    def command(self) -> tuple[str, ...]:
        if self._system is None:
            raise TransportError("system transport configuration is unavailable")
        return self._system.command()

    def send(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if self._system is not None:
            return self._system.send(request)
        validate_model("Request", dict(request))
        if self._sender is None:
            raise TransportError("production transport is not implemented in OPS-002")
        try:
            raw_response = self._sender(canonical_json_bytes(dict(request)))
        except Exception as exc:
            # Do not leak a subprocess/network exception into a response or log.
            raise TransportError("injected transport failed") from exc
        if isinstance(raw_response, Mapping):
            response = dict(raw_response)
        elif isinstance(raw_response, bytes):
            try:
                parsed = strict_json_loads(raw_response.decode("utf-8"))
            except Exception as exc:
                raise TransportError("transport returned invalid JSON") from exc
            if not isinstance(parsed, dict):
                raise TransportError("transport returned a non-object response")
            response = parsed
        else:
            raise TransportError("transport returned an unsupported response")
        validate_model("Response", response)
        return response


SSHTransport = SystemSSHTransport
SystemTransport = SystemSSHTransport
SSHTransportConfig = SSHConnectionConfig


__all__ = [
    "SSHConnectionConfig",
    "SSHConfigProvider",
    "SSHResult",
    "SSHRunner",
    "SSHTransport",
    "SSHTransportConfig",
    "StaticSSHConfigProvider",
    "SystemSSHTransport",
    "SystemTransport",
    "Transport",
    "TransportError",
]
