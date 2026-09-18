"""Loopback-only HTTP adapter for the independent ``ops-approve`` service."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..models import is_uuid
from ..plans import PlanError, default_plan_store
from ..storage import AtomicJsonStore, StorageError
from .service import ApprovalError, ApprovalService, WebAuthnConfig
from .store import ApprovalStore, CredentialStoreError, FileCredentialStore


class ApprovalHTTPError(RuntimeError):
    code = "precondition_failed"


def _loopback(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def _safe_path(path: str) -> list[str]:
    parts = path.split("/")
    if len(parts) < 3 or parts[0] != "" or parts[1] != "approval" or any(not part for part in parts[2:]):
        raise ApprovalHTTPError("approval path is invalid")
    if any(part in {".", ".."} or not is_uuid(part) for part in parts[2:3]):
        raise ApprovalHTTPError("approval path is invalid")
    return parts


def _safe_error(handler: BaseHTTPRequestHandler, status: int, code: str) -> None:
    value = {"ok": False, "error": code}
    payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


class ApprovalRequestHandler(BaseHTTPRequestHandler):
    server_version = "ops-approve/1.0"

    @property
    def approval_server(self) -> "ApprovalHTTPServer":
        return self.server  # type: ignore[return-value]

    def log_message(self, format: str, *args: Any) -> None:
        # Do not log request bodies, credential IDs, plans, or exception text.
        self.approval_server.event_log.append(f"{self.command} {self.path} {args[1]}")

    def _check_boundary(self, *, require_origin: bool) -> None:
        if not _loopback(self.client_address[0]):
            raise ApprovalHTTPError("approval service is loopback-only")
        expected_host = f"localhost:{self.approval_server.server_port}"
        if self.headers.get("Host") != expected_host:
            raise ApprovalHTTPError("approval Host is invalid")
        if require_origin and self.headers.get("Origin") != self.approval_server.config.origin:
            raise ApprovalHTTPError("approval Origin is invalid")
        origin = self.headers.get("Origin")
        if origin is not None and origin != self.approval_server.config.origin:
            raise ApprovalHTTPError("approval Origin is invalid")

    def _read_body(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ApprovalHTTPError("request body is missing")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ApprovalHTTPError("request body is invalid") from exc
        if length < 0 or length > self.approval_server.max_body_bytes:
            raise ApprovalHTTPError("request body exceeds the limit")
        try:
            value = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ApprovalHTTPError("request body is invalid") from exc
        if not isinstance(value, dict):
            raise ApprovalHTTPError("request body is invalid")
        return value

    def _json(self, status: int, value: Any) -> None:
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        try:
            self._check_boundary(require_origin=False)
            parsed = urlsplit(self.path)
            if parsed.query:
                raise ApprovalHTTPError("approval URL query is invalid")
            parts = _safe_path(parsed.path)
            if len(parts) != 3:
                raise ApprovalHTTPError("approval path is invalid")
            body = self.approval_server.service.render_html(parts[2]).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; connect-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except ApprovalError as exc:
            _safe_error(self, 410 if exc.code in {"approval_expired", "plan_stale"} else 400, exc.code)
        except ApprovalHTTPError:
            _safe_error(self, 403, "approval_boundary_denied")
        except Exception:
            _safe_error(self, 500, "approval_unavailable")

    def do_POST(self) -> None:  # noqa: N802
        try:
            parsed = urlsplit(self.path)
            if parsed.query:
                raise ApprovalHTTPError("approval URL query is invalid")
            path = parsed.path
            if path == "/sessions":
                self._check_boundary(require_origin=True)
                body = self._read_body()
                session = self.approval_server.service.open_session(str(body.get("plan_id", "")))
                self._json(
                    200,
                    {
                        "ok": True,
                        "session_id": session.session_id,
                        "url": session.url(self.approval_server.config),
                        "expires_at": session.expires_at,
                    },
                )
                return
            parts = _safe_path(path)
            if len(parts) != 4:
                raise ApprovalHTTPError("approval path is invalid")
            self._check_boundary(require_origin=True)
            body = self._read_body()
            if parts[3] == "options":
                data = self.approval_server.service.authentication_options(parts[2])
                self._json(200, {"ok": True, **data})
                return
            if parts[3] == "verify":
                data = self.approval_server.service.verify_assertion(
                    parts[2],
                    challenge_token=str(body.get("challenge_token", "")),
                    credential=body.get("credential", {}),
                )
                self._json(200, {"ok": True, **data})
                return
            raise ApprovalHTTPError("approval path is invalid")
        except ApprovalError as exc:
            status = 410 if exc.code in {"approval_expired", "plan_stale"} else 400
            _safe_error(self, status, exc.code)
        except ApprovalHTTPError:
            _safe_error(self, 403, "approval_boundary_denied")
        except Exception:
            _safe_error(self, 500, "approval_unavailable")


class ApprovalHTTPServer(ThreadingHTTPServer):
    """An explicitly loopback-bound approval endpoint."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, service: ApprovalService, *, host: str = "127.0.0.1", port: int | None = None) -> None:
        if host not in {"127.0.0.1", "::1"}:
            raise ApprovalHTTPError("approval service must bind to loopback")
        chosen_port = service.config.port if port is None else port
        if chosen_port != service.config.port:
            raise ApprovalHTTPError("approval port differs from the WebAuthn origin")
        self.service = service
        self.config = service.config
        self.max_body_bytes = 1 << 20
        self.event_log: list[str] = []
        super().__init__((host, chosen_port), ApprovalRequestHandler)


def build_system_service(*, store_root: Path, credential_root: Path, config: WebAuthnConfig | None = None) -> ApprovalService:
    """Construct the service from maintenance-selected, non-request paths."""

    plan_store = default_plan_store(store_root, enforce_private=False, create=False)
    credentials = FileCredentialStore(
        credential_root,
        environment="trusted",
        metadata_root=Path(credential_root) / "metadata",
        counter_root=Path(credential_root) / "counters",
        create=False,
    )
    state_store = AtomicJsonStore(Path(store_root))
    return ApprovalService(
        plan_store=plan_store,
        approval_store=ApprovalStore(state_store),
        credential_store=credentials,
        config=config,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ops-approve")
    parser.add_argument("--store-root", default="/var/lib/ops-control")
    parser.add_argument("--credential-root", default="/etc/ops-control/webauthn/trusted")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    try:
        config = WebAuthnConfig(port=args.port, origin=f"http://localhost:{args.port}")
        service = build_system_service(store_root=Path(args.store_root), credential_root=Path(args.credential_root), config=config)
        server = ApprovalHTTPServer(service, host="127.0.0.1", port=args.port)
    except (ApprovalError, ApprovalHTTPError, CredentialStoreError, PlanError, StorageError, OSError):
        sys.stderr.write("ops-approve: trusted approval service unavailable\n")
        return 1
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


__all__ = ["ApprovalHTTPError", "ApprovalHTTPServer", "ApprovalRequestHandler", "build_system_service", "main"]
