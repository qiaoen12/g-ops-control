"""Minimal client for the independent loopback ``ops-approve`` endpoint."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
import webbrowser
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

from ops.models import is_uuid, is_valid_utc


class ApprovalClientError(RuntimeError):
    code = "approval_unavailable"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        if code is not None:
            self.code = code
        super().__init__(message)


def validate_loopback_url(value: str, *, port: int = 8765) -> str:
    if not isinstance(value, str):
        raise ApprovalClientError("approval URL is invalid", code="invalid_request")
    parsed = urlsplit(value)
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise ApprovalClientError("approval URL is invalid", code="invalid_request") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != "localhost"
        or parsed_port != port
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or len(parsed.path.split("/")) != 3
        or not is_uuid(parsed.path.split("/")[-1])
    ):
        raise ApprovalClientError("approval URL is not loopback-only", code="precondition_failed")
    return value


@dataclass(frozen=True)
class ApprovalSessionLink:
    session_id: str
    url: str
    expires_at: str


class LoopbackApprovalClient:
    """Open sessions and optionally launch only a fixed localhost page.

    This client never accepts or sends an Approval record.  The server creates
    one only after a bound WebAuthn assertion has passed.
    """

    def __init__(self, base_url: str = "http://localhost:8765", *, timeout: float = 5.0) -> None:
        parsed = urlsplit(base_url)
        try:
            parsed_port = parsed.port
        except ValueError as exc:
            raise ApprovalClientError("approval endpoint is not loopback-only", code="precondition_failed") from exc
        if parsed.scheme != "http" or parsed.hostname != "localhost" or parsed_port not in {None, 8765} or parsed.path not in {"", "/"}:
            raise ApprovalClientError("approval endpoint is not loopback-only", code="precondition_failed")
        self.base_url = "http://localhost:8765"
        self.timeout = timeout

    def open(self, plan_id: str) -> ApprovalSessionLink:
        payload = json.dumps({"plan_id": plan_id}, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/sessions",
            data=payload,
            headers={"Content-Type": "application/json", "Origin": self.base_url},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                value = json.loads(response.read(1 << 20).decode("utf-8"))
        except (OSError, urllib.error.URLError, ValueError, UnicodeError) as exc:
            raise ApprovalClientError("approval service is unavailable") from exc
        if not isinstance(value, dict) or value.get("ok") is not True:
            code = value.get("error") if isinstance(value, dict) and isinstance(value.get("error"), str) else "approval_unavailable"
            raise ApprovalClientError("approval session could not be created", code=code)
        try:
            session_id = str(value["session_id"])
            url = validate_loopback_url(str(value["url"]))
            expires_at = str(value["expires_at"])
            if not is_uuid(session_id) or not is_valid_utc(expires_at):
                raise ValueError("approval session response is invalid")
        except (KeyError, ApprovalClientError, TypeError) as exc:
            raise ApprovalClientError("approval session response is invalid") from exc
        return ApprovalSessionLink(session_id=session_id, url=url, expires_at=expires_at)

    def open_browser(self, link: ApprovalSessionLink, *, opener: Callable[[str], Any] = webbrowser.open) -> bool:
        url = validate_loopback_url(link.url)
        try:
            return bool(opener(url))
        except Exception as exc:
            raise ApprovalClientError("approval page could not be opened") from exc


__all__ = ["ApprovalClientError", "ApprovalSessionLink", "LoopbackApprovalClient", "validate_loopback_url"]
