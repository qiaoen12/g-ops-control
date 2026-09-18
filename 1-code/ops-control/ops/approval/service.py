"""Loopback-only approval sessions and WebAuthn verification for OPS-005."""

from __future__ import annotations

import base64
import binascii
import html
import json
import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from ..models import ModelError, is_uuid, utc_now, validate_model
from ..storage import RecordNotFound, StorageError
from .store import ApprovalStore, CredentialProvider, CredentialStoreError


class ApprovalError(RuntimeError):
    code = "approval_required"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        if code is not None:
            self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class WebAuthnConfig:
    """Candidate R1 settings; Windows evidence is required before final freeze."""

    origin: str = "http://localhost:8765"
    rp_id: str = "localhost"
    rp_name: str = "Ops G-lite approval"
    port: int = 8765
    idle_timeout_seconds: int = 600
    max_session_seconds: int = 1800
    challenge_timeout_seconds: int = 120
    approval_start_window_seconds: int = 600

    def __post_init__(self) -> None:
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise ApprovalError("approval port is invalid", code="invalid_request")
        if self.origin != f"http://localhost:{self.port}" or self.rp_id != "localhost":
            raise ApprovalError("WebAuthn origin and RP configuration are not frozen safely", code="source_unavailable")
        for field in (
            "idle_timeout_seconds",
            "max_session_seconds",
            "challenge_timeout_seconds",
            "approval_start_window_seconds",
        ):
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ApprovalError("approval timeout configuration is invalid", code="invalid_request")
        if self.idle_timeout_seconds > self.max_session_seconds:
            raise ApprovalError("approval idle timeout exceeds session lifetime", code="invalid_request")


@dataclass
class ApprovalSession:
    session_id: str
    plan_id: str
    plan_digest: str
    owner_id: str
    created_at: str
    expires_at: str
    created_epoch: float
    deadline_epoch: float
    last_activity_epoch: float
    closed: bool = False

    def url(self, config: WebAuthnConfig) -> str:
        return f"{config.origin}/approval/{self.session_id}"


@dataclass
class _Challenge:
    token: str
    session_id: str
    plan_id: str
    plan_digest: str
    owner_id: str
    value: bytes
    created_epoch: float
    expires_epoch: float
    used: bool = False


_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_-]{16,256}$")


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ApprovalError("stored time is invalid", code="storage_failed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApprovalError("stored time is invalid", code="storage_failed") from exc
    if parsed.tzinfo is None:
        raise ApprovalError("stored time is not UTC", code="storage_failed")
    return parsed.astimezone(timezone.utc)


def _b64u_decode(value: Any) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,512}", value):
        raise ApprovalError("credential response is invalid", code="authentication_failed")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise ApprovalError("credential response is invalid", code="authentication_failed") from exc
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise ApprovalError("credential response is invalid", code="authentication_failed")
    return raw


def _safe_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)


class ApprovalService:
    """The only component allowed to turn a real WebAuthn assertion into Approval."""

    def __init__(
        self,
        *,
        plan_store: Any,
        approval_store: ApprovalStore,
        credential_store: CredentialProvider,
        config: WebAuthnConfig | None = None,
        now: Callable[[], str] = utc_now,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.plan_store = plan_store
        self.approval_store = approval_store
        self.credential_store = credential_store
        self.config = config or WebAuthnConfig()
        self.now = now
        self.clock = clock
        if getattr(credential_store, "environment", "trusted") != "trusted":
            raise ApprovalError("approval service requires the trusted credential store", code="source_unavailable")
        self._sessions: dict[str, ApprovalSession] = {}
        self._challenges: dict[str, _Challenge] = {}
        self._lock = threading.RLock()

    def _read_plan(self, plan_id: str) -> dict[str, Any]:
        if not is_uuid(plan_id):
            raise ApprovalError("plan ID is invalid", code="invalid_request")
        try:
            relative = self.plan_store.record_path("plans", plan_id)
            plan = self.plan_store.read_record(relative, "Plan")
        except (RecordNotFound, StorageError, ModelError) as exc:
            raise ApprovalError("immutable plan is unavailable", code="source_unavailable") from exc
        try:
            validate_model("Plan", plan)
        except Exception as exc:
            raise ApprovalError("immutable plan is invalid", code="storage_failed") from exc
        if plan.get("plan_id") != plan_id:
            raise ApprovalError("immutable plan path binding is invalid", code="storage_failed")
        return dict(plan)

    def _current_time(self) -> tuple[str, datetime, float]:
        value = self.now()
        parsed = _parse_time(value)
        return value, parsed, self.clock()

    def open_session(self, plan_id: str) -> ApprovalSession:
        """Create a temporary session; no Approval is written here."""

        plan = self._read_plan(plan_id)
        now_text, now_dt, now_epoch = self._current_time()
        plan_expires = _parse_time(plan["expires_at"])
        if plan_expires <= now_dt:
            raise ApprovalError("plan has expired", code="plan_stale")
        session_deadline = min(plan_expires, now_dt + timedelta(seconds=self.config.max_session_seconds))
        session_id = uuid.uuid4()
        session = ApprovalSession(
            session_id=str(session_id),
            plan_id=plan["plan_id"],
            plan_digest=plan["plan_digest"],
            owner_id=plan["owner_id"],
            created_at=now_text,
            expires_at=session_deadline.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            created_epoch=now_epoch,
            deadline_epoch=session_deadline.timestamp(),
            last_activity_epoch=now_epoch,
        )
        with self._lock:
            self._sessions[session.session_id] = session
        return session

    def _get_session(self, session_id: str, *, touch: bool = True) -> ApprovalSession:
        if not isinstance(session_id, str) or not is_uuid(session_id):
            raise ApprovalError("approval session is invalid", code="invalid_request")
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise ApprovalError("approval session is unavailable", code="approval_required")
            now_epoch = self.clock()
            if session.closed or now_epoch >= session.deadline_epoch or now_epoch - session.last_activity_epoch > self.config.idle_timeout_seconds:
                session.closed = True
                raise ApprovalError("approval session has expired", code="approval_expired")
            if touch:
                session.last_activity_epoch = now_epoch
            return session

    def _session_plan(self, session_id: str) -> tuple[ApprovalSession, dict[str, Any]]:
        session = self._get_session(session_id)
        plan = self._read_plan(session.plan_id)
        if plan["plan_id"] != session.plan_id or plan["plan_digest"] != session.plan_digest or plan["owner_id"] != session.owner_id:
            session.closed = True
            raise ApprovalError("immutable plan no longer matches the session", code="plan_stale")
        return session, plan

    def plan_for_session(self, session_id: str) -> dict[str, Any]:
        """Re-read the immutable Plan used by the confirmation page."""

        return self._session_plan(session_id)[1]

    def authentication_options(self, session_id: str) -> dict[str, Any]:
        session, plan = self._session_plan(session_id)
        try:
            credentials = self.credential_store.find_for_owner(plan["owner_id"])
        except CredentialStoreError as exc:
            raise ApprovalError("trusted approval credential is unavailable", code="approval_required") from exc
        if not credentials:
            raise ApprovalError("trusted approval credential is unavailable", code="approval_required")
        challenge = secrets.token_bytes(32)
        token = secrets.token_urlsafe(24)
        now_epoch = self.clock()
        with self._lock:
            self._challenges[token] = _Challenge(
                token=token,
                session_id=session.session_id,
                plan_id=plan["plan_id"],
                plan_digest=plan["plan_digest"],
                owner_id=plan["owner_id"],
                value=challenge,
                created_epoch=now_epoch,
                expires_epoch=min(session.deadline_epoch, now_epoch + self.config.challenge_timeout_seconds),
            )
        try:
            from webauthn import generate_authentication_options, options_to_json
            from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement

            options = generate_authentication_options(
                rp_id=self.config.rp_id,
                challenge=challenge,
                timeout=self.config.challenge_timeout_seconds * 1000,
                allow_credentials=[PublicKeyCredentialDescriptor(id=credential.credential_id) for credential in credentials],
                user_verification=UserVerificationRequirement.REQUIRED,
            )
            encoded_options = json.loads(options_to_json(options))
        except ImportError as exc:
            raise ApprovalError("WebAuthn dependency is unavailable", code="dependency_missing") from exc
        except Exception as exc:
            raise ApprovalError("WebAuthn options could not be created", code="approval_required") from exc
        return {"challenge_token": token, "options": encoded_options}

    def _consume_challenge(self, session_id: str, token: str) -> _Challenge:
        if not isinstance(token, str) or not _SAFE_TOKEN.fullmatch(token):
            raise ApprovalError("challenge is invalid", code="authentication_failed")
        with self._lock:
            challenge = self._challenges.get(token)
            if challenge is None or challenge.session_id != session_id:
                raise ApprovalError("challenge is invalid", code="authentication_failed")
            if challenge.used:
                raise ApprovalError("challenge was already used", code="authentication_failed")
            if self.clock() >= challenge.expires_epoch:
                challenge.used = True
                raise ApprovalError("challenge has expired", code="approval_expired")
            challenge.used = True
            return challenge

    def verify_assertion(self, session_id: str, *, challenge_token: str, credential: Mapping[str, Any]) -> dict[str, Any]:
        """Verify a browser assertion and publish exactly one Approval v1 record."""

        session, plan = self._session_plan(session_id)
        challenge = self._consume_challenge(session.session_id, challenge_token)
        if (
            challenge.plan_id != plan["plan_id"]
            or challenge.plan_digest != plan["plan_digest"]
            or challenge.owner_id != plan["owner_id"]
            or not isinstance(credential, Mapping)
        ):
            raise ApprovalError("challenge binding is invalid", code="authentication_failed")
        raw_id = credential.get("rawId")
        raw_id_bytes = _b64u_decode(raw_id)
        raw_id_canonical = base64.urlsafe_b64encode(raw_id_bytes).rstrip(b"=").decode("ascii")
        credential_id = credential.get("id")
        if credential_id is not None and (not isinstance(credential_id, str) or credential_id != raw_id_canonical):
            raise ApprovalError("credential binding is invalid", code="authentication_failed")
        # Serialize verification and sign-counter advancement for one trusted
        # credential. A second concurrent assertion therefore observes the
        # counter written by the first one instead of replaying old state.
        with self._lock:
            try:
                record = self.credential_store.find_by_raw_id(raw_id_canonical)
            except CredentialStoreError as exc:
                raise ApprovalError("credential is not trusted for this owner", code="authentication_failed") from exc
            if record.status != "active" or record.environment != "trusted" or record.owner_id != plan["owner_id"]:
                raise ApprovalError("credential is not trusted for this owner", code="authentication_failed")
            try:
                from webauthn import verify_authentication_response

                verified = verify_authentication_response(
                    credential=dict(credential),
                    expected_challenge=challenge.value,
                    expected_rp_id=self.config.rp_id,
                    expected_origin=self.config.origin,
                    credential_public_key=record.public_key,
                    credential_current_sign_count=record.sign_count,
                    require_user_verification=True,
                )
            except ImportError as exc:
                raise ApprovalError("WebAuthn dependency is unavailable", code="dependency_missing") from exc
            except Exception as exc:
                raise ApprovalError("WebAuthn assertion was rejected", code="authentication_failed") from exc
            if verified.credential_id != raw_id_bytes or not verified.user_verified:
                raise ApprovalError("WebAuthn assertion was rejected", code="authentication_failed")
            try:
                self.credential_store.update_sign_count(record, verified.new_sign_count)
            except CredentialStoreError as exc:
                raise ApprovalError("credential state could not be updated", code="storage_failed") from exc

        # Re-read Plan after authentication so the Approval is bound to the
        # exact immutable content that was shown and authenticated.
        _session_again, current_plan = self._session_plan(session_id)
        approved_at, approved_dt, _ = self._current_time()
        if _parse_time(current_plan["expires_at"]) <= approved_dt:
            raise ApprovalError("plan has expired", code="plan_stale")
        start_before_dt = min(
            _parse_time(current_plan["expires_at"]),
            approved_dt + timedelta(seconds=self.config.approval_start_window_seconds),
        )
        start_before = start_before_dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        approval = {
            "schema_version": 1,
            "approval_id": str(uuid.uuid4()),
            "owner_id": current_plan["owner_id"],
            "plan_id": current_plan["plan_id"],
            "plan_digest": current_plan["plan_digest"],
            "approver_credential_id": record.credential_ref,
            "approved_at": approved_at,
            "start_before": start_before,
            "max_runtime_seconds": current_plan["max_runtime_seconds"],
        }
        try:
            validate_model("Approval", approval)
            published = self.approval_store.publish(approval)
        except (ModelError, RuntimeError) as exc:
            if isinstance(exc, ApprovalError):
                raise
            raise ApprovalError("trusted Approval could not be published", code="storage_failed") from exc
        with self._lock:
            session.closed = True
        return {
            "approval_id": published["approval_id"],
            "plan_id": published["plan_id"],
            "plan_digest": published["plan_digest"],
            "approved_at": published["approved_at"],
            "start_before": published["start_before"],
            "user_verified": True,
        }

    def render_html(self, session_id: str) -> str:
        _session, plan = self._session_plan(session_id)
        approval_start_before = min(
            _parse_time(plan["expires_at"]),
            datetime.fromtimestamp(self.clock(), timezone.utc)
            + timedelta(seconds=self.config.approval_start_window_seconds),
        )
        approval_start_before_text = approval_start_before.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        rows = []
        for label, field in (
            ("action", "action_id"),
            ("action_version", "action_version"),
            ("bundle", "bundle_id"),
            ("resolved targets", "resolved_targets"),
            ("excluded targets + reason", "excluded"),
            ("resolved params", "resolved_params"),
            ("impact", "impact"),
            ("recovery evidence", "recovery_evidence_refs"),
            ("verification", "verification"),
            ("elevated", "elevated"),
            ("created_at", "created_at"),
            ("expires_at", "expires_at"),
            ("approval start window", "expires_at"),
            ("max runtime", "max_runtime_seconds"),
            ("plan digest", "plan_digest"),
        ):
            value = plan[field]
            if field == "expires_at" and label == "approval start window":
                value = f"approval must start before {approval_start_before_text}"
            rendered = _safe_json(value) if isinstance(value, (dict, list)) else str(value)
            rows.append(f"<dt>{html.escape(label)}</dt><dd><pre>{html.escape(rendered)}</pre></dd>")
        return f"""<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OPS-005 approval</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; connect-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<style>
body {{ font: 16px -apple-system, BlinkMacSystemFont, sans-serif; max-width: 900px; margin: 32px auto; padding: 0 20px; color: #202124; }}
dt {{ font-weight: 600; margin-top: 16px; }} dd {{ margin: 4px 0 0; }} pre {{ background: #f4f5f6; border: 1px solid #d9dce1; border-radius: 6px; padding: 10px; white-space: pre-wrap; overflow-wrap: anywhere; }}
button {{ font: inherit; padding: 10px 16px; margin: 20px 8px 8px 0; }} #status {{ white-space: pre-wrap; }}
</style>
<h1>Confirm OPS-005 Plan</h1>
<p>Review the server-rendered immutable Plan. WebAuthn runs only after explicit confirmation.</p>
<dl>{''.join(rows)}</dl>
<button id="confirm">Confirm with passkey</button>
<button id="close" type="button">Close</button>
<div id="status">Not approved.</div>
<script>
const confirmButton = document.getElementById('confirm');
const closeButton = document.getElementById('close');
const status = document.getElementById('status');
const root = window.location.pathname;
const fromB64u = value => {{ const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4); const raw = atob(padded); return Uint8Array.from(raw, c => c.charCodeAt(0)); }};
const toB64u = value => {{ const bytes = new Uint8Array(value); let raw = ''; for (const byte of bytes) raw += String.fromCharCode(byte); return btoa(raw).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, ''); }};
const post = async (path, body) => {{ const response = await fetch(path, {{ method: 'POST', headers: {{'Content-Type': 'application/json'}}, body: JSON.stringify(body) }}); const value = await response.json(); if (!response.ok || value.ok === false) throw new Error(value.error || 'approval request failed'); return value; }};
confirmButton.onclick = async () => {{ confirmButton.disabled = true; closeButton.disabled = true; status.textContent = 'Requesting a one-time WebAuthn challenge…'; try {{ const start = await post(root + '/options', {{}}); const options = start.options; options.challenge = fromB64u(options.challenge); if (options.allowCredentials) options.allowCredentials = options.allowCredentials.map(item => ({{...item, id: fromB64u(item.id)}})); status.textContent = 'Complete the real user-verification prompt…'; const credential = await navigator.credentials.get({{publicKey: options}}); const result = await post(root + '/verify', {{ challenge_token: start.challenge_token, credential: {{ id: credential.id, rawId: toB64u(credential.rawId), type: credential.type, response: {{ clientDataJSON: toB64u(credential.response.clientDataJSON), authenticatorData: toB64u(credential.response.authenticatorData), signature: toB64u(credential.response.signature), userHandle: credential.response.userHandle ? toB64u(credential.response.userHandle) : null }} }} }}); status.textContent = `APPROVED\\napproval_id=${{result.approval_id}}\\nuser_verified=${{result.user_verified}}`; }} catch (error) {{ status.textContent = 'Approval was not created.'; confirmButton.disabled = false; closeButton.disabled = false; }} }};
closeButton.onclick = () => {{ window.close(); status.textContent = 'Closed; no Approval was written.'; }};
</script>
"""


__all__ = ["ApprovalError", "ApprovalService", "ApprovalSession", "WebAuthnConfig"]
