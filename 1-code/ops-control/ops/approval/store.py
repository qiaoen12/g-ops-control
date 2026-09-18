"""Trusted Approval and maintenance-owned WebAuthn credential stores.

Approval records use the existing Approval v1 schema and the existing atomic
JSON storage primitive.  Credential records are deliberately a separate
internal format and root: they contain only public credential material and
are never accepted from an ordinary Request or gateway caller.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import stat
import threading
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping, Protocol

from ..models import ModelError, is_uuid, is_valid_utc, validate_model
from ..storage import AtomicJsonStore, RecordExists, RecordNotFound, StorageError


class ApprovalStoreError(RuntimeError):
    code = "storage_failed"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        if code is not None:
            self.code = code
        super().__init__(message)


class ApprovalConflict(ApprovalStoreError):
    code = "approval_conflict"


class CredentialStoreError(RuntimeError):
    code = "precondition_failed"


_SAFE_CREDENTIAL_REF = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$")
_SAFE_RAW_ID = re.compile(r"^[A-Za-z0-9_-]{1,512}$")


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64u(value: Any, *, label: str) -> bytes:
    if not isinstance(value, str) or not _SAFE_RAW_ID.fullmatch(value):
        raise CredentialStoreError(f"{label} is invalid")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise CredentialStoreError(f"{label} is invalid") from exc
    if _b64u(raw) != value:
        raise CredentialStoreError(f"{label} is invalid")
    return raw


@dataclass(frozen=True)
class MaintenanceContext:
    """A maintenance assertion bound to the metadata directory owner.

    The role label is descriptive only.  Authorization also checks the real
    effective UID against the owner of the maintenance-owned metadata root;
    an ops-approve process cannot manufacture an ``ops-maint`` label to gain
    registration or revocation access.
    """

    role: str = "ops-maint"
    euid: int | None = None

    def authorized(self, *, expected_uid: int | None = None) -> bool:
        if self.role != "ops-maint":
            return False
        claimed_uid = self.euid if self.euid is not None else expected_uid
        if claimed_uid is None or (expected_uid is not None and claimed_uid != expected_uid):
            return False
        try:
            return os.geteuid() == claimed_uid
        except AttributeError:  # pragma: no cover - Windows has no POSIX euid
            return False


@dataclass(frozen=True)
class CredentialRecord:
    credential_ref: str
    owner_id: str
    credential_id: bytes
    public_key: bytes
    sign_count: int
    environment: str
    status: str
    created_at: str
    revoked_at: str | None = None

    @property
    def raw_id(self) -> str:
        return _b64u(self.credential_id)

    def to_value(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "credential_ref": self.credential_ref,
            "owner_id": self.owner_id,
            "credential_id": self.raw_id,
            "public_key": _b64u(self.public_key),
            "sign_count": self.sign_count,
            "environment": self.environment,
            "status": self.status,
            "created_at": self.created_at,
            "revoked_at": self.revoked_at,
        }

    @classmethod
    def from_value(cls, value: Mapping[str, Any]) -> "CredentialRecord":
        if not isinstance(value, Mapping) or set(value) != {
            "schema_version",
            "credential_ref",
            "owner_id",
            "credential_id",
            "public_key",
            "sign_count",
            "environment",
            "status",
            "created_at",
            "revoked_at",
        }:
            raise CredentialStoreError("credential record is invalid")
        ref = value.get("credential_ref")
        owner_id = value.get("owner_id")
        environment = value.get("environment")
        status = value.get("status")
        created_at = value.get("created_at")
        revoked_at = value.get("revoked_at")
        if (
            not isinstance(ref, str)
            or not _SAFE_CREDENTIAL_REF.fullmatch(ref)
            or not isinstance(owner_id, str)
            or not is_uuid(owner_id)
            or environment not in {"trusted", "experimental"}
            or status not in {"active", "revoked"}
            or not isinstance(created_at, str)
            or not is_valid_utc(created_at)
            or (revoked_at is not None and (not isinstance(revoked_at, str) or not is_valid_utc(revoked_at)))
        ):
            raise CredentialStoreError("credential record is invalid")
        sign_count = value.get("sign_count")
        if isinstance(sign_count, bool) or not isinstance(sign_count, int) or sign_count < 0:
            raise CredentialStoreError("credential sign count is invalid")
        credential_id = _unb64u(value.get("credential_id"), label="credential ID")
        public_key = _unb64u(value.get("public_key"), label="credential public key")
        if not public_key:
            raise CredentialStoreError("credential public key is empty")
        if status == "revoked" and revoked_at is None:
            raise CredentialStoreError("revoked credential has no revocation time")
        if status == "active" and revoked_at is not None:
            raise CredentialStoreError("active credential has a revocation time")
        return cls(
            credential_ref=ref,
            owner_id=owner_id,
            credential_id=credential_id,
            public_key=public_key,
            sign_count=sign_count,
            environment=str(environment),
            status=str(status),
            created_at=created_at,
            revoked_at=revoked_at,
        )


class CredentialProvider(Protocol):
    def find_for_owner(self, owner_id: str) -> list[CredentialRecord]:
        ...

    def find_by_raw_id(self, raw_id: str) -> CredentialRecord:
        ...

    def update_sign_count(self, record: CredentialRecord, sign_count: int) -> CredentialRecord:
        ...


class FileCredentialStore:
    """A split metadata/counter store for one credential environment.

    ``metadata_root`` is maintenance-owned and read-only to the approval
    service.  ``counter_root`` is owned by ops-approve and contains only the
    monotonic authenticator counter plus its credential binding.  The legacy
    one-root constructor remains a local/test seam; production passes both
    roots explicitly.
    """

    def __init__(
        self,
        root: Path,
        *,
        environment: str,
        metadata_root: Path | None = None,
        counter_root: Path | None = None,
        create: bool = True,
    ) -> None:
        if environment not in {"trusted", "experimental"}:
            raise CredentialStoreError("credential environment is invalid")
        self.root = Path(root)
        self.metadata_root = Path(metadata_root) if metadata_root is not None else self.root
        self.counter_root = Path(counter_root) if counter_root is not None else self.root
        self._prepare_root(self.root, create=create)
        self._metadata_uid = self._prepare_root(self.metadata_root, create=create)
        self._counter_uid = self._prepare_root(self.counter_root, create=create)
        self.environment = environment
        self.metadata_store = AtomicJsonStore(self.metadata_root)
        self.counter_store = AtomicJsonStore(self.counter_root)
        # ``store`` is retained as a read-only compatibility alias for code
        # and fixtures that inspect the metadata side of the store.
        self.store = self.metadata_store
        self._lock = threading.RLock()

    @staticmethod
    def _prepare_root(path: Path, *, create: bool) -> int:
        try:
            if create:
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
            info = path.lstat()
        except OSError as exc:
            raise CredentialStoreError("credential store is unavailable") from exc
        if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
            raise CredentialStoreError("credential store root is not trusted")
        return info.st_uid

    def _metadata_path(self, raw_id: str) -> str:
        if not _SAFE_RAW_ID.fullmatch(raw_id):
            raise CredentialStoreError("credential ID is invalid")
        return self.metadata_store.record_path("credentials", raw_id)

    def _counter_path(self, raw_id: str) -> str:
        if not _SAFE_RAW_ID.fullmatch(raw_id):
            raise CredentialStoreError("credential ID is invalid")
        # ``counter_root`` is already the dedicated counter directory.  Keep
        # its records at the root so the deployment path is exactly
        # ``.../trusted/counters/<credential-id>.json``.
        return f"{raw_id}.json"

    @staticmethod
    def _expose_metadata(path: Path) -> None:
        """Make a metadata record read-only to its dedicated verifier group."""

        try:
            info = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(info.st_mode):
                raise OSError("credential metadata is not a regular file")
            # The deployment-provisioned parent owns the verifier group and
            # may carry setgid.  The maintenance UID need not belong to that
            # group, so chmod-ing the parent here can clear setgid on Unix and
            # make later metadata unreadable to ops-approve.
            path.chmod(0o640)
        except OSError as exc:
            raise CredentialStoreError("credential metadata projection failed") from exc

    @staticmethod
    def _counter_value(record: CredentialRecord, sign_count: int) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "credential_ref": record.credential_ref,
            "credential_id": record.raw_id,
            "sign_count": sign_count,
        }

    def _read_counter(self, record: CredentialRecord) -> int:
        try:
            value = self.counter_store.read_json(self._counter_path(record.raw_id))
        except RecordNotFound:
            return record.sign_count
        except (StorageError, ModelError) as exc:
            raise CredentialStoreError("credential counter is invalid") from exc
        if not isinstance(value, Mapping) or set(value) != {
            "schema_version",
            "credential_ref",
            "credential_id",
            "sign_count",
        }:
            raise CredentialStoreError("credential counter is invalid")
        sign_count = value.get("sign_count")
        if (
            value.get("credential_ref") != record.credential_ref
            or value.get("credential_id") != record.raw_id
            or isinstance(sign_count, bool)
            or not isinstance(sign_count, int)
            or sign_count < 0
        ):
            raise CredentialStoreError("credential counter binding is invalid")
        return max(record.sign_count, sign_count)

    def _read_metadata_record(self, raw_id: str) -> CredentialRecord:
        try:
            value = self.metadata_store.read_json(self._metadata_path(raw_id))
        except (RecordNotFound, StorageError) as exc:
            raise CredentialStoreError("credential is unavailable") from exc
        record = CredentialRecord.from_value(value)
        if record.raw_id != raw_id or record.environment != self.environment:
            raise CredentialStoreError("credential environment does not match")
        return record

    def _require_counter_writer(self) -> None:
        try:
            current_uid = os.geteuid()
        except AttributeError:  # pragma: no cover - Windows has no POSIX euid
            raise CredentialStoreError("credential counter updates require a POSIX service UID")
        if current_uid != self._counter_uid:
            raise CredentialStoreError("credential counter update is not authorized")

    def register(
        self,
        *,
        credential_ref: str,
        owner_id: str,
        credential_id: bytes,
        public_key: bytes,
        sign_count: int,
        created_at: str,
        maintenance: MaintenanceContext,
    ) -> CredentialRecord:
        if not maintenance.authorized(expected_uid=self._metadata_uid):
            raise CredentialStoreError("credential registration requires ops-maint")
        if (
            not isinstance(credential_ref, str)
            or not _SAFE_CREDENTIAL_REF.fullmatch(credential_ref)
            or not isinstance(owner_id, str)
            or not is_uuid(owner_id)
            or not isinstance(credential_id, bytes)
            or not credential_id
            or not isinstance(public_key, bytes)
            or not public_key
            or isinstance(sign_count, bool)
            or not isinstance(sign_count, int)
            or sign_count < 0
            or not isinstance(created_at, str)
            or not is_valid_utc(created_at)
        ):
            raise CredentialStoreError("credential registration is invalid")
        record = CredentialRecord(
            credential_ref=credential_ref,
            owner_id=owner_id,
            credential_id=bytes(credential_id),
            public_key=bytes(public_key),
            sign_count=sign_count,
            environment=self.environment,
            status="active",
            created_at=created_at,
        )
        with self._lock:
            try:
                target = self.metadata_store.write_once(self._metadata_path(record.raw_id), record.to_value())
                self._expose_metadata(target)
            except (StorageError, ModelError) as exc:
                raise CredentialStoreError("credential record could not be published") from exc
        return record

    def revoke(self, raw_id: str, *, revoked_at: str, maintenance: MaintenanceContext) -> None:
        if not maintenance.authorized(expected_uid=self._metadata_uid):
            raise CredentialStoreError("credential revocation requires ops-maint")
        with self._lock:
            try:
                # Revocation is a maintenance metadata operation. Do not
                # require access to the ops-approve-owned counter directory.
                record = self._read_metadata_record(raw_id)
                if not is_valid_utc(revoked_at):
                    raise CredentialStoreError("revocation time is invalid")
                revoked = CredentialRecord(
                    credential_ref=record.credential_ref,
                    owner_id=record.owner_id,
                    credential_id=record.credential_id,
                    public_key=record.public_key,
                    sign_count=record.sign_count,
                    environment=record.environment,
                    status="revoked",
                    created_at=record.created_at,
                    revoked_at=revoked_at,
                )
                target = self.metadata_store.write_json(self._metadata_path(raw_id), revoked.to_value())
                self._expose_metadata(target)
            except CredentialStoreError:
                raise
            except (RecordNotFound, StorageError, ModelError) as exc:
                raise CredentialStoreError("credential revocation failed") from exc

    def find_by_raw_id(self, raw_id: str) -> CredentialRecord:
        with self._lock:
            record = self._read_metadata_record(raw_id)
            return replace(record, sign_count=self._read_counter(record))

    def find_for_owner(self, owner_id: str) -> list[CredentialRecord]:
        if not is_uuid(owner_id):
            raise CredentialStoreError("credential owner is invalid")
        directory = self.metadata_root / "credentials"
        if not directory.exists():
            return []
        try:
            info = directory.lstat()
        except OSError as exc:
            raise CredentialStoreError("credential metadata is unavailable") from exc
        if directory.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise CredentialStoreError("credential metadata directory is invalid")
        records: list[CredentialRecord] = []
        for path in sorted(directory.iterdir(), key=lambda item: item.name):
            if path.is_symlink() or not path.is_file() or path.suffix != ".json":
                continue
            raw_id = path.stem
            try:
                record = self.find_by_raw_id(raw_id)
            except CredentialStoreError:
                continue
            if record.owner_id == owner_id and record.status == "active":
                records.append(record)
        return records

    def update_sign_count(self, record: CredentialRecord, sign_count: int) -> CredentialRecord:
        if isinstance(sign_count, bool) or not isinstance(sign_count, int) or sign_count < 0:
            raise CredentialStoreError("credential sign count is invalid")
        self._require_counter_writer()
        with self._lock:
            current = self.find_by_raw_id(record.raw_id)
            if (
                current.credential_ref != record.credential_ref
                or current.owner_id != record.owner_id
                or current.credential_id != record.credential_id
                or current.public_key != record.public_key
                or current.environment != record.environment
            ):
                raise CredentialStoreError("credential binding changed")
            updated = replace(current, sign_count=max(current.sign_count, sign_count))
            try:
                self.counter_store.write_json(
                    self._counter_path(record.raw_id),
                    self._counter_value(updated, updated.sign_count),
                )
            except (StorageError, ModelError) as exc:
                raise CredentialStoreError("credential sign count could not be updated") from exc
            return updated


class MemoryCredentialStore:
    """Explicit test seam; never used by the default trusted service."""

    def __init__(self, records: list[CredentialRecord] | None = None, *, environment: str = "experimental") -> None:
        self.environment = environment
        self._records = {record.raw_id: record for record in records or []}
        self._lock = threading.RLock()

    def put(self, record: CredentialRecord) -> None:
        if record.environment != self.environment:
            raise CredentialStoreError("credential environment does not match")
        with self._lock:
            self._records[record.raw_id] = record

    def find_by_raw_id(self, raw_id: str) -> CredentialRecord:
        with self._lock:
            record = self._records.get(raw_id)
        if record is None or record.environment != self.environment:
            raise CredentialStoreError("credential is unavailable")
        return record

    def find_for_owner(self, owner_id: str) -> list[CredentialRecord]:
        with self._lock:
            return [
                record
                for record in self._records.values()
                if record.owner_id == owner_id and record.status == "active" and record.environment == self.environment
            ]

    def update_sign_count(self, record: CredentialRecord, sign_count: int) -> CredentialRecord:
        with self._lock:
            current = self.find_by_raw_id(record.raw_id)
            updated = CredentialRecord(
                credential_ref=current.credential_ref,
                owner_id=current.owner_id,
                credential_id=current.credential_id,
                public_key=current.public_key,
                sign_count=max(current.sign_count, sign_count),
                environment=current.environment,
                status=current.status,
                created_at=current.created_at,
                revoked_at=current.revoked_at,
            )
            self._records[record.raw_id] = updated
            return updated


class ApprovalStore:
    """Immutable per-plan Approval v1 publication."""

    def __init__(self, store: AtomicJsonStore) -> None:
        self.store = store

    def _path(self, plan_id: str) -> str:
        if not is_uuid(plan_id):
            raise ApprovalStoreError("plan ID is invalid", code="invalid_request")
        return self.store.record_path("approvals", plan_id)

    @staticmethod
    def _expose_read_projection(path: Path) -> None:
        """Expose an immutable Approval to the ops-exec read group only."""

        try:
            info = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(info.st_mode):
                raise OSError("approval projection target is not a regular file")
            # The deployment-provisioned parent owns the executor group and
            # may carry setgid.  ops-approve must not chmod that parent: Unix
            # can clear setgid when the owner is not a member of the group.
            path.chmod(0o640)
        except OSError as exc:
            raise ApprovalStoreError("approval read projection could not be published") from exc

    def publish(self, approval: Mapping[str, Any]) -> dict[str, Any]:
        value = dict(approval)
        try:
            validate_model("Approval", value)
        except (ModelError, RuntimeError) as exc:
            raise ApprovalStoreError("approval record is invalid", code="approval_required") from exc
        relative = self._path(str(value["plan_id"]))
        try:
            target = self.store.write_immutable_record(relative, "Approval", value)
            self._expose_read_projection(target)
        except RecordExists:
            try:
                existing = self.store.read_record(relative, "Approval")
            except (RecordNotFound, StorageError, ModelError) as exc:
                raise ApprovalStoreError("existing approval is unreadable") from exc
            immutable_fields = (
                "owner_id",
                "plan_id",
                "plan_digest",
                "approver_credential_id",
                "approved_at",
                "start_before",
                "max_runtime_seconds",
            )
            if any(existing.get(field) != value.get(field) for field in immutable_fields):
                raise ApprovalConflict("a different approval already exists for this plan")
            self._expose_read_projection(self.store.safe_path(relative))
            return existing
        except (StorageError, ModelError) as exc:
            raise ApprovalStoreError("approval could not be published") from exc
        return value

    def get_for_plan(self, plan_id: str) -> dict[str, Any]:
        relative = self._path(plan_id)
        try:
            return self.store.read_record(relative, "Approval")
        except RecordNotFound as exc:
            raise ApprovalStoreError("trusted approval is unavailable", code="approval_required") from exc
        except (StorageError, ModelError) as exc:
            raise ApprovalStoreError("trusted approval is invalid", code="approval_required") from exc


class TrustedApprovalProvider:
    """Read-only provider used by the execution gate."""

    def __init__(self, approval_store: ApprovalStore) -> None:
        self.store = approval_store

    def get_for_plan(self, plan_id: str) -> dict[str, Any]:
        return self.store.get_for_plan(plan_id)


__all__ = [
    "ApprovalConflict",
    "ApprovalStore",
    "ApprovalStoreError",
    "CredentialProvider",
    "CredentialRecord",
    "CredentialStoreError",
    "FileCredentialStore",
    "MaintenanceContext",
    "MemoryCredentialStore",
    "TrustedApprovalProvider",
]
