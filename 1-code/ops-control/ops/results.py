"""Run and Result v1 persistence for the OPS-005 launcher."""

from __future__ import annotations

import re
import stat
from typing import Any, Callable, Mapping

from .models import ModelError, is_uuid, utc_now, validate_model
from .storage import AtomicJsonStore, RecordExists, RecordNotFound, StorageError


class ResultError(RuntimeError):
    code = "storage_failed"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        if code is not None:
            self.code = code
        super().__init__(message)


_SECRET_MARKER = re.compile(
    r"(?i)(?:-----begin .*private key-----|authorization\s*:|bearer\s+|\b(?:password|passwd|secret|token|api[_-]?key)\b|sk-[a-z0-9]|fake_secret_sentinel|ops_test_secret_sentinel)"
)
_SAFE_RESULT_WARNING = re.compile(r"^[A-Za-z0-9._:/ -]{1,256}$")


def _validate_run_id(run_id: str) -> str:
    if not isinstance(run_id, str) or not is_uuid(run_id):
        raise ResultError("run ID is invalid", code="invalid_request")
    return run_id


def _clean_warnings(warnings: list[str] | tuple[str, ...] | None) -> list[str]:
    result: list[str] = []
    for warning in warnings or []:
        if not isinstance(warning, str) or not _SAFE_RESULT_WARNING.fullmatch(warning) or _SECRET_MARKER.search(warning):
            raise ResultError("result warning is unsafe", code="storage_failed")
        result.append(warning)
    return result


class ResultService:
    """Store initial/final RunSummary records without accepting raw process output."""

    def __init__(self, store: AtomicJsonStore, *, now: Callable[[], str] = utc_now) -> None:
        self.store = store
        self.now = now

    def _path(self, directory: str, run_id: str) -> str:
        return self.store.record_path(directory, _validate_run_id(run_id))

    @staticmethod
    def _counts(target_count: int, status: str) -> dict[str, int]:
        values = {"pending": 0, "running": 0, "succeeded": 0, "failed": 0, "unreachable": 0, "not_run": 0, "unknown": 0}
        if status == "running":
            values["pending"] = target_count
        elif status == "succeeded":
            values["succeeded"] = target_count
        elif status == "failed":
            values["failed"] = target_count
        elif status == "unknown":
            values["unknown"] = target_count
        else:
            raise ResultError("run status is invalid", code="storage_failed")
        return values

    def initial_run(self, plan: Mapping[str, Any], run_id: str) -> dict[str, Any]:
        _validate_run_id(run_id)
        hosts = sorted(set(plan.get("resolved_targets", [])))
        if len(hosts) != len(plan.get("resolved_targets", [])) or not hosts:
            raise ResultError("run targets are invalid", code="storage_failed")
        value = {
            "schema_version": 1,
            "owner_id": plan.get("owner_id"),
            "run_id": run_id,
            "plan_id": plan.get("plan_id"),
            "created_at": self.now(),
            "finished_at": None,
            "status": "running",
            "target_count": len(hosts),
            "counts": self._counts(len(hosts), "running"),
            "hosts": hosts,
            "warnings": [],
        }
        try:
            validate_model("RunSummary", value)
        except (ModelError, RuntimeError) as exc:
            raise ResultError("initial run is invalid", code="storage_failed") from exc
        return value

    def save_initial(self, run: Mapping[str, Any]) -> None:
        value = dict(run)
        try:
            validate_model("RunSummary", value)
            self.store.write_immutable_record(self._path("runs", value["run_id"]), "RunSummary", value)
        except (ModelError, RuntimeError) as exc:
            if isinstance(exc, ResultError):
                raise
            raise ResultError("initial run could not be saved", code="storage_failed") from exc

    @staticmethod
    def _expose_read_projection(path: Any) -> None:
        """Expose only the final non-secret result to the ops-call group.

        ``AtomicJsonStore`` intentionally creates private files.  The
        deployment template pre-creates the result directory with a dedicated
        read-only group; changing only the mode of this already-published,
        immutable final record makes that projection explicit without adding a
        second result schema or a shared write path.
        """

        try:
            info = path.lstat()
            parent_info = path.parent.lstat()
            if not stat.S_ISREG(info.st_mode) or path.is_symlink():
                raise OSError("result projection target is not a regular file")
            if path.parent.is_symlink() or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_mode & 0o022:
                raise OSError("result projection parent is not trusted")
            # The deployment-provisioned parent owns the read-only projection
            # group and may carry setgid.  Do not chmod it from ops-exec: the
            # service UID need not belong to that group, and Unix may clear
            # setgid during an unprivileged chmod, breaking future result
            # projections.  Only the immutable file needs its read bit set.
            path.chmod(0o640)
        except OSError as exc:
            raise ResultError("result read projection could not be published", code="storage_failed") from exc

    def finish(self, run: Mapping[str, Any], *, status: str, warnings: list[str] | None = None) -> dict[str, Any]:
        value = dict(run)
        if status not in {"succeeded", "failed", "unknown"}:
            raise ResultError("result status is invalid", code="storage_failed")
        value["status"] = status
        value["finished_at"] = self.now()
        target_count = value.get("target_count")
        if isinstance(target_count, bool) or not isinstance(target_count, int) or target_count < 1:
            raise ResultError("run target count is invalid", code="storage_failed")
        value["counts"] = self._counts(target_count, status)
        value["warnings"] = _clean_warnings(warnings)
        try:
            validate_model("RunSummary", value)
            # A final result is a terminal fact.  Publish it once, then never
            # replace it: a retry that observes an older snapshot must not
            # overwrite succeeded/failed with a later unknown (or vice versa).
            target = self.store.write_immutable_record(self._path("results", value["run_id"]), "RunSummary", value)
            self._expose_read_projection(target)
        except RecordExists:
            existing = self._read("results", value["run_id"])
            if existing is None:
                raise ResultError("result commit state is unknown", code="result_unknown")
            if existing.get("plan_id") != value.get("plan_id") or existing.get("owner_id") != value.get("owner_id"):
                raise ResultError("stored result is not bound to the run", code="result_unknown")
            # Existing running records are also immutable.  Returning the
            # durable record keeps the public state conservative without
            # allowing a second writer to mutate it.
            return existing
        except (ModelError, RuntimeError) as exc:
            if isinstance(exc, ResultError):
                raise
            raise ResultError("result could not be saved", code="storage_failed") from exc
        return value

    def _read(self, directory: str, run_id: str) -> dict[str, Any] | None:
        try:
            value = self.store.read_record(self._path(directory, run_id), "RunSummary")
            if value.get("run_id") != run_id:
                raise ResultError("stored run path binding is invalid", code="result_unknown")
            return value
        except RecordNotFound:
            return None
        except ResultError:
            raise
        except (StorageError, ModelError) as exc:
            raise ResultError("stored run result is invalid", code="storage_failed") from exc

    def get(self, run_id: str) -> dict[str, Any]:
        value = self._read("results", run_id)
        if value is not None:
            return value
        value = self._read("runs", run_id)
        if value is not None:
            return value
        raise ResultError("run result is unavailable", code="source_unavailable")

    def get_if_present(self, run_id: str) -> dict[str, Any] | None:
        value = self._read("results", run_id)
        if value is not None:
            return value
        return self._read("runs", run_id)

    def find_for_plan(self, plan_id: str) -> dict[str, Any] | None:
        """Find a durable run marker for a plan after an uncertain write.

        This only reads existing RunSummary v1 records.  It is used to make a
        failed/ambiguous use publication fail closed on a later apply without
        introducing another idempotency schema.
        """
        if not is_uuid(plan_id):
            raise ResultError("plan ID is invalid", code="invalid_request")
        for directory in ("results", "runs"):
            root = self.store.root / directory
            try:
                info = root.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ResultError("run state is unavailable", code="result_unknown") from exc
            if root.is_symlink() or not stat.S_ISDIR(info.st_mode):
                raise ResultError("run state is invalid", code="result_unknown")
            matches: list[dict[str, Any]] = []
            try:
                entries = sorted(root.iterdir(), key=lambda item: item.name)
            except OSError as exc:
                raise ResultError("run state is unavailable", code="result_unknown") from exc
            for entry in entries:
                if entry.is_symlink() or not entry.is_file() or entry.suffix != ".json":
                    continue
                run_id = entry.stem
                if not is_uuid(run_id):
                    continue
                value = self._read(directory, run_id)
                if value is not None and value["plan_id"] == plan_id:
                    matches.append(value)
            if len(matches) > 1:
                raise ResultError("multiple runs exist for the immutable plan", code="result_unknown")
            if matches:
                return matches[0]
        return None


__all__ = ["ResultError", "ResultService"]
