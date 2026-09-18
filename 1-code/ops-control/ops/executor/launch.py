"""Exactly-once OPS-005 launch chain.

The launcher is the sole consumer of the trusted Approval provider.  It never
re-parses ``current`` after the fixed release snapshot, and an immutable
``uses`` or ``launches`` record is treated as a durable idempotency boundary.
"""

from __future__ import annotations

import contextlib
import os
import stat
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from ..gates import ExecutionGate
from ..models import ModelError, is_uuid, utc_now, validate_model
from ..results import ResultError, ResultService
from ..storage import AtomicJsonStore, RecordExists, RecordNotFound, StorageError
from .broker import BrokerConfig, BrokerError, BrokerInvocation, FixedBroker


class LaunchError(RuntimeError):
    code = "precondition_failed"

    def __init__(self, message: str, *, code: str | None = None, run_id: str | None = None, status: str | None = None) -> None:
        if code is not None:
            self.code = code
        self.run_id = run_id
        self.status = status
        super().__init__(message)


class ServiceManagerResponseLost(RuntimeError):
    """The manager may have accepted the launch but its response is unknown."""

    code = "result_unknown"


@dataclass(frozen=True)
class ServiceManagerResult:
    accepted: bool
    completed: bool
    exit_code: int | None = None
    warning: str | None = None


class ServiceManager(Protocol):
    def start(self, invocation: BrokerInvocation, *, run_id: str, plan: Mapping[str, Any]) -> ServiceManagerResult:
        ...


_FIXED_NOOP_PROGRAM = "import sys; raise SystemExit(0 if len(sys.argv) == 2 and sys.argv[1].startswith('/') else 1)"


class Ops005NoopServiceManager:
    """Run only a fixed, harmless local process for the OPS-005 action."""

    def __init__(
        self,
        *,
        runner: Callable[[BrokerInvocation], ServiceManagerResult] | None = None,
        timeout_seconds: int = 30,
    ) -> None:
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or timeout_seconds < 1:
            raise LaunchError("service manager timeout is invalid", code="invalid_request")
        self.runner = runner
        self.timeout_seconds = timeout_seconds

    def start(self, invocation: BrokerInvocation, *, run_id: str, plan: Mapping[str, Any]) -> ServiceManagerResult:
        release = Path(invocation.release)
        if (
            plan.get("action_id") != "ops005.noop"
            or not is_uuid(run_id)
            or not release.is_absolute()
            or any(part == ".." for part in release.parts)
        ):
            raise LaunchError("OPS-005 service manager received an unsupported plan", code="action_frozen")
        if self.runner is not None:
            result = self.runner(invocation)
            if not isinstance(result, ServiceManagerResult):
                raise LaunchError("service manager returned an invalid result", code="result_unknown", status="unknown")
            return result
        # No shell, request parameters, adapter paths, or inherited search
        # paths are involved.  The fixed interpreter and absolute release
        # directory came from the maintenance-owned BrokerInvocation.
        try:
            completed = subprocess.run(
                [str(invocation.executable), "-c", _FIXED_NOOP_PROGRAM, str(release)],
                cwd=str(release),
                env=dict(invocation.environment),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ServiceManagerResult(accepted=True, completed=False, warning="service_manager_timeout")
        except (OSError, ValueError):
            return ServiceManagerResult(accepted=False, completed=False, warning="service_manager_unavailable")
        return ServiceManagerResult(
            accepted=True,
            completed=completed.returncode == 0,
            exit_code=completed.returncode,
            warning=None if completed.returncode == 0 else "service_manager_exit_nonzero",
        )


class Ops005FixedBroker(FixedBroker):
    """FixedBroker specialization with one allowlisted OPS-005 capability."""

    capability = "ops005.noop"

    def __init__(self, config: BrokerConfig) -> None:
        if config.production:
            raise BrokerError("OPS-005 harmless broker must use the non-production capability profile")
        super().__init__(config)


def default_ops005_broker(*, store_root: Path) -> Ops005FixedBroker:
    """Build a source-checkout broker with a fixed absolute release snapshot."""

    package_root = Path(__file__).resolve().parents[2]
    return Ops005FixedBroker(
        BrokerConfig(
            interpreter=Path(sys.executable).resolve(),
            release_root=package_root.parent,
            code_dir=package_root,
            data_dir=Path(store_root).resolve(),
            release_id=package_root.name,
            broker_entrypoint=package_root / "ops" / "executor" / "broker.py",
            allowed_capabilities=("ops005.noop",),
            production=False,
        )
    )


@dataclass(frozen=True)
class ApplyOutcome:
    run_id: str
    status: str
    result: dict[str, Any] | None = None

    def data(self) -> dict[str, Any]:
        value: dict[str, Any] = {"run_id": self.run_id, "status": self.status}
        if self.result is not None:
            value["result"] = self.result
        return value


_RELEASE_THREAD_LOCK = threading.RLock()


class ExactlyOnceLauncher:
    """Implement Gate → use → run → fixed release → launch → Result."""

    def __init__(
        self,
        *,
        store: AtomicJsonStore,
        gate: ExecutionGate,
        broker: FixedBroker,
        service_manager: ServiceManager,
        result_service: ResultService | None = None,
        now: Callable[[], str] = utc_now,
        release_lock_path: Path | None = None,
    ) -> None:
        self.store = store
        self.gate = gate
        self.broker = broker
        self.service_manager = service_manager
        self.results = result_service or ResultService(store, now=now)
        self.now = now
        self.release_lock_path = (
            Path(release_lock_path)
            if release_lock_path is not None
            else self.store.root / "locks" / "release.lock"
        )
        self._ambiguous_plans: dict[str, str] = {}

    def _path(self, directory: str, record_id: str) -> str:
        try:
            return self.store.record_path(directory, record_id)
        except StorageError as exc:
            raise LaunchError("launch record path is invalid", code="storage_failed") from exc

    def _read_optional(self, directory: str, record_id: str, model: str) -> dict[str, Any] | None:
        try:
            return self.store.read_record(self._path(directory, record_id), model)
        except RecordNotFound:
            return None
        except (StorageError, ModelError) as exc:
            raise LaunchError("launch state is unreadable", code="result_unknown", run_id=record_id, status="unknown") from exc

    def _trusted_owner(self) -> str:
        try:
            owner = self.gate.identity_provider.owner_id()
        except Exception as exc:
            raise LaunchError("trusted current owner is unavailable", code="precondition_failed") from exc
        if not is_uuid(owner):
            raise LaunchError("trusted current owner is invalid", code="precondition_failed")
        return owner

    def _unknown(
        self,
        run: Mapping[str, Any] | None,
        run_id: str,
        *,
        warnings: list[str] | None = None,
    ) -> ApplyOutcome:
        # A concurrent retry may have read ``runs/<run_id>`` just before the
        # real manager completed.  Observe the authoritative final record
        # before attempting to publish an unknown result, and let
        # ResultService's immutable terminal write arbitrate the remaining
        # race.  In particular, never turn a saved succeeded result into
        # unknown.
        result: dict[str, Any] | None = None
        if run is not None:
            try:
                observed = self.results.get_if_present(run_id)
                if observed is not None and observed.get("status") in {"succeeded", "failed", "unknown"}:
                    return ApplyOutcome(run_id=run_id, status=str(observed["status"]), result=observed)
                result = self.results.finish(
                    run,
                    status="unknown",
                    warnings=warnings or ["execution_state_unknown"],
                )
            except ResultError:
                result = None
        public_status = "unknown" if result is None or result.get("status") == "running" else str(result["status"])
        return ApplyOutcome(run_id=run_id, status=public_status, result=result)

    @staticmethod
    def _stored_outcome(run_id: str, result: Mapping[str, Any]) -> ApplyOutcome:
        status = result.get("status")
        if status not in {"succeeded", "failed", "unknown"}:
            status = "unknown"
        return ApplyOutcome(run_id=run_id, status=str(status), result=dict(result))

    def _existing_use_outcome(self, use: Mapping[str, Any], *, plan_id: str, owner_id: str) -> ApplyOutcome:
        if use.get("plan_id") != plan_id:
            raise LaunchError("existing use record is not bound to the plan", code="result_unknown", status="unknown")
        run_id = use.get("run_id")
        if not isinstance(run_id, str) or not is_uuid(run_id):
            raise LaunchError("existing use record is invalid", code="result_unknown", status="unknown")
        if use.get("owner_id") != owner_id:
            raise LaunchError("plan use belongs to another owner", code="precondition_failed")
        try:
            result = self.results.get_if_present(run_id)
        except ResultError as exc:
            raise LaunchError("existing result is unreadable", code="result_unknown", status="unknown") from exc
        if result is not None:
            if result.get("plan_id") != plan_id or result.get("owner_id") != owner_id:
                raise LaunchError("existing result is not bound to the plan", code="result_unknown", status="unknown")
            if result.get("status") == "running":
                return self._unknown(result, run_id)
            return ApplyOutcome(run_id=run_id, status=str(result["status"]), result=result)
        run = self._read_optional("runs", run_id, "RunSummary")
        if run is not None and (run.get("plan_id") != plan_id or run.get("owner_id") != owner_id):
            raise LaunchError("existing run is not bound to the plan", code="result_unknown", status="unknown")
        launch = self._read_optional("launches", run_id, "LaunchRecord")
        # A durable launch marker, or even a missing initial run after use,
        # means the caller cannot prove whether the process was accepted.
        return self._unknown(run, run_id)

    def _existing_plan_outcome(self, plan_id: str, *, owner_id: str) -> ApplyOutcome | None:
        """Return a fail-closed outcome for a plan with a durable run marker."""
        ambiguous_run_id = self._ambiguous_plans.get(plan_id)
        if ambiguous_run_id is not None:
            run = self._read_optional("runs", ambiguous_run_id, "RunSummary")
            return self._unknown(run, ambiguous_run_id)
        try:
            run = self.results.find_for_plan(plan_id)
        except ResultError as exc:
            raise LaunchError("existing run state is unknown", code="result_unknown", status="unknown") from exc
        if run is None:
            return None
        if run.get("owner_id") != owner_id:
            raise LaunchError("existing run belongs to another owner", code="precondition_failed")
        if run.get("status") == "running":
            return self._unknown(run, run["run_id"])
        return ApplyOutcome(run_id=run["run_id"], status=str(run["status"]), result=run)

    def _persist_ambiguous_use(self, plan: Mapping[str, Any], run_id: str) -> ApplyOutcome:
        """Persist an unknown RunSummary when use publication is ambiguous."""
        self._ambiguous_plans[str(plan["plan_id"])] = run_id
        try:
            run = self.results.initial_run(plan, run_id)
            self.results.save_initial(run)
        except ResultError:
            return ApplyOutcome(run_id=run_id, status="unknown")
        return self._unknown(run, run_id)

    @contextlib.contextmanager
    def _release_guard(self):
        with _RELEASE_THREAD_LOCK:
            path = self.release_lock_path
            handle = None
            fd = None
            try:
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                parent_info = path.parent.lstat()
                if path.parent.is_symlink() or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_mode & 0o022:
                    raise OSError("release lock parent is not trusted")
                if path.is_symlink():
                    raise OSError("release lock is a symbolic link")
                flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(path, flags, 0o600)
                handle = os.fdopen(fd, "a+")
                lock_info = os.fstat(fd)
                if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_mode & 0o077:
                    raise OSError("release lock is not a private regular file")
                try:
                    import fcntl
                except ImportError:  # pragma: no cover - exercised on Windows
                    fcntl = None
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                else:  # pragma: no cover - exercised on Windows
                    import msvcrt

                    handle.seek(0)
                    if lock_info.st_size == 0:
                        handle.write("0")
                        handle.flush()
                    msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    if fcntl is not None:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    else:  # pragma: no cover - exercised on Windows
                        import msvcrt

                        handle.seek(0)
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    handle.close()
                    handle = None
                    fd = None
            except OSError as exc:
                raise LaunchError("trusted release lock is unavailable", code="result_unknown", status="unknown") from exc
            finally:
                if handle is not None:
                    handle.close()
                elif fd is not None:
                    os.close(fd)

    def apply(self, plan_id: str) -> ApplyOutcome:
        if not isinstance(plan_id, str) or not is_uuid(plan_id):
            raise LaunchError("plan ID is invalid", code="invalid_request")
        owner_id = self._trusted_owner()
        existing_use = self._read_optional("uses", plan_id, "UseRecord")
        if existing_use is not None:
            return self._existing_use_outcome(existing_use, plan_id=plan_id, owner_id=owner_id)
        existing_plan = self._existing_plan_outcome(plan_id, owner_id=owner_id)
        if existing_plan is not None:
            return existing_plan

        # No caller Approval crosses this call.  The gate obtains it only from
        # its trusted provider and re-reads the immutable Plan and bindings.
        gate_evidence = self.gate.validate_for_gateway_start(plan_id)
        try:
            plan = self.store.read_record(self._path("plans", plan_id), "Plan")
        except (RecordNotFound, StorageError, ModelError) as exc:
            raise LaunchError("immutable plan is unavailable", code="storage_failed") from exc
        if plan.get("owner_id") != owner_id:
            raise LaunchError("plan owner is not the trusted current owner", code="precondition_failed")
        if (
            gate_evidence.get("plan_id") != plan.get("plan_id")
            or gate_evidence.get("plan_digest") != plan.get("plan_digest")
            or gate_evidence.get("owner_id") != plan.get("owner_id")
            or gate_evidence.get("action_id") != plan.get("action_id")
            or gate_evidence.get("bundle_id") != plan.get("bundle_id")
        ):
            raise LaunchError("immutable plan changed during gate", code="plan_stale")
        if plan.get("action_id") != "ops005.noop":
            raise LaunchError("only the OPS-005 harmless action is executable", code="action_frozen")
        run_id = uuid.uuid4()
        run_id_text = str(run_id)
        use = {
            "schema_version": 1,
            "owner_id": plan["owner_id"],
            "plan_id": plan["plan_id"],
            "run_id": run_id_text,
            "created_at": self.now(),
            "bundle_id": plan["bundle_id"],
            "resolved_targets": list(plan["resolved_targets"]),
        }
        try:
            validate_model("UseRecord", use)
            self.store.write_immutable_record(self._path("uses", plan_id), "UseRecord", use)
        except RecordExists:
            winner = self._read_optional("uses", plan_id, "UseRecord")
            if winner is None:
                raise LaunchError("concurrent use state is unknown", code="result_unknown", status="unknown")
            return self._existing_use_outcome(winner, plan_id=plan_id, owner_id=owner_id)
        except (ModelError, StorageError) as exc:
            winner = self._read_optional("uses", plan_id, "UseRecord")
            if winner is not None:
                return self._existing_use_outcome(winner, plan_id=plan_id, owner_id=owner_id)
            return self._persist_ambiguous_use(plan, run_id_text)

        try:
            run = self.results.initial_run(plan, run_id_text)
        except ResultError:
            return ApplyOutcome(run_id=run_id_text, status="unknown")
        try:
            self.results.save_initial(run)
        except (ResultError, StorageError) as exc:
            existing_run = self._read_optional("runs", run_id_text, "RunSummary")
            if existing_run is not None:
                return self._unknown(existing_run, run_id_text)
            return self._unknown(None, run_id_text)

        try:
            with self._release_guard():
                existing_launch = self._read_optional("launches", run_id_text, "LaunchRecord")
                if existing_launch is not None:
                    return self._unknown(run, run_id_text)
                try:
                    invocation = self.broker.build_invocation(Ops005FixedBroker.capability)
                except (BrokerError, OSError) as exc:
                    failed = self.results.finish(run, status="failed", warnings=["fixed_release_unavailable"])
                    return self._stored_outcome(run_id_text, failed)
                launch = {
                    "schema_version": 1,
                    "owner_id": plan["owner_id"],
                    "run_id": run_id_text,
                    "bundle_id": plan["bundle_id"],
                    "attempted_at": self.now(),
                }
                try:
                    validate_model("LaunchRecord", launch)
                    self.store.write_immutable_record(self._path("launches", run_id_text), "LaunchRecord", launch)
                except RecordExists:
                    return self._unknown(run, run_id_text)
                except (ModelError, StorageError) as exc:
                    marker = self._read_optional("launches", run_id_text, "LaunchRecord")
                    if marker is not None:
                        return self._unknown(run, run_id_text)
                    return self._unknown(run, run_id_text)
                try:
                    manager_result = self.service_manager.start(invocation, run_id=run_id_text, plan=plan)
                except ServiceManagerResponseLost:
                    return self._unknown(run, run_id_text)
                except Exception:
                    # A manager exception after the immutable launch marker is
                    # not proof that no process was accepted.
                    return self._unknown(run, run_id_text)
                if not manager_result.accepted:
                    warning = manager_result.warning or "service_manager_rejected"
                    failed = self.results.finish(run, status="failed", warnings=[warning])
                    return self._stored_outcome(run_id_text, failed)
                if not manager_result.completed:
                    warning = manager_result.warning or "service_manager_incomplete"
                    return self._unknown(run, run_id_text, warnings=[warning])
                warnings = [] if manager_result.warning is None else [manager_result.warning]
                try:
                    succeeded = self.results.finish(run, status="succeeded", warnings=warnings)
                except ResultError:
                    return self._unknown(run, run_id_text)
                return self._stored_outcome(run_id_text, succeeded)
        except LaunchError as exc:
            if exc.code == "result_unknown":
                return self._unknown(run, run_id_text)
            raise
        except Exception:
            # The use and/or launch markers make a retry unsafe.  Best-effort
            # unknown result is the only safe public outcome here.
            return self._unknown(run, run_id_text)


__all__ = [
    "ApplyOutcome",
    "ExactlyOnceLauncher",
    "LaunchError",
    "Ops005FixedBroker",
    "Ops005NoopServiceManager",
    "ServiceManager",
    "ServiceManagerResponseLost",
    "ServiceManagerResult",
    "default_ops005_broker",
]
