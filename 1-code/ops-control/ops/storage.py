"""Fail-closed JSON file primitives for OPS-002.

The root is a constructor dependency, never a request field.  A replacement
is prepared beside its destination, synced, and atomically committed.  The
old inode is held by a same-directory rollback link until the post-commit
directory sync succeeds, so a reported write failure can restore the old
record.  Immutable records use a same-directory hard-link publication so
concurrent first creators have exactly one winner.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

from .models import ModelError, canonical_json_bytes, strict_json_loads, validate_model


class StorageError(RuntimeError):
    code = "storage_failed"


class RecordExists(StorageError):
    code = "record_exists"


class RecordNotFound(StorageError):
    code = "source_unavailable"


class StorageCommitUnknown(StorageError):
    """The visible commit could not be rolled back safely."""

    code = "storage_failed"


def _is_regular(mode: int) -> bool:
    return stat.S_ISREG(mode)


class AtomicJsonStore:
    """A small, bounded, symlink-aware JSON store under one trusted root."""

    def __init__(
        self,
        root: Path,
        *,
        max_bytes: int = 1 << 20,
        replace_fn: Callable[[str, str], None] = os.replace,
        link_fn: Callable[[str, str], None] = os.link,
        fsync_fn: Callable[[int], None] = os.fsync,
        fchmod_fn: Callable[[int, int], None] | None = getattr(os, "fchmod", None),
    ) -> None:
        self.root = Path(root)
        self.max_bytes = max_bytes
        self._replace = replace_fn
        self._link = link_fn
        self._fsync = fsync_fn
        self._fchmod = fchmod_fn
        self._check_root()

    def _check_root(self) -> None:
        try:
            root_stat = self.root.lstat()
        except FileNotFoundError as exc:
            raise StorageError("trusted storage root is unavailable") from exc
        if self.root.is_symlink() or not stat.S_ISDIR(root_stat.st_mode):
            raise StorageError("trusted storage root is not a directory")
        if root_stat.st_mode & 0o022:
            raise StorageError("trusted storage root is writable by group or other users")

    @staticmethod
    def _reject_relative(relative: str) -> tuple[str, ...]:
        if (
            not isinstance(relative, str)
            or not relative
            or "\\" in relative
            or (len(relative) >= 2 and relative[1] == ":")
        ):
            raise StorageError("record path must be a relative POSIX path")
        path = PurePosixPath(relative)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise StorageError("record path contains an unsafe component")
        return path.parts

    def _safe_directory(self, path: Path, *, create: bool = False) -> None:
        try:
            info = path.lstat()
        except FileNotFoundError:
            if not create:
                raise StorageError("record parent is unavailable")
            try:
                path.mkdir(mode=0o700)
            except FileExistsError:
                # Another first writer may have created the same trusted
                # directory.  Re-stat it below and still reject a symlink.
                pass
            info = path.lstat()
        if path.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise StorageError("record parent is not a trusted directory")
        if info.st_mode & 0o022:
            raise StorageError("record parent is writable by group or other users")

    def safe_path(self, relative: str, *, create_parents: bool = False) -> Path:
        parts = self._reject_relative(relative)
        current = self.root
        for part in parts[:-1]:
            current = current / part
            self._safe_directory(current, create=create_parents)
        target = current / parts[-1]
        if target.exists() or target.is_symlink():
            try:
                target_stat = target.lstat()
            except FileNotFoundError as exc:
                raise StorageError("record path changed during validation") from exc
            if target.is_symlink() or not _is_regular(target_stat.st_mode):
                raise StorageError("record target is not a regular file")
        return target

    def _encode(self, value: Any) -> bytes:
        payload = canonical_json_bytes(value)
        if len(payload) + 1 > self.max_bytes:
            raise StorageError("record exceeds the read/write limit")
        return payload + b"\n"

    def _write_temp(self, parent: Path, payload: bytes) -> Path:
        fd, raw_path = tempfile.mkstemp(prefix=".ops-control-", suffix=".tmp", dir=parent)
        temp_path = Path(raw_path)
        try:
            if self._fchmod is not None:
                self._fchmod(fd, 0o600)
            else:  # pragma: no cover - current supported Unix test hosts have fchmod
                os.chmod(temp_path, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                self._fsync(handle.fileno())
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                temp_path.unlink()
            except OSError:
                pass
            raise
        return temp_path

    def _sync_parent(self, parent: Path) -> None:
        flags = getattr(os, "O_RDONLY", 0)
        directory_fd = os.open(parent, flags)
        try:
            self._fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def _check_existing_target(self, target: Path) -> None:
        if target.is_symlink():
            raise StorageError("record target is a symbolic link")
        if target.exists():
            try:
                target_stat = target.lstat()
            except FileNotFoundError as exc:
                raise StorageError("record target changed during validation") from exc
            if not _is_regular(target_stat.st_mode):
                raise StorageError("record target is not a regular file")

    @staticmethod
    def _file_identity(path: Path) -> tuple[int, int]:
        info = path.lstat()
        if not _is_regular(info.st_mode):
            raise StorageError("record target is not a regular file")
        return info.st_dev, info.st_ino

    @staticmethod
    def _reserve_path(parent: Path, *, prefix: str) -> Path:
        fd, raw_path = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=parent)
        os.close(fd)
        path = Path(raw_path)
        try:
            path.unlink()
        except OSError:
            try:
                path.unlink()
            except OSError:
                pass
            raise
        return path

    def _hold_old_record(self, target: Path) -> Path | None:
        """Keep the old inode named until the replacement is durable."""
        try:
            target.lstat()
        except FileNotFoundError:
            return None
        self._check_existing_target(target)
        rollback_path = self._reserve_path(target.parent, prefix=".ops-control-rollback-")
        try:
            self._link(str(target), str(rollback_path))
        except Exception:
            try:
                rollback_path.unlink()
            except OSError:
                pass
            raise
        return rollback_path

    @staticmethod
    def _discard_path(path: Path | None) -> None:
        if path is None:
            return
        try:
            path.unlink()
        except (FileNotFoundError, OSError):
            # Cleanup is deliberately best effort.  It must not turn a
            # successful commit into a reported write failure.
            pass

    def _rollback_replacement(
        self,
        target: Path,
        rollback_path: Path | None,
        new_identity: tuple[int, int],
    ) -> None:
        """Restore the pre-commit target, refusing to clobber a rival writer."""
        try:
            if self._file_identity(target) != new_identity:
                raise StorageCommitUnknown("record commit state is unknown")
            if rollback_path is None:
                target.unlink()
            else:
                self._replace(str(rollback_path), str(target))
        except StorageCommitUnknown:
            raise
        except Exception as exc:
            raise StorageCommitUnknown("record commit state is unknown") from exc

    def write_json(self, relative: str, value: Any) -> Path:
        """Replace a record atomically; reported failures preserve the old value."""
        payload = self._encode(value)
        target = self.safe_path(relative, create_parents=True)
        parent = target.parent
        temp_path: Path | None = None
        rollback_path: Path | None = None
        replaced = False
        try:
            temp_path = self._write_temp(parent, payload)
            self._check_existing_target(target)
            rollback_path = self._hold_old_record(target)
            new_identity = self._file_identity(temp_path)
            self._replace(str(temp_path), str(target))
            temp_path = None
            replaced = True
            try:
                self._sync_parent(parent)
            except Exception as exc:
                try:
                    self._rollback_replacement(target, rollback_path, new_identity)
                except StorageCommitUnknown:
                    # The old inode remains at rollback_path when possible;
                    # do not delete that evidence or claim the target is old.
                    rollback_path = None
                    raise
                rollback_path = None
                raise StorageError("record write rolled back after directory sync failure") from exc
            self._discard_path(rollback_path)
            rollback_path = None
            return target
        except StorageCommitUnknown:
            raise
        except StorageError:
            raise
        except Exception as exc:
            raise StorageError("atomic record write failed") from exc
        finally:
            self._discard_path(temp_path)
            if not replaced:
                self._discard_path(rollback_path)

    def write_once(self, relative: str, value: Any) -> Path:
        """Publish an immutable record; an existing record is never overwritten."""
        payload = self._encode(value)
        target = self.safe_path(relative, create_parents=True)
        parent = target.parent
        temp_path: Path | None = None
        try:
            temp_path = self._write_temp(parent, payload)
            self._check_existing_target(target)
            try:
                self._link(str(temp_path), str(target))
            except FileExistsError as exc:
                raise RecordExists("immutable record already exists") from exc
            temp_path.unlink()
            temp_path = None
            self._sync_parent(parent)
            return target
        except RecordExists:
            raise
        except StorageError:
            raise
        except (OSError, ValueError) as exc:
            raise StorageError("immutable record creation failed") from exc
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink()
                except FileNotFoundError:
                    pass
                except OSError:
                    pass

    def read_json(self, relative: str) -> Any:
        target = self.safe_path(relative)
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(target, flags)
        except FileNotFoundError as exc:
            raise RecordNotFound("record is unavailable") from exc
        except OSError as exc:
            raise StorageError("record could not be opened safely") from exc
        try:
            info = os.fstat(fd)
            if not _is_regular(info.st_mode) or info.st_size > self.max_bytes:
                raise StorageError("record is not a bounded regular file")
            chunks: list[bytes] = []
            remaining = self.max_bytes + 1
            while remaining > 0:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > self.max_bytes:
                raise StorageError("record exceeds the read limit")
            try:
                return strict_json_loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ModelError) as exc:
                raise StorageError("record contains invalid JSON") from exc
        except StorageError:
            raise
        except OSError as exc:
            raise StorageError("record could not be read") from exc
        finally:
            os.close(fd)

    def write_record(self, relative: str, model_name: str, value: Any) -> Path:
        try:
            validate_model(model_name, value)
        except Exception as exc:
            if isinstance(exc, (ModelError, RuntimeError)):
                raise
            raise ModelError("model validation failed") from exc
        return self.write_json(relative, value)

    def write_immutable_record(self, relative: str, model_name: str, value: Any) -> Path:
        validate_model(model_name, value)
        return self.write_once(relative, value)

    def read_record(self, relative: str, model_name: str) -> Any:
        value = self.read_json(relative)
        try:
            return validate_model(model_name, value)
        except Exception as exc:
            if isinstance(exc, RuntimeError) and not isinstance(exc, ModelError):
                raise
            raise StorageError("stored record failed schema validation") from exc

    def record_path(self, directory: str, record_id: str) -> str:
        """Build a safe ``directory/<id>.json`` name without accepting path input."""
        if not isinstance(directory, str) or not directory:
            raise StorageError("record directory is required")
        if not isinstance(record_id, str) or not record_id or "/" in record_id or "\\" in record_id:
            raise StorageError("record ID is not safe")
        relative = f"{directory}/{record_id}.json"
        self.safe_path(relative, create_parents=True)
        return relative


# Short aliases keep later consumers from inventing separate storage formats.
Storage = AtomicJsonStore


__all__ = [
    "AtomicJsonStore",
    "RecordExists",
    "RecordNotFound",
    "Storage",
    "StorageCommitUnknown",
    "StorageError",
]
