"""Trusted, non-request-controlled resource discovery.

The CLI deliberately exposes no ``--root``/``--policy`` option.  Production
callers construct a provider from trusted configuration; source-tree use
derives the workspace from this package's location and verifies the expected
layout.  Tests may inject an explicit temporary provider.
"""

from __future__ import annotations

import stat
from dataclasses import dataclass
from pathlib import Path


class ResourceError(RuntimeError):
    """Raised when a trusted resource root is missing or unsafe."""

    code = "source_unavailable"


_ALLOWED_RESOURCES = frozenset(
    {
        "actions/manifest.yml",
        "policy/logging.yml",
        "policy/credential-refs.yml",
        "policy/machine-classes.yml",
        "policy/special-rules.yml",
        "inventory/management.yml",
        "ansible/inventories/lab/hosts.ini",
        "identity/mapping.yml",
    }
)


def _safe_directory(path: Path, *, label: str) -> Path:
    path = Path(path)
    try:
        stat = path.lstat()
    except FileNotFoundError as exc:
        raise ResourceError(f"{label} is unavailable") from exc
    if not path.is_dir() or path.is_symlink():
        raise ResourceError(f"{label} is not a trusted directory")
    if stat.st_mode & 0o022:
        raise ResourceError(f"{label} is writable by group or other users")
    return path


@dataclass(frozen=True)
class TrustedResourceProvider:
    """Resolve the small allowlisted set of sanitized infra references."""

    infra_root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "infra_root", _safe_directory(Path(self.infra_root), label="infra root"))

    @classmethod
    def from_package(cls) -> "TrustedResourceProvider":
        # In a source checkout: <workspace>/1-code/ops-control/ops/resources.py.
        # This is derived, not a machine-specific absolute path.
        package_root = Path(__file__).resolve().parents[1]
        if package_root.name == "ops-control" and package_root.parent.name == "1-code":
            workspace_root = package_root.parents[1]
            return cls(workspace_root / "2-infra" / "ops-control")

        # A wheel installed into a clean venv has no sibling infra tree.  When
        # it is deliberately run from a checked-out G-lite workspace, accept
        # that workspace only after verifying its marker and expected code
        # layout; an arbitrary cwd is never enough.
        current = Path.cwd().resolve()
        for candidate in (current, *current.parents):
            if (
                (candidate / "AGENTS.md").is_file()
                and (candidate / "1-code" / "ops-control" / "ops").is_dir()
                and (candidate / "2-infra" / "ops-control").is_dir()
            ):
                return cls(candidate / "2-infra" / "ops-control")
        raise ResourceError("package has no trusted sibling infra resource root")

    def path(self, relative: str) -> Path:
        if relative not in _ALLOWED_RESOURCES:
            raise ResourceError("resource is not allowlisted")
        target = self.infra_root / relative
        current = self.infra_root
        for part in Path(relative).parts:
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError as exc:
                raise ResourceError(f"resource {relative} is unavailable") from exc
            if current.is_symlink() or (current.is_file() and part != Path(relative).name):
                raise ResourceError(f"resource {relative} crosses an unsafe link")
            if part == Path(relative).name:
                if not current.is_file() or not stat.S_ISREG(info.st_mode):
                    raise ResourceError(f"resource {relative} is not a regular file")
                if info.st_mode & 0o022:
                    raise ResourceError(f"resource {relative} is writable by group or other users")
            elif current.is_dir() and info.st_mode & 0o022:
                raise ResourceError(f"resource {relative} crosses a writable directory")
        return target

    def relative_path(self, relative: str, *, root: str, suffix: str | None = None) -> Path:
        """Resolve a manifest-controlled file under one trusted resource root.

        The caller supplies a path from a trusted release manifest, never from
        a Request or CLI option.  The method intentionally repeats the
        component-by-component link and traversal checks used by ``path`` so
        descriptor and adapter files cannot escape their allowlisted roots.
        """
        if not isinstance(relative, str) or not relative or "\\" in relative:
            raise ResourceError("resource reference is not a safe relative path")
        candidate = Path(relative)
        if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
            raise ResourceError("resource reference contains an unsafe component")
        if suffix is not None and candidate.suffix != suffix:
            raise ResourceError("resource reference has an unsupported suffix")
        root_path = self.infra_root / root
        _safe_directory(root_path, label=f"{root} root")
        current = root_path
        for part in candidate.parts:
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError as exc:
                raise ResourceError("resource reference is unavailable") from exc
            if current.is_symlink():
                raise ResourceError("resource reference crosses an unsafe link")
            if current.is_dir():
                if info.st_mode & 0o022:
                    raise ResourceError("resource reference crosses a writable directory")
                continue
            if not current.is_file() or not stat.S_ISREG(info.st_mode):
                raise ResourceError("resource reference is not a regular file")
            if info.st_mode & 0o022:
                raise ResourceError("resource reference is writable by group or other users")
        return current

    def action_manifest_path(self) -> Path:
        return self.path("actions/manifest.yml")

    def action_descriptor_path(self, relative: str) -> Path:
        return self.relative_path(relative, root="actions", suffix=".yml")

    def action_adapter_path(self, relative: str) -> Path:
        return self.relative_path(relative, root="actions", suffix=None)

    def identity_mapping_path(self) -> Path:
        """Return the one fixed maintenance-owned identity mapping path."""

        return self.path("identity/mapping.yml")

    def read_text(self, relative: str, *, max_bytes: int = 1 << 20) -> str:
        target = self.path(relative)
        if target.stat().st_size > max_bytes:
            raise ResourceError(f"resource {relative} exceeds the read limit")
        return target.read_text(encoding="utf-8")


__all__ = ["ResourceError", "TrustedResourceProvider"]
