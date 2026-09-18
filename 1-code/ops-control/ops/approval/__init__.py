"""Independent loopback approval primitives for OPS-005.

The approval package is intentionally separate from the ordinary gateway.  A
gateway caller can request a session, but only the loopback WebAuthn service
can publish a trusted Approval record.
"""

from .service import ApprovalError, ApprovalService, ApprovalSession, WebAuthnConfig
from .store import (
    ApprovalStore,
    CredentialRecord,
    FileCredentialStore,
    MaintenanceContext,
    MemoryCredentialStore,
    TrustedApprovalProvider,
)

__all__ = [
    "ApprovalError",
    "ApprovalService",
    "ApprovalSession",
    "ApprovalStore",
    "CredentialRecord",
    "FileCredentialStore",
    "MaintenanceContext",
    "MemoryCredentialStore",
    "TrustedApprovalProvider",
    "WebAuthnConfig",
]
