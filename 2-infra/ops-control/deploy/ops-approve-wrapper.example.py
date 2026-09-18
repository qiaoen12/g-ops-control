#!/usr/bin/python3
"""Template entrypoint for the independent ops-approve service UID.

The wrapper must be installed and owned by the independent maintenance
procedure.  It refuses to start when the process does not own the approval
state and trusted credential roots, so ops-call cannot turn this into a
general management entrypoint. The release is a complete workspace and is
imported from the fixed package path below; caller environment and
command-line paths are not consulted.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_PACKAGE_ROOT = Path("/opt/ops-control/current/1-code/ops-control")
if not _PACKAGE_ROOT.is_dir():
    raise SystemExit("ops-approve: fixed release package is unavailable")
sys.path.insert(0, str(_PACKAGE_ROOT))

from ops.approval.server import main


def _owned_by_process(path: Path) -> bool:
    try:
        return path.stat().st_uid == os.geteuid()
    except OSError:
        return False


if __name__ == "__main__":
    approval_root = Path("/var/lib/ops-control/approvals")
    counter_root = Path("/etc/ops-control/webauthn/trusted/counters")
    metadata_root = Path("/etc/ops-control/webauthn/trusted/metadata")
    if not (_owned_by_process(approval_root) and _owned_by_process(counter_root) and not _owned_by_process(metadata_root)):
        raise SystemExit("ops-approve: independent approval UID ownership check failed")
    raise SystemExit(main())
