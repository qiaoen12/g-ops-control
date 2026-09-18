#!/usr/bin/python3
"""Template entrypoint for the root-owned OPS-005 broker.

Install this file as ``/usr/local/libexec/ops-control/broker`` with owner
``root:root`` and mode ``0755``.  The only permitted caller is the exact
sudoers rule for ``ops-call -> ops-exec``; the broker accepts Request v1 on
stdin and has no command-line options.  A release is a complete workspace
bundle, so this wrapper imports only the fixed package path below; it never
uses caller-controlled ``PYTHONPATH`` or command-line paths.
"""

import sys
from pathlib import Path


_PACKAGE_ROOT = Path("/opt/ops-control/current/1-code/ops-control")
if not _PACKAGE_ROOT.is_dir():
    raise SystemExit("ops-control broker: fixed release package is unavailable")
sys.path.insert(0, str(_PACKAGE_ROOT))

from ops.executor.broker import main


if __name__ == "__main__":
    raise SystemExit(main())
