#!/usr/bin/python3
"""Template launcher for the root-owned OPS-004 forced command.

Install this file as ``/usr/local/libexec/ops-control/ops-call`` from a
reviewed release, with owner ``root:root`` and mode ``0755``. The SSH key
line invokes it through the fixed ``/usr/bin/python3 -E -s`` interpreter;
the key line, not the client, supplies the only accepted ``--credential-id``.
The release is a complete workspace and this wrapper imports only its fixed
package path; caller environment and command-line paths are not consulted.
"""

import sys
from pathlib import Path


_PACKAGE_ROOT = Path("/opt/ops-control/current/1-code/ops-control")
if not _PACKAGE_ROOT.is_dir():
    raise SystemExit("ops-control gateway: fixed release package is unavailable")
sys.path.insert(0, str(_PACKAGE_ROOT))

from ops.executor import main


if __name__ == "__main__":
    raise SystemExit(main())
