# Reusable modules

No module is shipped by this reset. Add a module only when a generic need is repeated, a reviewed Contract defines its boundary, and mature tools cannot provide the same capability with less risk.

A module must stay independent of personal inventory, credentials, runtime state, and site-specific facts. It must document target selection, platform and NAT/offload constraints, approval needs, concurrency behavior, verification, and rollback. Do not turn this directory into a replacement control plane.
