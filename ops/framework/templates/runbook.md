# Runbook

## Purpose

`<what this procedure accomplishes>`

## Before starting

- [ ] The Contract or change request is approved independently.
- [ ] An explicit target and exact `--limit` selection are recorded.
- [ ] Target facts are current, consistent, and not retired.
- [ ] Primary/standby scope is intentional and does not write both by default.
- [ ] Platform, NAT/offload, proxy-only, and unmanaged-host boundaries are known.
- [ ] A concurrency lock or equivalent coordination is active.
- [ ] Required human approval exists for a high-risk fixed action or destructive purge.
- [ ] Secrets are available only through the approved external mechanism.

## Fixed path

`Human / Agent → Semaphore → Ansible`

Record the selected mature-tool job and its external history. Do not add an arbitrary shell wrapper or silently expand the target.

## Exploratory path

`Agent → Service Card / Runbook → Komari / Central Logs / Semaphore History → SSH / API / CLI`

Use observations as evidence, not as a substitute for target validation. A paused service is not automatically restarted, and an unmanaged machine is not silently added to Ansible management.

## Procedure

1. Validate target, facts, approval, and concurrency state.
2. Perform the smallest reversible action supported by the selected mature tool.
3. Observe the stated success criteria.
4. Stop and report if facts conflict, evidence is missing, or the target changes.

## Recovery and closeout

- Recovery/rollback: `<explicit safe action or “blocked pending human decision”>`
- Evidence: `<external history or log reference>`
- Follow-up: `<owner and next review>`
