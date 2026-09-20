# Service Card

Use this card to describe one reusable operation or service boundary. It is not an inventory record and must not contain credentials or live runtime output.

## Identity

- Name: `<generic-service-name>`
- Owner: `<team-or-role>`
- Change class: `<fixed | exploratory>`
- Risk: `<low | medium | high>`

## Target

- Explicit target: `<required target identifier>`
- Target source and freshness: `<source and timestamp>`
- Lifecycle: `<active | retired | unknown>`
- Platform boundary: `<linux | windows | other>`
- Primary/standby scope: `<single role or explicitly reviewed set>`

If the target is missing, retired, uncertain, or supported facts conflict, stop and deny the operation.

## Intent and controls

- Intended outcome: `<one sentence>`
- Preconditions: `<facts that must be true>`
- `--limit` / target selection: `<exact selection rule>`
- Concurrency protection: `<lock or coordination rule>`
- Human approval: `<not required | required before execution>`
- Destructive action: `<none | explicitly described and approved>`

## Execution and evidence

- Fixed path: `Human / Agent → Semaphore → Ansible`
- Exploratory path: `Agent → Service Card / Runbook → existing observations → SSH / API / CLI`
- Verification: `<observable success criteria>`
- Rollback or stop condition: `<safe recovery or explicit blocker>`
- Evidence location: `<external system or link; never a secret>`

## Secrets and boundaries

Reference a secret by an external name only. Never place a secret, private key, personal host fact, or credential value in this card. Record NAT/offload, proxy-only, paused-service, unmanaged-host, and Linux/Windows constraints when they apply.
