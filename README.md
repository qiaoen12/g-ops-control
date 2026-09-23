# Thin OPS

Thin OPS is a small, public operations framework: reusable safety rules, service-card and runbook templates, mature-tool integration guidance, and sanitized examples. It describes how an operator should make a change without becoming another operations control plane.

Public software: `qiaoen12/g-ops-control`.
The canonical public software repository is `qiaoen12/g-ops-control`. It owns:

- framework guidance and reusable templates;
- reusable modules when a real, repeated need justifies one;
- hub integration definitions for mature tools;
- a fictional example site;
- tests, CI, and architecture decisions.

It does not own real VPS or host identity, IPs, domains, usernames, ports, personal inventory, credential profiles, secrets, live runtime state, task output, or service databases. Private runtime configuration stays outside this repository and may consume a reviewed public tag.

## Execution paths

Fixed work follows:

```text
Human / Agent → Semaphore → Ansible
```

Exploratory work follows:

```text
Agent → Service Card / Runbook → Komari / Central Logs / Semaphore History → SSH / API / CLI
```

These paths use existing tools and explicit boundaries. There is no self-built Gateway/Broker/Approval control plane, dynamic router, or replacement Python runtime here.

## Safety shape

Every change names an explicit target and validates current facts before execution. Conflicting or uncertain facts deny by default; retired targets are not eligible; primary and standby are not written together by default; high-risk fixed actions require human approval; secrets never enter a public request or configuration; and destructive purge is not ordinary cleanup. Target/`--limit` discipline, concurrency protection, platform boundaries, NAT/offload constraints, proxy-only responsibility, paused-service handling, and unmanaged-host boundaries belong in the relevant card or runbook.

Runtime data is outside Git. The repository keeps only generic guidance and fictional examples.

## Layout

| Path | Role |
| --- | --- |
| `ops/framework/` | Framework guidance and templates |
| `ops/modules/` | Future reusable modules, only when justified |
| `ops/hub/` | Boundaries for Semaphore, Ansible, observability, and backup integrations |
| `ops/sites/example/` | Minimal fictional site example |
| `docs/` | Architecture and ADRs |
| `tests/` | Structure and public-safety checks |

G-lite v3.4 binding:

- The GitHub Issue body is the Contract SSOT: record Original Intent before Contract. Start only from an OPEN Issue whose latest `approved` label event comes from an independent Actor and is not older than its last body edit; recheck before remote writes.
- Developer: `g-lite-developer[bot]` / App ID `5017695`; Reviewer: `g-lite-reviewer[bot]` / App ID `5010632`. They use separate App identities; neither self-approves or substitutes for Human Authority.
- Developer fetches/pushes via its App over HTTPS, verifies commit identity, and isolates Git transport from global URL rewrites. Before PR, check that current `main` is an ancestor of the proposed HEAD; checks and independent Review must apply to that HEAD. A new commit needs fresh checks and Review.
- Human Authority: the human repository controller owns Genesis, governance, and the final squash merge through GitHub gates.
- Local Bootstrap configures identity only; GitHub is the SSOT for Issue, PR, review, check, and merge state.
- Status: ACTIVE; Required Check: `unit`.

Run the local CI-equivalent check from the repository root:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```
