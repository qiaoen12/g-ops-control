# Thin OPS V4 architecture

## Purpose

Thin OPS is the public, canonical software layer for safe operations guidance. It keeps the reusable parts small: framework rules, templates, mature-tool integration boundaries, future reusable modules, a sanitized example, and CI/ADR evidence.

The public repository is `qiaoen12/ops-control`. Private runtime repositories or stores may consume a reviewed public tag, but they remain the source of real inventory, connection details, credentials, secrets, live state, logs, and service databases.

## Execution boundaries

The fixed path is:

```text
Human / Agent → Semaphore → Ansible
```

The exploratory path is:

```text
Agent → Service Card / Runbook → Komari / Central Logs / Semaphore History → SSH / API / CLI
```

The paths are intentionally tool-oriented. Thin OPS does not add a self-built Gateway/Broker/Approval control plane, dynamic router, API, plan engine, or general shell wrapper. Mature systems own execution, state, approval history, observation, and backup state in their normal boundaries.

## Safety invariants

Cards and runbooks should express these generic constraints where relevant:

- require an explicit target and exact target/`--limit` selection;
- deny by default when facts are uncertain or conflict;
- never target a retired host;
- do not write primary and standby together by default;
- require human approval for high-risk fixed actions;
- keep secrets out of public requests and configuration;
- treat destructive purge as a separately approved action, not ordinary cleanup;
- validate targets before upgrades and protect concurrent work;
- record NAT, mainland/offload, proxy-only, and Linux/Windows boundaries;
- do not blindly restart paused services;
- do not silently make unmanaged machines Ansible-managed.

These are reusable safety rules, not a new runtime contract. Live facts are evaluated by the operator’s private systems at execution time.

## Ownership and history

Git, Issues, and PRs preserve public design history and deleted implementation history. Runtime data remains outside Git. The old control-plane implementation is not a compatibility dependency, and this reset does not deploy or change any external operational system.
