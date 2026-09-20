# ADR: Thin OPS V4 reset

Status: accepted by Issue #9; implementation follows the approved Contract.

## Decision

Perform a one-time reset to the final Thin OPS V4 public shape. Remove the old OPS-001–005 self-built control plane and the old infrastructure expression from the current tree. Keep only generic, durable safety knowledge as documentation, templates, and lightweight structure tests.

## Why the old control plane is retired

The old implementation accumulated a custom execution path, runtime records, approval plumbing, inventory abstractions, wrappers, and mirrored infrastructure expression before repeated Pilots proved that this software boundary was needed. That created a second source of truth beside mature tools and made private runtime facts too easy to confuse with public software. A transition architecture would preserve that confusion, so no compatibility layer is retained.

Names such as Gateway, Broker, Approval Store, Plan runtime, LaunchRecord, and UseRecord describe deleted historical components only. They are not current interfaces or implementation targets.

## Mature tools first

Semaphore and Ansible already provide the fixed execution path and job history. Komari and Central Logs provide observations for exploratory work, while SSH/API/CLI remain explicit endpoint channels. Restic remains an external backup tool. Reusing those boundaries keeps execution, state, and credentials where their operators already understand them instead of rebuilding a smaller and less proven control plane.

## Public software and private runtime

The public repository contains reusable rules, templates, modules when justified, hub boundaries, tests, ADRs, and a fictional example. Real hosts, IPs, domains, usernames, ports, personal inventory, credential profiles, secrets, runtime state, service databases, logs, task output, and backup state remain private and outside Git. This separation lets an unrelated operator reuse the public software without receiving personal topology.

## No runtime-schema migration

Old JSON schemas, fixtures, wrappers, and runtime records are not a public compatibility target. Migrating them would preserve the old control-plane contract under new names and would imply a runtime that this Contract explicitly removes. The new templates are human-readable guidance, not a replacement serialization or API schema.

## History

The old implementation and its OPS-001–005 development history remain recoverable through Git history, the Issue, and PRs. The private `qiaoen12/g-lite-ops` repository at the approved migration-source revision was read only for generic lessons; it is not a dependency, source copy, or synchronized repository and should be archived separately after this reset is accepted.

## Knowledge retained

The reset retains only generic safety knowledge: explicit targets; deny-by-default handling for uncertainty and conflicting facts; retired-target rejection; primary/standby write separation; human approval for high-risk fixed actions; external-only secret references; separate destructive purge approval; target/`--limit` discipline; pre-upgrade validation; concurrency protection; NAT/offload and mainland boundaries; Linux/Windows separation; proxy-only responsibility; paused-service handling; and the rule that unmanaged machines do not silently become Ansible-managed.

## Admission gate for future runtime work

No new self-built runtime is admitted by implication. A future proposal needs a new approved Contract and repeated Pilot evidence, and must answer:

1. How many times has the real problem repeated?
2. Why are Agent + SSH/API/CLI insufficient?
3. Why are Semaphore and Ansible insufficient?
4. Why are Komari, Logs, and Restic insufficient?
5. What concrete loss follows from not developing it?

If any answer is unclear, the correct decision is not to develop.

## Scope and non-goals

This reset does not deploy Semaphore, Komari, Central Logs, or Restic; import real inventory; implement service-specific upgrade automation; add an API, router, approval engine, arbitrary shell wrapper, or v2.3 catalog; or modify a production machine. It changes only the public repository tree and its CI/architecture guidance.
