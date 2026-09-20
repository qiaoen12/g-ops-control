# Thin OPS framework

This directory contains generic operating guidance and templates. It is documentation and policy shape, not a daemon, API, broker, approval service, inventory, or execution runtime.

Use a Service Card to describe an operation before it is considered for a fixed or exploratory path. Use a Runbook to make preconditions, target selection, execution, verification, and recovery explicit. Keep secrets, connection facts, live state, and site-specific inventory outside this repository.

The framework assumes mature tools own execution:

- fixed changes are coordinated by Semaphore and executed by Ansible;
- exploratory work uses a card/runbook, existing observations, and an explicitly selected SSH/API/CLI endpoint;
- Komari, Central Logs, Semaphore History, and Restic remain external systems whose runtime data is not stored here.

The policy and catalog templates express guardrails without defining a new runtime format. A future module or runtime needs a separately approved Contract and repeated Pilot evidence.
