# Hub integrations

This directory documents boundaries to mature operational systems. It does not deploy or embed those systems.

- Semaphore coordinates approved fixed jobs.
- Ansible owns fixed host execution and its normal target/`--limit` discipline.
- Komari and Central Logs provide exploratory observations.
- Semaphore History records fixed-job evidence.
- Restic remains an external backup tool and its state stays outside Git.
- SSH, API, and CLI are endpoint channels selected by a reviewed Service Card or Runbook.

Connection details, inventories, tokens, private keys, service databases, and live output belong in private runtime storage. This boundary does not introduce a Gateway, Broker, plan engine, approval service, or arbitrary command wrapper.
