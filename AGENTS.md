# Agent guidance for Thin OPS

## Contract and authorization

- The current GitHub Issue body is the Contract SSOT. Chat history is not authorization.
- Before work starts, read the current Issue and verify that it is open, the `approved` label is present, and the approval is fresh and independent. Recheck the Contract before any remote write.
- Developer identity is `qiaoen12`; independent Reviewer identity is `qiaoen-reviewer`. Never mix credentials or use the Reviewer account for development or push.

## GitHub-native flow

Use ordinary `git` and `gh` commands only:

```text
Issue Contract → branch/worktree → PR → CI → independent Review → squash merge
```

Required GitHub checks and rulesets are the merge gates. Do not add a parallel workflow language or bypass review. This repository is public; private runtime configuration belongs in a separate private store or repository.

## Where work belongs

- Put framework rules and generic templates in `ops/framework/`.
- Put a reusable module in `ops/modules/` only after a reviewed Contract establishes the need.
- Put mature-tool integration boundaries in `ops/hub/`; do not implement a new control plane there.
- Put only fictional, sanitized examples in `ops/sites/example/`.
- Put architecture rationale and decisions in `docs/`.

Do not add real personal facts: no production IPs, domains, hostnames, usernames, ports, inventory, credential profiles, secrets, or runtime output. Do not commit personal notes, `5-record/`, or private historical files.

## Architecture guardrails

Thin OPS uses Semaphore and Ansible for fixed execution, and Service Cards/Runbooks plus existing observability and endpoint tools for exploratory work. Do not add a replacement Gateway, Broker, Plan, Approval, Router, API, or Python runtime. Do not copy old runtime schemas, wrappers, fixtures, or inventory as a compatibility layer.

A future self-built runtime requires a new approved Contract and repeated Pilot evidence. The proposal must answer all five questions:

1. How many times has the real problem repeated?
2. Why are Agent + SSH/API/CLI insufficient?
3. Why are Semaphore and Ansible insufficient?
4. Why are Komari, Logs, and Restic insufficient?
5. What concrete loss follows from not developing it?

If those answers are not clear, do not develop the runtime.

## Verification

Run the same entry point used by CI from the repository root:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

Also check `git diff --check`, confirm that `1-code/` and `2-infra/` do not exist, and scan the current tree for personal facts or secret material before opening a PR.
