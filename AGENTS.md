# Agent guidance for Thin OPS

## Contract and authorization

- The current GitHub Issue body is the Contract SSOT, with Original Intent before Contract. Chat history is not authorization.
- Before work starts, read the current Issue: it must be OPEN, and the latest `approved` label event (accounting for removal and re-addition) must be by an Actor independent of the author and Developer, at or after the last body edit. A label alone is not enough. Recheck the Contract before any remote write.
- Developer identity is `g-lite-developer[bot]` / App ID `5017695`; independent Reviewer identity is `g-lite-reviewer[bot]` / App ID `5010632`. Never mix credentials or use the Reviewer account for development or push.
- Human Authority is the human repository controller. Genesis, governance changes, and the final squash merge stay human-controlled.
- Local Bootstrap configures identity only; GitHub is the SSOT for Issue, PR, review, check, and merge state. This repository has no local task/review/merge state.
- Current status is `ACTIVE`; consumer Required Check is `unit`.

## GitHub-native flow

Use ordinary `git` and `gh` commands only:

```text
Issue Contract → branch/worktree → PR → CI → independent Review → squash merge
```

Developer must authenticate as its own App, verify commit author/committer, and use App-authenticated HTTPS for fetch and push with global Git URL rewrites isolated; do not fall back to human or Reviewer credentials. Before proposing a PR, fetch current `main` and verify it is an ancestor of HEAD. Required checks (including `unit`) and independent Reviewer approval must apply to the current PR HEAD; changes to HEAD require new checks and Review. Only Human Authority authorizes the final squash merge through GitHub gates. Do not add a parallel workflow language or bypass review. This repository is public; private runtime configuration belongs in a separate private store or repository.

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
