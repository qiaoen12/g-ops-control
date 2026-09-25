# Agent guidance for Thin OPS

## Contract and authorization

- The current GitHub Issue body is the Contract SSOT, with Original Intent before Contract. Chat history is not authorization.
- Before work starts, read the current Issue: it must be OPEN, and the latest `approved` label event (accounting for removal and re-addition) must be by an Actor independent of the author and Developer, at or after the last body edit. A label alone is not enough. Recheck the Contract before any remote write.
- Developer identity is `g-lite-developer[bot]` / App ID `5017695`; independent Reviewer identity is `g-lite-reviewer[bot]` / App ID `5010632`. Never mix credentials or use the Reviewer account for development or push.
- Human Authority is the human repository controller. Genesis, governance changes, and the final Squash merge stay human-controlled.
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
<!-- g-lite:managed protocol start -->
# Agent protocol

This repository uses the G-lite GitHub-native protocol.

## Contract

For new tasks, record Original Intent (the user's words or a fixed PRD reference) before the Issue Contract containing Goal, Acceptance, Out of scope, and Authorization. This version does not require reconciler to audit older consumers for Original Intent.

Before development and again before PR review, read the current OPEN Issue Contract, author/editor, lastEditedAt, current approved label and latest approved label event (actor and timestamp). Missing approval is INVALID; lastEditedAt absent or <= approvedAt is FRESH; later edits are STALE. Stop if facts cannot be verified or authorization is invalid/stale. The Actor that writes or materially edits the current Contract version cannot approve it. Reauthorization requires independent fresh approved; do not cache authorization.

## Roles

- Main coordinates the Issue → Developer → CI → independent Reviewer → rework → merge flow; it is not another GitHub Actor and must not write the Developer's PR branch. It may mechanically merge with Human Authority credentials only after that human explicitly authorizes the current task.
- Developer Actor: machine identity / GitHub App; may create/edit Contracts, develop, push, and open/update PRs within fresh authorized scope. It must not approve its own Contract, provide its own Required Review, or merge.
- Reviewer Actor: independent machine identity / GitHub App; may independently add approved and review the current PR HEAD with APPROVE / REQUEST_CHANGES. It must not develop, push, change repository governance, or merge.
- Developer and Reviewer must not independently change the Ruleset / governance that constrains them.
- Human Authority: one or more human accounts with appropriate permissions on this repository. After GitHub gates pass, it may perform final Squash merge through GitHub UI, CLI, API, or tools under its explicit instruction.
- Concrete account/App bindings are replaceable per consumer; no canonical username or App is required. Verify both Apps' identities, independence, and installation access externally. Do not add a Merge Bot / Merge Executor or identity registry.

## Genesis / ACTIVE

Human Authority controls Genesis: create the repository, install/authorize both Apps, establish initial protocol files and CI, configure Ruleset / governance / security, and verify ACTIVE readiness. Tools may execute under Human Authority's identity and authorization; this does not grant Developer administrator powers.

In ACTIVE, Developer + Reviewer handle daily tasks; Human Authority intervenes at governance boundaries or final merge.

## Local Bootstrap

Local Bootstrap ≠ Repository Task. Local App private key installation/rotation, ~/.config/g-lite/ credential directories, token helpers, shell identity bootstrap, read-only identity preflight, and new-machine identity setup need no Issue Contract. They do not authorize changing repository durable facts; repository changes enter the appropriate lifecycle.

In each checkout that uses the local credential entry, first add `.g-lite-local/` to that checkout's Git local exclude (locate it with `git rev-parse --git-path info/exclude`). Then create a `.g-lite-local/credentials` symlink to the actual machine credential root. Neither the symlink nor its target belongs in Git; do not change repository `.gitignore` or assume fixed Developer / Reviewer private-key file layouts. Verify the entry is ignored and a previously clean `git status` remains clean.

Developer / Reviewer use short-lived Installation Access Tokens. Never put private keys, JWTs, tokens, or PATs in repo, Issue, PR, evidence logs, or canonical state; do not persist tokens in state files. Local credentials stay in external secure mechanisms, outside canonical runtime.

For Developer / Reviewer operations, first invoke the configured role entry available in the current workspace / machine. The role entry must live-verify the expected API Actor and target repository access; credential paths, environment variables, or a human `gh` login do not establish identity. An Actor or access mismatch is `BLOCK`: stop the role action, do not guess private-key layouts or attempt temporary authentication, and do not fall back to Human identity.

Only when no callable role entry is available, inspect `.g-lite-local/credentials` and the machine-local `~/.config/g-lite/` entry for minimal existence, type, and accessibility metadata. Do not enumerate or display credential contents, or record private keys, JWTs, tokens, PATs, or resolved machine-specific credential absolute paths in the repository, Issue, PR, evidence logs, or canonical state.

Verify API Actor, commit author, and Git transport separately. Developer clone/fetch/push uses App HTTPS credentials. Before each operation verify the effective HTTPS remote and absence of applicable insteadOf rewrite: user/global Git config can silently turn HTTPS into human SSH authentication. Prefer task-process config/credential isolation, inspect repo-local config, and preserve existing user global Git / SSH settings.

Human, Developer, and Reviewer credentials may coexist on one Mac. Before each key GitHub / Git action verify the actual API Actor, transport, and role. Developer must not push/merge as Human Authority; Reviewer must not Review as Developer or Human Authority. Stop an action on identity mismatch. Physical credential isolation is future hardening, not a v3.4 Freeze condition.

## GitHub facts

GitHub is the source of truth for Issue authorization, PR, Checks, Review, Ruleset, merge eligibility, and merge result. Do not create local task, review, merge, or approval state or a second GitHub database.

The default branch requires PRs, at least one independent approval, stale review dismissal, a stable consumer-owned Required Check, squash-only merge, and no routine bypass. Enable Secret scanning / Push protection where supported. Consumer CI is owned by this repository and its Agent; G-lite does not generate or select it. Reconciler App assertions are invocation-only, require external verification of both roles, and do not authorize governance writes or manage credentials.

## Main delivery SOP

1. Main follows CI and Review. Failed CI or REQUEST_CHANGES returns to Developer for in-scope repair and a new HEAD.
   Wait for Required Checks on that HEAD and independent Reviewer re-review.
2. Before merge, read live main SHA B and PR HEAD H; prove B is an ancestor of H with GitHub compare
   or `git merge-base --is-ancestor`. On mismatch, Main does not update the PR branch.
   Developer uses App identity to update main/rebase/merge base and push a new HEAD;
   only Developer may run `gh pr update-branch` when it writes the branch. Repeat CI, Review, and preflight.
3. `merge-authorized` is an optional one-time Genesis prerequisite for automatic completion.
   On explicit task-level instruction from Human Authority, Main verifies that human API Actor and creates/applies the label if absent.
   Reconciler bootstrap does not create it. Without fresh label, ask Human Authority again before final merge;
   Developer-authored Issue text does not grant merge permission.
4. For automatic merge, verify the label is still attached, its latest LabeledEvent Actor is an authorized human,
   its createdAt is no earlier than Issue body lastEditedAt, and authorization has not been revoked.
5. Preflight live GitHub facts: OPEN Issue, current Contract with independent fresh approved,
   OPEN non-draft PR targeting main, B ancestor of H, Required Checks PASS and independent APPROVE on H,
   and merge eligibility. Re-read B, H, authorization, and gates immediately before merge;
   verify Human Authority API Actor, then squash merge with expected H (`gh pr merge --squash --match-head-commit H`).
   Read merged state, merge commit SHA, and Issue state; report Checks, Review, and unverified items.
   Without a strict latest-base Ruleset, main can advance between the last read and merge.
6. Ask Human Authority for scope changes, unverifiable identity/authorization/gates, governance or high-impact actions,
   or about three failures on one path without new evidence. Continue routine CI and Review rework within scope.
<!-- g-lite:managed protocol end -->
