---
name: Contract
about: Propose a scoped, reviewable change
title: ""
labels: ""
assignees: ""
---

## Original Intent

What did the requester originally ask for? Preserve their wording before refining the Contract.

## Contract

### Goal

What concrete outcome is requested?

### Scope

What paths and behavior are in scope?

### Out of scope

What must not be changed or added in this task?

### Safety and public boundary

- Does this keep real infrastructure facts, credentials, and runtime state outside the public repository?
- What target, approval, conflict, concurrency, and rollback boundaries apply?

### Acceptance

How will the result be verified, including the required CI check?

### Authorization

The author must not approve the same Contract. The independent `g-lite-reviewer[bot]` adds `approved` only after reading the final Issue body; Developer and Reviewer remain separate.
<!-- g-lite:managed protocol start -->
### G-lite delivery lifecycle

For medium-or-larger work, record an Implementation & Verification Plan in the Contract.

- Keep the primary checkout on default/main; make task edits in one dedicated native Git worktree on one writable task branch.
- Reach LOCAL GREEN before opening the PR.
- REVIEW-READY requires the intended PR HEAD, CI GREEN for that current HEAD, and no unresolved Contract blocker.
- An independent Reviewer reviews the current Contract and PR HEAD.
- Human Authority performs the final Squash merge after required gates pass.
<!-- g-lite:managed protocol end -->
