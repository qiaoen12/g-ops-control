# ops-control

Public operations-control code. Private host facts and credentials do not belong in this repository.

## Contract

- The GitHub Issue body is the contract.
- Label `approved` means a human approved that contract.
- Do not treat chat history as the contract.

## Flow

Issue → branch → pull request → review by the independent GitHub reviewer account → squash merge.

Required checks and rulesets on GitHub are the merge gates. Do not add a parallel local workflow language.

## Do not

- Do not use `new`, `zdev`, `zfix`, `zreview`, `zsync`, `zpr`, `zmerge`, or other G-lite runtime commands.
- Do not write credentials, tokens, private keys, or passwords.
- Do not upload real IP addresses, hostnames, usernames, ports, or production inventory.
- Do not copy private configuration into this repository. Private config stays in a private store/repo and may pin a public tag.
- Do not commit `5-record/` or personal notes.

## Layout

- `1-code/ops-control/` — Python package, schemas, tests
- `2-infra/ops-control/` — sanitized lab policy and fictional inventory

## Test

Run these commands from the repository root:

```bash
PYTHONPATH=1-code/ops-control python -m unittest discover -s 1-code/ops-control/tests/unit -p 'test_*.py'
PYTHONPATH=1-code/ops-control python -m unittest discover -s 1-code/ops-control/tests/integration -p 'test_*.py'
PYTHONPATH=1-code/ops-control python -m ops doctor --offline
```
