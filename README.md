# ops-control

Public snapshot of the ops-control code. It contains no real hosts, addresses, or secrets.

Private inventory and credentials stay in a separate private repository. That private repo should depend on a tag of this public repo rather than forking a second copy of the code.

## Layout

| Path | Role |
| --- | --- |
| `1-code/ops-control/` | Python package, JSON schemas, unit/integration tests |
| `2-infra/ops-control/` | Sanitized lab policy and fictional inventory |

## Install and test

Python 3.12 or newer:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r 1-code/ops-control/requirements.lock
PYTHONPATH=1-code/ops-control .venv/bin/python -m unittest discover -s 1-code/ops-control/tests/unit -p 'test_*.py'
PYTHONPATH=1-code/ops-control .venv/bin/python -m unittest discover -s 1-code/ops-control/tests/integration -p 'test_*.py'
PYTHONPATH=1-code/ops-control .venv/bin/python -m ops doctor --offline
```

`doctor --offline` only checks schemas, dependencies, and the sanitized lab references. It does not connect to hosts.
