# ops-control

`ops-control` 是面向个人运维场景的受控控制面实现。当前仓库已经包含严格 v1 JSON 契约、受控资源与 inventory 访问、动作 registry、不可变 plan、执行 gates、gateway、审批服务、固定 executor / broker 边界、安全日志与原子存储；同时配套脱敏 policy / inventory / Ansible 资产和 unit / integration tests。

这些能力默认 fail-closed，并不等于自动拥有生产主机访问权。public repo 不保存真实 host、address 或 secret；真实 inventory、credentials 与生产连接配置必须保留在受控的私有环境中。

## 离线安装与测试

要求 Python 3.12 或更高版本。代码根不依赖 Ansible。请从仓库根目录创建虚拟环境、按锁文件安装依赖，并通过 `PYTHONPATH` 直接使用源码：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r 1-code/ops-control/requirements.lock
export PYTHONPATH="$PWD/1-code/ops-control"
.venv/bin/python -m unittest discover -s 1-code/ops-control/tests/unit -p 'test_*.py'
PYTHONPATH=1-code/ops-control .venv/bin/python -m unittest discover -s 1-code/ops-control/tests/integration -p 'test_*.py'
.venv/bin/python -m ops doctor --offline
```

`requirements.lock` 只锁定直接依赖版本；平台 wheel 的传递依赖由安装器解析。没有网络安装授权时，不应伪造 hash；先准备依赖，再按锁文件安装。

`doctor --offline` 只检查本包 schema、依赖和可信定位到的脱敏 `2-infra/ops-control` policy/reference，不连接生产主机。

当前 CLI 已包含 `doctor`、`actions list`、`plan`、`approval open`、`apply`、`result` 等入口。是否能真正执行某一步，仍由当前 registry、可信资源、identity、approval、gate 和 fixed broker 条件决定；缺少前置条件时应返回结构化失败，而不是绕过安全边界。`--human` 只负责把同一个 response 对象渲染为人类可读文本。

## 当前能力

| 能力 | 主要实现位置 | 当前定位 |
| --- | --- | --- |
| schema / model contract | `schema/`、`ops/models.py` | 严格 v1 数据契约、校验与规范化 |
| resource / inventory access | `ops/resources.py`、`ops/inventory.py` | 只从可信资源入口读取受控 policy / inventory |
| action registry | `ops/registry.py` | 由受信 manifest 决定动作集合，默认冻结、拒绝任意 adapter |
| plan / gates | `ops/plans.py`、`ops/gates.py` | 构造不可变 plan，并在执行前重新验证安全条件 |
| gateway | `ops/gateway.py` | 作为结构化请求入口，绑定系统侧 identity / credential context |
| approval | `ops/approval/`、`client/approval.py` | 提供 loopback approval / WebAuthn 边界与 approval record |
| executor / broker | `ops/executor/` | 固定、deny-by-default 的执行边界；不接受任意 shell / path / Ansible 参数 |
| logging / storage | `ops/logs.py`、`ops/storage.py` | 白名单安全日志与原子、受限 JSON 存储 |
| sanitized infra / Ansible assets | `2-infra/ops-control/` | 脱敏 lab policy、虚构 inventory、受控 playbook / deploy 示例 |

## 包结构

| 外部契约落点 | 仓库实际路径 | 用途 |
| --- | --- | --- |
| `ops/`、`client/` | `1-code/ops-control/ops/`、`client/` | Python API、CLI、gateway、approval、executor 与传输边界 |
| `schema/*.v1.json` | `1-code/ops-control/schema/` | 可安装的数据契约 |
| `tests/fixtures/`、`tests/unit/`、`tests/integration/` | `1-code/ops-control/tests/` | 无秘密离线回归 |
| policy / inventory / actions | `2-infra/ops-control/` | 脱敏管理元数据、动作描述、policy 与 Ansible 投影 |

`TrustedResourceProvider` 负责把代码访问限制在受控资源根下。生产 identity、credentials、真实 inventory 和其它私有材料不应因为 public repo 中存在 schema、示例或 deploy 模板就被复制进来。

## 安全与部署边界

当前仓库已经实现控制面核心组件和受控执行边界，但仍必须区分“代码能力存在”和“生产环境已经部署/授权”：

- public repo 不包含真实主机、地址、PAT、SSH key、WebAuthn credential 或其它 secret；
- 不从请求中接受任意 root、shell、command、inventory、plugin、playbook、extra vars 或 credential 路径；
- fixed broker / executor 的存在不表示任意业务动作已经开放，release、capability、identity、approval 与 gate 仍需满足受信条件；
- `2-infra/ops-control` 默认是 sanitized lab / fictional inventory，不应指向旧生产 inventory；
- 真实 private inventory / credentials 应保存在独立私有位置，并由部署环境显式绑定；
- 仓库中的 deploy / Ansible / recovery 资产存在，不等于对应生产安装、远端执行或恢复演练已经成功；
- `RecoveryEvidence` 等记录模型只能表达证据，不能替代真实恢复验证。
