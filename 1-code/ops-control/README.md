# ops-control

`ops-control` 是 G-lite OPS-002 的首个离线控制面基础包：严格 v1 JSON 契约、规范化摘要、受控 JSON 文件 IO、安全事件接口和 CLI 外壳。它不执行远端动作，也不替代后续 Issue 的 registry、plan、gateway、审批或 executor。

## 离线安装与测试

要求 Python 3.12 或更高版本。代码根不依赖 Ansible。请从仓库根目录创建虚拟环境、按锁文件安装依赖，并通过 `PYTHONPATH` 直接使用源码：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r 1-code/ops-control/requirements.lock
export PYTHONPATH="$PWD/1-code/ops-control"
.venv/bin/python -m unittest discover -s 1-code/ops-control/tests/unit -p 'test_*.py'
.venv/bin/python -m ops doctor --offline
```

`requirements.lock` 只锁定直接依赖版本；平台 wheel 的传递依赖由安装器解析。没有网络安装授权时，不应伪造 hash；先准备依赖，再按锁文件安装。

`doctor --offline` 只检查本包 schema、依赖和可信定位到的脱敏 `2-infra/ops-control` policy/reference。当前命令树的其它命令先返回结构化 `unsupported_command` 和非零退出码，不读取参数文件，不连接主机。`--human` 只是把同一个 response 对象渲染为人类可读文本。

## 包结构

| 外部契约落点 | G-lite 实际路径 | 用途 |
| --- | --- | --- |
| `ops/`、`client/` | `1-code/ops-control/ops/`、`client/` | Python API、CLI、传输 seam |
| `schema/*.v1.json` | `1-code/ops-control/schema/` | 可安装的数据契约 |
| `tests/fixtures/`、`tests/unit/` | `1-code/ops-control/tests/` | 无秘密离线回归 |
| `policy/logging.yml` | `2-infra/ops-control/policy/logging.yml` | 日志字段唯一白名单 |
| `inventory/management.yml` | `origin/main` 的 `2-infra/ops-control/inventory/management.yml` | 脱敏管理元数据；本任务不复制、不改写 |

`TrustedResourceProvider` 是跨域资源的唯一入口。它只允许 `policy/logging.yml`、`policy/credential-refs.yml` 和 `inventory/management.yml` 三个相对资源名；CLI 没有任意 root、policy、data 或 secret 路径参数。

## 未实现边界

本任务没有连接生产、读取 `$OLD_VPS_ROOT`、读取旧 `credentials/` 或 `private/*.secrets.yml`、读取 sibling backup、执行 SSH/Ansible、安装服务、实现真实 transport、审批、计划、动作注册、批次执行、恢复状态机或自动清锁。`RecoveryEvidence` 只定义不可变记录和引用；脚本或 rclone 配置存在不等于恢复验证成功。
