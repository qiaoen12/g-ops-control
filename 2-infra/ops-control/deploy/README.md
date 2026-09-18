# OPS-004 deployment templates

这些文件是可丢弃 Linux 实验的声明式模板，不是安装器，也不会自动创建用户/组、写 `/etc/ssh`、写 sudoers、安装 release 或修改现有 SSH 恢复入口。真实实验必须先得到用户授权，并由独立维护身份逐项审阅和执行。

## 固定边界

- `ops-call` 只有 root-owned `authorized_keys` 中逐 key 绑定的固定 forced command（含稳定 `--credential-id`），没有 shell、PTY、SFTP、agent/X11/端口转发或用户环境注入。
- `ops-call` 只能读取身份映射并写自己的 bounded Plan；固定 Gateway 会把 immutable Plan 暴露为 `ops-plan-read` 的只读 projection，不能写 `approvals/`、`current`、policy、identity、`uses/`、`launches/` 或 `blockers/`。
- `ops-exec` 通过 root-owned exact broker 接收原有 `Request v1`，读取 Plan/Approval projection，并独占写 `uses/`、`launches/`、`runs/` 与 `results/`；它不能写 approvals。
- `ops-approve` 是独立 loopback-only 审批服务：从 `ops-maint` 拥有的 metadata 目录只读维护登记的 trusted WebAuthn 公钥/owner/status，只能发布 `approvals/` 并在单独的 counter 目录持久化单调 sign counter；它不提供凭据注册/撤销入口，普通 `ops-call` 不能伪造或提交 Approval。
- `ops-maint` 保留经审阅的 root-owned 发布、身份登记、恢复和回退入口；目录模式不会把这些写权限授予日常服务 UID，不作为日常 AI/调用凭据。

`sudoers.example` 只允许无参数 exact broker path。Gateway 传递的是既有 `Request v1` 的 `apply` 对象；broker 自己从维护侧配置解析 release、代码和解释器，并拒绝调用者提供的 executable、argv、systemd、cwd、key、env、Ansible 搜索路径或任意 path。

`broker-wrapper.example.py` 假定 `/opt/ops-control/current` 是完整 release workspace，固定从其中的 `1-code/ops-control` 导入；若维护者采用其他 release 打包布局，必须由维护者审阅并替换 wrapper，不能通过 Request、CLI 参数或环境变量选择代码路径。

## 建议的实验顺序

1. 复制模板到临时材料目录，填入不含秘密的实验值；不复制生产 key、inventory 或地址。
2. 由维护者在可丢弃 Linux 上创建四个独立 UID/组，并按 `layout.yml` 建立 `ops-control` 穿越组与仅供 `ops-exec`/`ops-approve` 读取 Plan 的 `ops-plan-read` 组；目录使用 setgid 继承其专用 group，维护侧用 root-owned procedure 写入发布、配置和 SSH key 文件。
3. 安装固定 release 与 root-owned wrapper，按每把 key 在 `authorized_keys.example` 中绑定 `--credential-id`，用 `preflight.sh.example --root <staging-or-disposable-root>` 做只读检查。
4. 单独保留已有管理员 SSH 登录，先验证恢复入口，再以当前 Mac 建立 `ops-call` 连接。
5. 运行 OPS-004 R6 的不同 UID 正反例和 R7 Human Demo-0；失败时删除整个 disposable host 或按维护者记录回退，不在生产主机试验。
6. 由 `ops-maint` 在 metadata 目录登记/撤销 credential；在独立 `ops-approve` UID 下启动 loopback `ops-approve`，只读 metadata、只写独立 counter 和 `approvals/`；OPS-005 的 `ops approval open PLAN_ID` 只建立临时会话，浏览器确认后才写入 `approvals/`。

## 回退 / 卸载

实验失败时优先销毁 disposable host。若必须保留主机，由 `ops-maint` 先恢复原有 sshd 配置和管理员 key，再撤掉 `ForceCommand`、sudoers exact rule、实验用户/组和 `/opt/ops-control`、`/etc/ops-control`、`/var/lib/ops-control` 实验目录。任何删除操作都由维护者核对目标后执行；本模板本身不删除文件。

不要删除用户已有 SSH 恢复入口来“证明”隔离有效。生产环境不在 OPS-004 范围内。
