# baseline fixtures

虚构 host/service/software ID。地址只用文档网段（192.0.2.0/24、198.51.100.0/24、203.0.113.0/24）。

`cases/` 提供 inherited-rules 的判定输入；预期索引在 `expected/allow-deny.json`，并与 `policy/special-rules.yml` 的 deny-wins evaluate 对齐。
连接投影与 lab inventory 共用 `ansible/inventories/lab/hosts.ini`，管理元数据共用 `inventory/management.yml`。
