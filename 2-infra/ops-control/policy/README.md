# policy

固定适用规则的脱敏投影。连接真值不放这里。

| 文件 | 用途 |
| --- | --- |
| `machine-classes.yml` | 大陆 / 全球 / NAT，以及旧源实际存在的 Windows、未纳管云电脑、退役类 |
| `special-rules.yml` | 来源 → 判定输入 → allow/deny → 责任任务 |
| `credential-refs.yml` | 凭据引用名，不含值 |

后续 OPS-003 的 policy_digest 应消费本目录的规范化内容，而不是生产 `group_vars`。
