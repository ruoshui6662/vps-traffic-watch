# VPS 流量统计监控系统 — T4 安全验收报告（ACCEPTANCE）

- 验收人：sec_reviewer（安全验证与文档，任务 t4）
- 验收日期：2026-08-15
- 验收对象：T1（docs/SECURITY.md 审计）、T2（后端加固）、T3（安装加固）全部交付物
- 结论：**全部验收项 PASS**，未发现可利用漏洞；复测中发现 2 项低危 Host 头校验缺口，**已当场修复并补回归**（见 §4）；文档（README 安全章节、SPEC §4/§6.1）已同步。

---

## 1. 回归测试结果（本地，Python 3.12.10 + Flask 3.1.3 via .piptmp/vendor）

| 套件 | 命令 | 结果 |
|---|---|---|
| storage 自检 | `python -m vpsmon.storage` | **全部通过**（WAL/聚合/正增量/幂等/空库/边界） |
| collector 自检 | `python -m vpsmon.collector --self-test` | **20/20**（网卡选择/回退/采样/降级） |
| config 自检 | `python -m vpsmon.config` | **26/26**（默认值/合法解析/非法回退/布尔串/白名单形式/overrides） |
| api 冒烟 | `python -m vpsmon.api` | **55/55**（全端点/鉴权/限流/白名单/代理/参数/头/日志脱敏/空库） |
| app 端到端 | `python -m vpsmon.app --selftest` | **51/51**（含 T4 新增 Host userinfo/端口校验 3 例） |
| 集成 empty | `.devtest/integration.py` :18080 | **31/31** |
| 集成 seeded | `.devtest/integration.py` :18081 | **26/26** |
| 集成 token | `.devtest/integration.py` :18082 | **10/10** |
| 渗透补充 | `.devtest/pen_check.py` :18083/:18084 | **79/79**（见 §2） |
| TLS 失败闭合 | 配置不存在的证书/密钥 | **退出码 1**，拒绝以明文启动（不静默降级） |
| 日志脱敏（实测） | token 服务访问日志 | `GET /api/status?redacted`（`?token=sekrit` 不出日志） |

合计：**自检 152+ 项、集成 67 项、渗透 79 项，全部 PASS**。

## 2. 渗透式复测明细（pen_check.py，对运行实例）

- **路径穿越/目录探测**：`/static/` 目录、`..%2f`、`%2e%2e`、双编码 `%252e%252e`、反斜杠、`....//`、空字节 `%00`、`/static/../../etc/passwd`、`/static/../vpsmon/config.py` 等 15 种 → 全部 404，**无任何文件泄露**。
- **敏感路径直读**：`/config.json`、`/vpsmon.db`、`/.gitignore` 及 `/static/../` 变体 → 全部非 200。
- **方法面**：TRACE → 405；OPTIONS → 200 且 Allow 仅 `GET/HEAD/OPTIONS`（Flask 标准行为，无副作用）。
- **安全响应头**（API + 静态 + 根）：CSP（`default-src 'self'`、`script-src 'self'` 无外域/内联、`object-src 'none'`、`frame-ancestors 'none'`）、XFO=DENY、nosniff、Referrer-Policy=no-referrer、Permissions-Policy、API `Cache-Control: no-store`、HTTP 下无 HSTS（仅 HTTPS 下发，已由 selftest 验证）→ 全部正确。
- **Host 头**：IP 字面量/localhost/`[::1]` 放行；未知域名、带点后缀、`@` userinfo、非法端口、斜杠/反斜杠/空白、缺失 Host → 400（缺失 Host 由 HTTP/1.1 层 400）。
- **注入探测**：iface/month/limit 的 SQLi 与 XSS 载荷（`' OR '1'='1`、`<script>`、`UNION SELECT`、`; DROP` 等 7 组）→ 400/200 且**无错误回显**（无 traceback/SQL 错误）。
- **异常输入**：limit 30 位数字、iface 5000 字符、全空白 iface、month 空字节、超长 query → 无 500。
- **鉴权**：无 token/错 token/`?token=`（默认）→ 统一 401；`X-Token` 正确 → 200；重复 X-Token 头 → **401 失败闭合**；正/误 token 中位耗时比 1.17（恒定时间特征）。
- **限流**：rate_limit=5 实例前 5 次 200、第 6 次起 429；rate_limit=0 关闭；跨实例桶隔离。
- **白名单/代理**：CIDR 命中放行、未命中 403、IPv4-mapped IPv6 归并、trusted_proxy+XFF 采信与伪造拒绝（selftest 覆盖，本机无法伪造 remote_addr 做 live 验证——已在报告注明测试方法）。

## 3. install.sh / uninstall.sh 静态审查

| 项 | 结论 |
|---|---|
| 端口解析优先级 `--port` > `VPSMON_PORT` > 交互输入 > 非交互报错 | ✅ 代码确认（install.sh:105-194）；交互非法重试 3 次退出；管道模式无端口即报错退出（不再静默默认 8080） |
| `is_valid_port`：纯数字、≤5 位、`10#` 强制十进制防八进制陷阱 | ✅ |
| token 三级生成回退 openssl → `/dev/urandom`+od → python3 secrets（128bit） | ✅（generate_token，生成时机在依赖安装后） |
| `--token ""` 显式不鉴权 + 长度 < 8 警告 + 未设置 token 醒目警告 | ✅ |
| 防火墙交互确认放行 + `.firewall-rule` 标记（ufw/firewalld） | ✅（firewall_allow）；非交互默认只提示不放行 |
| 卸载撤销：install.sh do_uninstall 与 uninstall.sh 均先撤规则再删数据目录；标记缺失不误删 | ✅（firewall_revoke 双实现一致） |
| `umask 077` 子 shell 写入 config.json（消除 644 窗口）| ✅（write_config） |
| `/opt/vpsmon` 归 root 只读：去掉 `chown -R vpsmon`，改 `chmod -R o-w` + `ProtectSystem=strict` | ✅ |
| `VPSMON_EXPECTED_SHA256` tarball 校验，不匹配立即退出 | ✅（fetch_remote_source） |
| 既有参数/行为兼容（--port/--token/--iface/--interval/--keep-data/uninstall 旧写法） | ✅ |
| 结构平衡 | ✅ 关键字计数：if==fi（80/80）、case==esac（8/8）、循环==done（4/4），heredoc 配对正常；`bash -n` 因沙箱禁止 signal pipe 无法执行（环境限制，非脚本问题） |
| vpsmon.service 加固 | ✅ UMask=0077、ProtectSystem=strict、ProtectKernel*/ProtectProc/PrivateDevices/空 CapabilityBoundingSet 等；不兼容项（MemoryDenyWriteExecute/ProcSubset/PrivateUsers/IPAddressDeny）保留注释说明 |
| requirements 精确 pin | ✅ `flask==3.1.3`、`psutil==7.2.2` |

## 4. 复测发现并修复的问题（T4 新增修复）

**Host 头校验两处低危缺口（vpsmon/app.py `_valid_host`）**：
1. `Host: evil.com@127.0.0.1:18083`（userinfo 伪装）此前被放行（hostname 解析为 IP 字面量 127.0.0.1）；
2. `Host: 127.0.0.1:99999`（越界端口）此前被放行（端口未校验）。

修复：字符黑名单增加 `@`；解析后访问 `parsed.port`（越界/非数字抛 ValueError → 拒绝）。补 3 条自检断言（app selftest 48→51）。经重新全量回归（§1 结果含此修复后状态），未引入回归。

> 说明：此二项虽无实际可利用面（有效 host 均为 IP 字面量，不参与 DNS 解析，无 rebinding 风险；应用不消费 Host 端口），但按纵深防御收紧，成本极低。

## 5. 残余风险与建议（接受项）

| # | 项 | 状态 | 说明/建议 |
|---|---|---|---|
| 1 | 内存限流重启清零 | 接受（SECURITY §7.3） | 单进程单用户场景；配合强 token 无实际威胁 |
| 2 | token 明文存 config.json | 接受（600+700） | root 可见属运维必然 |
| 3 | 自签 TLS 浏览器告警 | 接受（过渡） | 公网正式部署走反代 ACME（README 已给 nginx/caddy 示例） |
| 4 | `curl|bash` 供应链信任 | 接受（部署方责任） | 已文档化信任模型 + commit pin + `VPSMON_EXPECTED_SHA256` |
| 5 | L1 `expose_meta` 未实施 | 建议做 | hostname/uptime/db_bytes 常显，token 保护下可接受 |
| 6 | S1 waitress 生产 WSGI 未实施 | 建议做 | 单用户监控足够；替换无 API 改动 |
| 7 | journald `SystemMaxUse` / `keep_days` 清理 | 建议做 | 运维可选：`journalctl --vacuum-size=100M` |
| 8 | 500 不泄堆栈 | ✅ 代码级确认 | 通用错误处理 + 服务端日志；全输入面已参数化/钳制，无可用触发点 |
| 9 | 白名单/代理 live 验证 | 测试方法限制 | selftest 用 environ_overrides 覆盖（含 IPv4-mapped IPv6、XFF 伪造拒绝）；真实多源 IP 需部署环境验证 |

## 6. 文档交付核对

- ✅ `README.md` 新增"安全（Security）"章节：默认安全配置表、安全字段说明、TLS/反代（nginx/caddy 示例 + Host 改写要点 + trusted_proxy 配置）、安全 FAQ（token 泄露处置、bind 127.0.0.1、来源 IP 限制、Host 钉扎）；同步更新安装参数表/安装流程/API 鉴权段/FAQ/目录结构/自检清单。
- ✅ `docs/SPEC.md` §4.1 配置表新增 bind/allow_ips/rate_limit/allow_url_token/ssl_certfile/ssl_keyfile/trusted_proxy/debug；§6.1 鉴权契约重写（默认仅 X-Token、?token= 默认 401、恒定时间比较、检查顺序 403→429→401→400、安全响应头与 Host 校验）。
- ✅ `docs/SECURITY.md` §5.3 实施状态更新（L2/L4 已完成、S4 部分完成）；§8 验收清单对应项全部达成。
- ✅ 新增 `.devtest/pen_check.py` 与 `.devtest/pen/*.json` 复测脚手架（gitignore 内，非交付物）。

## 7. 验收清单（SECURITY.md §8）对照

| # | 验收项 | 结果 |
|---|---|---|
| 1 | 安全头（全部响应） | ✅ 实测 |
| 2 | 鉴权：无 token 401 / X-Token 200 / `?token=` 401（默认） | ✅ 实测 |
| 3 | 限流 429 | ✅ 实测（rate_limit=5） |
| 4 | 白名单 403 | ✅ selftest 实测 |
| 5 | TLS（启用后 https 200 / 缺证书拒绝启动） | ✅ 失败闭合实测；正向用例需真实证书（README 指引） |
| 6 | systemd 加固评分/指令 | ✅ 静态审查（vpsmon.service） |
| 7 | 日志无 `?token=` | ✅ 实测脱敏 |
| 8 | 安装流程（管道必须端口/交互重试/token 自动生成打印） | ✅ 代码审查 + 逻辑模拟 |

**最终结论：T1/T2/T3 交付物通过 T4 验收，可交付。**
