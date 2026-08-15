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

---

## 8. T8 安全复审结论（OpenWrt 支持 + 标准库双后端 + 发布面）— 追加

- 复审人：ow_researcher（架构师，任务 t8）；依据 docs/SECURITY.md §9（完整记录）
- 复审对象：T4（`procmetrics.py`/`security.py`/`stdserver.py`/api 纯处理器/app 双后端）、T5（install.sh/uninstall.sh OpenWrt 分支）、T7（systemd 单元分档与行尾注释修复）、发布面
- 结论：**未发现可利用漏洞（无高危/中危）**；T4/T5/T7 交付物通过 T8 安全复审。

### 8.1 回归实测（T8 复审环境：本机无 flask/psutil = OpenWrt stdlib 模拟；.piptmp/vendor 提供 Flask 3.1.3）

| 套件 | 结果 |
|---|---|
| storage / config / collector | ✅ 全过（collector 20/20 走 psutil 缺失 → /proc 路径）|
| procmetrics 自检 | ✅ 22/22 |
| security 自检 | ✅ 47/47 |
| stdserver 自检（含双后端逐字段契约对比）| ✅ 38/38（T8 新增 1 项）|
| api 冒烟（Flask）| ✅ 55/55 无回归 |
| app 端到端（Flask）| ✅ 51/51 无回归 |
| app 直接脚本执行（`python vpsmon/app.py --selftest`）| ✅ stdlib 链全过 |
| 双后端门序探针（`.devtest/t8_probe.py`）| ✅ 确认 §4.12-5 差异 |

### 8.2 T8 修复项

1. **`.gitignore` 残留目录缺口**：`vpsmon_x_*/` → `vpsmon_*_test_*/`（覆盖 proc/http/config/app 自检残留目录）。
2. **stdlib 门序断言锁定**：stdserver 自检新增"白名单外 POST 已知端点 → 403（先于 405）"，锁定白名单优先语义。

### 8.3 T7 复核确认

- ✅ `vpsmon.service` 模板与 install.sh 生成单元值行无行尾注释；selftest 含守卫（install.sh 自检段）。
- ✅ 三档门限（219/229/230/231/233/244）断言完备，版本不足指令绝不出现在单元里。
- ✅ `ExecStart` 为 `-m vpsmon.app` 模式，路径正确。
- ⚠️ install.sh `--selftest` 需 bash，Windows 本机未执行（环境限制）；建议在 Linux 实测终验。

### 8.4 复核结论对照（SECURITY.md §9.4/§9.5）

- ✅ stdserver 静态穿越防护 / Host 校验 / 安全门顺序 / 限流白名单一致性 / TLS fail-closed / 日志脱敏
- ✅ procmetrics 纯文件解析无注入面 / procd 参数引号安全 / uci 段名精确撤销 / /etc/vpsmon 权限（config 600、目录 700）/ PROBE_PATHS 顺序
- ✅ 发布面：.gitignore 全覆盖、README 占位符、无硬编码密钥、无 CDN 兜底
- ✅ OpenWrt root 无降权暴露面已文档化（SECURITY §4.12-1：bind 127.0.0.1/LAN + allow_ips + uci src=lan + 反代/TLS 配置示例）

**最终结论：T4/T5/T7 交付物通过 T8 安全复审，可交付。**

---

## 9. T6 双平台回归验收 + OpenWrt 文档（reviewer 交付）— 追加

- 验收人：ow_reviewer（验证与文档，任务 t6）
- 验收日期：2026-08-15
- 验收对象：T1–T8 全部交付物（双平台回归）+ README OpenWrt 章节 + 发布面
- 结论：**全部验收项 PASS**；代码层面未发现需修复的缺陷（0 修复）；发布面清理 2 类残留（T7 调试脚本、探测残留库/空目录）；2 项环境限制已记录（Windows 沙箱禁 bash 执行、空目录 ACL 锁定）。

### 9.1 回归测试结果（本机 Python 3.12.10；Flask 3.1.3 via .piptmp/vendor；psutil 缺失 = OpenWrt stdlib 模拟）

| 路径 | 套件 | 命令 | 结果 |
|---|---|---|---|
| Flask | api 冒烟 | `PYTHONPATH=.piptmp\vendor python -m vpsmon.api` | **55/55** |
| Flask | app 端到端 | `PYTHONPATH=... python -m vpsmon.app --selftest` | **51/51** |
| Flask | stdserver（含双后端契约对比） | `PYTHONPATH=... python -m vpsmon.stdserver --self-test` | **51/51**（13 项契约全一致） |
| stdlib | procmetrics | `python -m vpsmon.procmetrics --self-test` | **22/22** |
| stdlib | security | `python -m vpsmon.security --self-test` | **47/47** |
| stdlib | collector | `python -m vpsmon.collector --self-test` | **20/20** |
| stdlib | stdserver | `python -m vpsmon.stdserver --self-test` | **38/38** |
| stdlib | storage / config | `python -m vpsmon.storage` / `python -m vpsmon.config` | 全过 / **26/26** |
| T1 | 直接脚本执行（Flask） | `python vpsmon\app.py --selftest` | **51/51** |
| T1 | 直接脚本执行（stdlib） | `python vpsmon\app.py --selftest` | stdlib 链全过 |
| T1 | `-m` 执行（stdlib） | `python -m vpsmon.app --selftest` | stdlib 链全过 |
| 双后端 | 契约逐字段 | stdserver 自检 `compare()`：6 端点 + 3 错误路径 + 静态页/穿越 | **status 与 body 逐字相等** |

> 说明：Windows 本机无 `/proc`，`/api/status` 实时采集打印 WARNING 并回退库内样本——属 api.py 设计内的单点失败降级，非失败。全部断言 PASS，进程真实退出码 0（早前 `2>&1` 包装显示 exit 1 为 PowerShell stderr 错误记录伪影，已用重定向到文件 + `$LASTEXITCODE` 复核确认）。

### 9.2 install.sh / uninstall.sh 静态审查

| 项 | 结果 |
|---|---|
| 结构平衡（Python 状态机：剥 heredoc/注释/字符串后配对） | ✅ install.sh 与 uninstall.sh 的 if/fi、case/esac、for..done 全部配对（正确处理单行 `if..fi`/`case..esac` 与多行 `if/elif/else; fi` 形式） |
| heredoc 配对 / 引号 / 花括号 / `$()` 上下文 | ✅ `_t7_unit_check.py` 状态机断言全过（运行后已删除该调试脚本） |
| systemd 单元分档生成矩阵（v219/228/229/230/231/233/244/254） | ✅ `_t7_unit_check.py`：**ALL PASSED**——含/不含断言、档位标签、T7 值行无行尾注释守卫 |
| vpsmon.service 参考模板 | ✅ 值行无行尾注释；`ExecStart=-m vpsmon.app`；完整档指令齐全；不兼容项注释保留 |
| OpenWrt 分支隔离 | ✅ 7 个 OpenWrt 函数体（is_openwrt/openwrt_install_service/openwrt_start_and_check/openwrt_firewall_allow/openwrt_firewall_revoke/openwrt_do_uninstall/openwrt_print_success）均无 systemctl/journalctl/apt/dnf/yum/apk 引用；常量与关键片段（opkg update / `import sqlite3, http.server` 模块校验 / procd_open_instance / respawn / uci）全部在位 |
| `bash -n` / `bash install.sh --selftest` | ⚠️ 环境限制：沙箱禁 signal pipe（Git Bash 启动即崩，与 T8 §8.3 记录一致）；已用 `_t7_unit_check.py`（Windows 等价实现）替代验证并全过；建议发布前在 Linux 实机跑一次 `bash install.sh --selftest` |

### 9.3 README.md OpenWrt 文档（本任务交付，逐项核对）

- ✅ **新增"OpenWrt 路由器支持"章节**：前置要求（`opkg update` / 完整版 `python3` 含 sqlite3+http.server / Flash ≥16MB）；安装命令（本地 + 远程一行，`--port` 必填说明）；procd 管理表（`/etc/init.d/vpsmon status|start|stop|restart|enable|disable` + `logread` 日志）；数据目录 `/etc/vpsmon`（`/var` 为 tmpfs 重启清空的说明 + overlay 持久化验证）；uci 防火墙（安装自动放行说明 + 手动示例）；安全建议（bind 127.0.0.1 / allow_ips / uci src=lan / TLS·反代见 SECURITY §4.12）；卸载命令；已知限制（logread 替代 journalctl、python3-light 误装排查、小内存/overlay WAL 自动回退）。
- ✅ **新增"系统要求"章节**：Linux VPS / OpenWrt / NAS（无 Flask 自动 stdlib 模式）/ Windows 四平台要求表 + 双后端自动选择说明（6 端点逐字段一致）。
- ✅ 同步更新：简介双后端技术栈、功能特性新增 OpenWrt/NAS、文件位置（部署态）拆 VPS/OpenWrt 两表、配置加载顺序补 `/etc/vpsmon/config.json`、一键卸载补 OpenWrt 分支、目录结构与自检清单补 procmetrics/security/stdserver 模块与 stdlib 自检命令。
- ✅ README 全文无真实 token/密钥（token 一律 `<token>` 占位符；secret 扫描命中项均为 systemd 指令名误报）。

### 9.4 发布就绪检查

| 项 | 结果 |
|---|---|
| git status 核对 | ✅ 变更集 = 12 modified + 3 个新模块（procmetrics/security/stdserver.py），无 config.json/.piptmp/.devtest/.agent-teams/证书/数据库入库 |
| .gitignore 覆盖 | ✅ `config.json`、`*.db*`、`*.pem`、`*.key`、`.firewall-rule`、`.piptmp/`、`.devtest/`、`.agent-teams/`、`vpsmon_*_test_*/` 均经 `git check-ignore -v` 命中 |
| 残留清理 | ✅ 删除 T7 调试脚本 `_t7_unit_check.py`、探测残留 `probe_t8.db`、空测试目录；⚠️ 7 个空目录（`tmp*`、`vpsmon_x_zr2yz86q`）ACL 锁定无法删除（沙箱产物，git 不跟踪空目录，不影响发布） |
| 行尾 / BOM | ✅ 关键文件（README/install.sh/uninstall.sh/vpsmon.service/Python 源码）全部 LF 无 BOM；⚠️ LICENSE 为既有 CRLF（非本特性变更，可选统一） |
| 无悬空引用 | ✅ 删除的 `_t7*` 脚本在 docs/源码中无任何引用 |

### 9.5 残余风险与建议（接受项）

1. **bash 自检未在本机执行**（沙箱限制）——等效断言已由 `_t7_unit_check.py` 全过；发布前 Linux 实机 `bash install.sh --selftest` 终验一次（与 T8 §8.3 同款建议）。
2. **OpenWrt 真机未实测**——opkg 安装/procd 启停/uci 撤销/重启持久化为静态审查 + 逻辑模拟；建议发布后按 SPEC §13.6 T5 验收清单在真实设备终验（x86_64 或真实路由器）。
3. **LICENSE CRLF**——非阻塞，可选统一为 LF。

**最终结论：T1–T8 全部交付物通过 T6 双平台回归验收；README OpenWrt 章节交付完成；发布面就绪。可交付。**
