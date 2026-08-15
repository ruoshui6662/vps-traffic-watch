# VPS 流量统计监控系统 — 安全审计与加固方案（SECURITY）

- 版本：1.0
- 审计人：sec_researcher（安全审计专家，任务 t1）
- 审计日期：2025（项目即将托管 GitHub 公网部署前）
- 审计对象：`install.sh`、`uninstall.sh`、`vpsmon.service`、`vpsmon/{app,api,config,collector,storage}.py`、`vpsmon/static/*`、`README.md`、`docs/SPEC.md`、`requirements.txt`
- 用途：本文档是 T2（后端加固）/ T3（安装加固）的实施依据；"必须做"清单见 §5。

---

## 1. 审计范围与部署形态

```
公网 IP:port（HTTP，默认 8080，绑定 0.0.0.0）
  └─ Flask(werkzeug dev server)  ← root 一键安装脚本（curl|bash 可远程执行）
       ├─ / 与 /static/*：静态页，不鉴权
       ├─ /api/*：6 个只读 GET 端点，可选 token 鉴权（X-Token 头 或 ?token= 参数）
       ├─ SQLite WAL（/var/lib/vpsmon/vpsmon.db，采集线程唯一写者）
       └─ psutil 采样线程（CPU/内存/磁盘/网卡计数）
systemd 服务 vpsmon（User=vpsmon，ProtectSystem=full 等基础加固）
数据：/var/lib/vpsmon/config.json（600，含 token 明文）、vpsmon.db（700 目录）
```

单用户自监控场景；无多账户体系、无 Cookie/会话（全部 GET 只读，无 CSRF 面）。

---

## 2. 威胁模型

### 2.1 资产
| 资产 | 说明 |
|---|---|
| 监控数据 | 月度/日度流量、实时速率、CPU/内存/磁盘占用、样本明细（数据库） |
| 访问令牌 token | config.json 中明文存储；是 `/api/*` 的唯一访问凭据 |
| 主机完整性 | 安装脚本以 **root** 执行；systemd 服务以降权用户 vpsmon 运行 |
| 服务器元信息 | hostname、uptime、网卡名、库大小（`/api/status`、`/api/interfaces` 返回） |

### 2.2 信任边界
1. **公网 → Flask**：主要攻击面。token 是唯一防线，且默认安装 **token 为空（无鉴权）**。
2. **root → 安装脚本**：`curl|bash` 管道下，脚本内容即 root 代码执行（供应链信任）。
3. **vpsmon 用户 → 数据/程序**：systemd 以 vpsmon 运行；程序目录属主当前被 `chown -R vpsmon`（见 M7）。
4. **本机低权限用户 → config.json/数据库**：依赖目录 700 / 文件 600 权限（写入窗口见 M6）。

### 2.3 攻击面清单
| 攻击面 | 说明 |
|---|---|
| 网络探测 | 扫描 8080/其他端口指纹识别 Flask/werkzeug |
| token 暴力破解 | 无速率限制 + 弱口令 → 在线爆破；`==` 比较 → 时序侧信道（理论） |
| 信息泄露 | `/api/status` hostname/uptime/db 大小；`/api/interfaces` 网卡清单；`?token=` 进访问日志/Referer |
| 日志泄露 | werkzeug access log 含完整 query string（`?token=xxx`）→ journald |
| 供应链 | `curl|bash` 无校验；GitHub tarball 无校验和；pip 依赖版本无上限；前端 CDN 兜底脚本无 SRI |
| 本地提权面 | 安装脚本以 root 运行；`/opt/vpsmon` 运行期可写（vpsmon 属主）；systemd 加固不完整 |
| XSS/localStorage | 无 CSP；token 存 localStorage → XSS 即令牌失窃 |
| 传输窃听 | 公网明文 HTTP，token 与统计数据可被中间人嗅探 |
| 数据完整性 | SQLite 注入面（已复核为无，见 §6）；config.json 被篡改 → 改 token/绑定向内网 |

### 2.4 典型攻击场景（示例）
- **S1 裸奔暴露**：默认安装（无 token、0.0.0.0:8080）→ 全网任意人可读流量与系统占用 → 泄露主机规模/业务量，辅助进一步攻击。
- **S2 暴力破解**：攻击者枚举 `/api/status?token=` → 无限流、弱 token 可在数分钟内被猜中 → 完全接管读权限。
- **S3 日志捞 token**：用户访问 `?token=xxx` → 请求行含 token 写入 journald/反代日志 → 日志泄露即凭据泄露。
- **S4 供应链投毒**：GitHub 仓库被入侵或改名接管 → 用户 `curl|bash` 远程安装 → root 执行恶意 install.sh。
- **S5 局域网/公网嗅探**：明文 HTTP 下 token 与流量数据被中间人截获（公共 Wi-Fi / 骨干抓包）。
- **S6 XSS 连锁**：若页面存在注入点（当前未发现），攻击脚本读 localStorage 的 token → 直接以合法身份调 API。

---

## 3. 风险分级清单

图例：位置 = `文件:行`；归属 = T2（后端）/ T3（安装）/ 文档。

### 3.1 高危（6 项）— 必须修复

| # | 风险 | 位置 | 攻击场景 | 影响 | 修复方案 | 归属 |
|---|---|---|---|---|---|---|
| H1 | 默认无鉴权 + 0.0.0.0 + 静默默认端口 | install.sh:27,29,75,345；app.py:97；config.py:26-27 | 默认安装即公网裸奔 | 任何人可读全部监控数据与系统信息 | 安装时**强制生成/设置 token**（见 §4.10）；`bind` 可配 127.0.0.1；端口交互必填（M9） | T3+T2 |
| H2 | token 用普通 `==` 比较（非恒定时间） | api.py:57-58 | 远程时序侧信道逐字符探测 token | 理论可恢复 token（远程噪声大但属标准缺陷） | `hmac.compare_digest` 比较（见 §4.1） | T2 |
| H3 | `?token=` 查询参数鉴权默认启用 | api.py:58；app.js:51-59；install.sh:343 | token 进入访问日志/浏览器历史/Referer/代理日志 | 凭据泄露，任何日志出口都是泄漏点 | 默认仅 `X-Token` 头；`allow_url_token` 配置项兼容，默认 false（见 §4.1） | T2 |
| H4 | 无速率限制 | api.py（全部端点） | 在线暴力破解 token；无 token 时刷爆 CPU/磁盘 IO 的查询放大 | 鉴权失效/服务拒绝 | 内存按 IP 限流（60/min 可调，0=关）（见 §4.2） | T2 |
| H5 | 无 IP 白名单 | api.py | 攻击面向全互联网开放，无法收敛到可信 IP | 持续扫描/爆破无入口管控 | `allow_ips` 白名单（IPv4/IPv6 + CIDR）（见 §4.3） | T2 |
| H6 | 远程安装无完整性校验（curl\|bash + tarball 无校验和） | install.sh:427-489；README:36-48 | 仓库被投毒/接管 → 用户 root 执行恶意脚本 | 主机完全失陷（root） | 文档化信任模型 + 支持 `VPSMON_EXPECTED_SHA256` 校验 + 建议 commit 固定（见 §4.11） | T3+文档 |

### 3.2 中危（10 项）— 必须修复

| # | 风险 | 位置 | 攻击场景 | 影响 | 修复方案 | 归属 |
|---|---|---|---|---|---|---|
| M1 | 无任何安全响应头 | app.py:create_app | XSS 无 CSP 兜底；点击劫持；MIME 嗅探；代理缓存敏感 JSON | 多项浏览器侧防线缺失 | after_request 注入 CSP/XFO/nosniff/Referrer-Policy/Cache-Control（见 §4.6） | T2 |
| M2 | 公网明文 HTTP，无 TLS | app.py:97；install.sh:336-341 | 中间人嗅探 token 与流量数据 | 凭据与监控数据泄露 | config `ssl_certfile`/`ssl_keyfile` → Flask `ssl_context`（自签证书）；反代 HTTPS 示例（见 §4.5） | T2+文档 |
| M3 | requirements 版本无上限 | requirements.txt:1-2 | 依赖上游引入破坏性/恶意版本；不可复现 | 供应链漂移、部署不可复现 | 精确 pin + 可选 hashes（见 §4.11） | T3 |
| M4 | 前端 CDN 兜底脚本无 SRI；token 存 localStorage | app.js:543-559,48-61 | 本地 vendor 缺失时从 jsdelivr 加载无校验第三方代码；XSS 后 token 直接可读 | 第三方脚本执行 = 任意 JS；令牌失窃放大 | **删除 CDN 兜底**（vendor 必随包）；localStorage 风险文档化 + CSP 兜底（见 §4.11/§4.6） | T2 |
| M5 | werkzeug access log 记录完整 query string | app.py（werkzeug 默认日志） | `?token=xxx` 写入 journald | 日志泄露即凭据泄露（与 H3 联动） | 日志脱敏：过滤 query string；token 默认仅头（见 §4.7） | T2 |
| M6 | config.json 写入权限窗口：`cat >` 后 `chmod 600`，中间为 644 | install.sh:243-253 | 同机其他用户在该窗口读 token（瞬时但真实） | token 泄露给低权限本地用户 | `umask 077` 包裹写入或 `install -m 600` 原子落盘（见 §4.10） | T3 |
| M7 | `/opt/vpsmon` 被 `chown -R vpsmon`，且 `ProtectSystem=full` **不覆盖 /opt** | install.sh:230；vpsmon.service:24 | 服务被攻破后 vpsmon 用户可改写程序目录（持久化后门） | 降权防线被削弱；纵深防御缺失 | 程序目录归 root:root 只读；`ProtectSystem=strict` + `ReadWritePaths=/var/lib/vpsmon`（见 §4.9/§4.10） | T3 |
| M8 | systemd 加固缺口 | vpsmon.service | 缺 UMask/CapabilityBoundingSet/ProtectKernel*/Restrict* 等；`MemoryDenyWriteExecute` 需评估兼容性 | 爆破面/内核接口面未收敛 | 扩展加固清单；MemoryDenyWriteExecute 与 Python 不兼容→注释说明（见 §4.9） | T3 |
| M9 | 安装流程：端口静默默认 8080、无交互输入、token 默认空 | install.sh:27,75,342-346 | 误装成公网裸奔；弱/无凭据 | 默认部署即高危态 | 交互 `read` 校验端口（1-65535 非法重试）；非交互/管道模式必须 `--port`/`VPSMON_PORT` 否则报错；token 默认强随机生成（见 §4.10） | T3 |
| M10 | 防火墙仅打印提示，不落地；卸载不撤销 | install.sh:316-326；uninstall.sh | 用户忘记放行/残留放行规则 | 可用性受损或卸载后遗留暴露面 | 交互确认后 ufw/firewalld 自动放行并记录；卸载撤销（见 §4.10） | T3 |

### 3.3 低危（5 项）— 建议修复

| # | 风险 | 位置 | 影响 | 修复方案 | 归属 |
|---|---|---|---|---|---|
| L1 | `/api/status` 返回 hostname/uptime/db_bytes 等元信息 | api.py:151-166 | 信息面扩大（攻击者指纹化主机） | 保留（单用户自监控需要展示），文档说明；可选 `expose_meta` 开关脱敏 | 建议做 |
| L2 | 无 Host 头校验 | app.py:create_app | Host 头投毒（URL 生成）/DNS rebinding | 校验 `request.host` ∈ {绑定 IP:port、hostname}，否则 400（见 §4.8） | 建议做 |
| L3 | `/api/interfaces` 泄露全部网卡名与累计字节 | api.py:214-238 | 网卡拓扑信息泄露 | 保留（功能需要），文档说明；受 token 保护后风险可接受 | 文档 |
| L4 | 前端 `setFreshness` 使用 innerHTML | app.js:169 | 当前数据面全为数字/固定字符串，无实际注入点；纵深防御 | 改为 textContent（或保留并注释数据面受控） | 建议做 |
| L5 | 公网 IP 探测依赖第三方 ifconfig.me | install.sh:299-313 | 第三方服务可观测安装来源 IP；不可用时回退 hostname -I | 优先 hostname -I/云元数据，第三方仅兜底（已回退，文档说明） | 文档 |

### 3.4 建议（4 项）— 增强

| # | 建议 | 位置 | 说明 | 归属 |
|---|---|---|---|---|
| S1 | 生产 WSGI（waitress/gunicorn）替代 Flask dev server | app.py:97；README FAQ10 | dev server 单线程/调试语义，生产建议 waitress；API 无改动可替换 | 建议做 |
| S2 | 反代 + 自动 HTTPS 示例（nginx/caddy + ACME）、自签证书生成命令 | README | 公网部署首选；自签证书浏览器告警说明 | 文档 |
| S3 | 卸载脚本撤销安装时添加的防火墙规则 | uninstall.sh | 与 M10 联动，安装记录规则 → 卸载删除 | 必须做(T3) |
| S4 | Permissions-Policy 头、journald 容量限制/轮转、keep_days 清理启用 | app.py / 文档 | 纵深防御与存储卫生 | 建议做 |

**统计：高危 6、中危 10、低危 5、建议 4，共 25 项。**

---

## 4. 加固方案设计

### 4.1 鉴权（T2）

1. **恒定时间比较**：`hmac.compare_digest(提供的, 配置的)`，替代 `==`。
   ```python
   import hmac
   provided = request.headers.get("X-Token", "")
   if not hmac.compare_digest(provided.encode(), token.encode()):
       return _err("unauthorized", 401)
   ```
2. **默认仅请求头**：新增配置 `allow_url_token`（bool，默认 **false**）。
   - `true` 时保留 `?token=` 兼容（README 已警告该方式进日志）；
   - `false` 时忽略 query 中的 token，仅认 `X-Token`。
   - 前端 `app.js` 已实现"URL 读取 → localStorage → 一律走 X-Token 头"（app.js:48-61），配置默认关闭后前端功能不受影响。
3. **token 为空 = 关闭鉴权**保持现状，但安装层强制默认生成（见 §4.10），并输出醒目警告"未设置 token 时任何人均可读数据"。
4. **统一 401**：无 token / 错 token / 头与参均错 → 相同 `{"ok":false,"error":"unauthorized"}` 与延迟（不区分存在性，防枚举）。

### 4.2 速率限制（T2）

- 配置 `rate_limit`（int，**默认 60**，单位：次/分钟/IP；`0` = 关闭）。
- 实现：`before_request` 钩子，内存滑动窗口 `dict[ip, deque[timestamp]]`（`collections.deque`），超窗裁剪后计数，超限 → `429 {"ok":false,"error":"rate limited"}`。
- 键：`request.remote_addr`（默认，防 XFF 伪造）；仅当配置 `trusted_proxy` 且请求来自该代理时改用 `X-Forwarded-For` 首段。
- 单进程内存态，重启清零（单用户场景可接受，文档注明）；多 worker 需共享存储（本期不涉及）。
- 附带收益：无 token 部署下也限制查询放大（monthly/history 的扫描成本）。

### 4.3 IP 白名单（T2）

- 配置 `allow_ips`（list，默认 `[]` = 不限制）。条目支持 `1.2.3.4`、`10.0.0.0/8`、`2001:db8::/32`。
- 实现：`ipaddress.ip_address(remote) in ipaddress.ip_network(entry)`，任一命中放行；非空且未命中 → `403 {"ok":false,"error":"forbidden"}`。
- 检查顺序：白名单（403）→ 限流（429）→ 鉴权（401）。白名单优先于鉴权，可在无 token 时仅对可信 IP 开放（如仅允许自家 IP 时可不设 token）。

### 4.4 监听绑定（T2）

- 配置 `bind`（str，默认 `"0.0.0.0"` 保持公网可达；可设 `"127.0.0.1"` 纯本机）。
- `app.run(host=cfg["bind"], ...)`，替换硬编码（app.py:97）。
- 公网部署建议：白名单/反代二选一；纯本机场景 bind=127.0.0.1 且无需 TLS。

### 4.5 TLS（T2 + 文档）

- 配置 `ssl_certfile` / `ssl_keyfile`（默认空 = 不启用 TLS）：
  ```python
  ssl_ctx = (cfg["ssl_certfile"], cfg["ssl_keyfile"]) if both else None
  app.run(host=cfg["bind"], port=cfg["port"], ssl_context=ssl_ctx, ...)
  ```
- 自签证书生成（文档提供）：
  ```bash
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout /var/lib/vpsmon/key.pem -out /var/lib/vpsmon/cert.pem -subj "/CN=<服务器IP或域名>"
  chown vpsmon:vpsmon /var/lib/vpsmon/{cert,key}.pem && chmod 600 /var/lib/vpsmon/key.pem
  ```
- 公网正式部署推荐：nginx/caddy 反代 + ACME 自动证书（S2 文档示例），并配套 HSTS（仅 HTTPS 时下发）。
- 说明：自签证书有浏览器告警与中间人提示的固有弱点，仅作过渡；反代 + 可信证书才是公网推荐形态。

### 4.6 安全响应头（T2，after_request 统一注入）

对 **所有响应**（静态页 + API）：

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
```

对 `/api/*` 追加：

```
Cache-Control: no-store
```

**CSP 取值说明（已在现有前端验证可工作）**：
- 页面脚本均为外部文件（`vendor/echarts.min.js`、`js/app.js`），**无内联 script** → `script-src 'self'` 可行；
- 内联样式属性（index.html:81 `style="width:0%"` 等）与 ECharts 动态注入样式 → `style-src 'unsafe-inline'` 必需；
- `data:` favicon（index.html:8）→ `img-src data:` 必需；
- API fetch 同源 → `connect-src 'self'`；
- 若保留 CDN 兜底脚本（不推荐），需追加 `script-src https://cdn.jsdelivr.net` + `<script integrity="sha384-...">` SRI，否则被 CSP 拦截——与 M4 的"删除兜底"二选一，推荐删除。
- HTTPS 部署时追加 `Strict-Transport-Security: max-age=31536000; includeSubDomains`（仅 TLS 下有意义）。

### 4.7 日志脱敏与信息泄露（T2）

1. **access log 脱敏**：给 werkzeug logger 挂 `logging.Filter`，将消息中的 query string（`?...` 到行尾/空格前）替换为 `?redacted`：
   ```python
   class QueryRedactFilter(logging.Filter):
       def filter(self, record):
           record.msg = re.sub(r"\?[^ \"]*", "?redacted", record.getMessage())
           record.args = ()
           return True
   logging.getLogger("werkzeug").addFilter(QueryRedactFilter())
   ```
   （H3 默认关闭 `?token=` 后此面大幅收敛，脱敏为纵深防御。）
2. **应用日志**：现有 `log.exception` 不记录请求参数/token（已合规）；`app.py:84` 启动日志含 `iface`（配置项，非请求输入）——保留。
3. **不打印 token**：任何日志路径不得输出 token 值（安装脚本打印到**终端**属用户明确要求，见 §4.10；不在服务日志中打印）。
4. 文档建议：journald `SystemMaxUse` 限额（S4）。

### 4.8 应用配置硬化（T2）

1. **debug 显式关**：新增配置 `debug`（默认 false）；若配置为 true → `log.warning` 警告并**强制回退 false**（生产绝不带调试器）。
2. **500 不泄堆栈**：现状已达标（app.py:70-73 通用错误 + 服务端日志），保持并加回归断言。
3. **Host 头校验（L2）**：`before_request` 校验 `request.host` 的 host 部分 ∈ {`cfg["bind"]`, `127.0.0.1`, socket.gethostname()} 之一（端口忽略），否则 400——防 Host 头投毒与 DNS rebinding。
4. **参数边界复核**：现有 `_clamp_int`（limit 1-1000、minutes 5-1440）、`_parse_month` 严格校验均已达标，T2 回归测试覆盖（§6）。
5. **可选元信息脱敏（L1）**：配置 `expose_meta`（默认 true 保持兼容）；false 时 `/api/status` 隐藏 hostname/uptime/db_bytes。

### 4.9 systemd 加固清单（T3）

在现有基础上（已含：`User/Group=vpsmon`、`NoNewPrivileges`、`PrivateTmp`、`ProtectSystem=full`、`ProtectHome`、`ReadWritePaths=/var/lib/vpsmon`、`Restart=always`、`PYTHONUNBUFFERED=1`）：

```ini
[Service]
# ---- 新增（已验证与 Python3/psutil 兼容，建议全部启用）----
UMask=0077
ProtectSystem=strict          # 更强：除 ReadWritePaths 外全只读（含 /opt/vpsmon）
ProtectKernelTunables=true    # psutil 只读 /proc/sys，不受影响
ProtectKernelModules=true
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectClock=true
ProtectProc=invisible         # psutil 读 /proc/stat、/proc/net、/proc/meminfo 为顶层文件，兼容；部署后实测确认
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
PrivateDevices=true           # 提供私有 /dev（含 urandom，Python secrets 可用）
CapabilityBoundingSet=        # 空集合：服务无需任何 capability
SystemCallArchitectures=native
Environment=PYTHONDONTWRITEBYTECODE=1   # strict 下 /opt/vpsmon 只读，禁止写 __pycache__

# ---- 不启用（与 Python/psutil 不兼容，务必保留注释说明，不要打开）----
# MemoryDenyWriteExecute=true  # CPython/libffi（psutil 的 C 扩展）需要 W^X 内存映射，
#                              # 启用后服务启动即崩溃（实测文档记录）
# ProcSubset=pid               # psutil 依赖完整 /proc（/proc/net/dev、/proc/stat 等），
#                              # 启用后采集全部失效
# PrivateUsers=true            # 改变文件属主映射语义，易致数据目录权限错乱
# IPAddressDeny=any            # 会阻断服务自身创建监听 socket，导致无法绑定端口

# ---- 可用但需逐项实测（本期不强制）----
# RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
# SystemCallFilter=@system-service   # Python 动态特性多，需充分回归
```

> `ProtectSystem=full` 只保护 /usr、/boot、/etc，**不覆盖 /opt**——这正是 M7（`/opt/vpsmon` 需归 root 只读）与升级 `strict` 的原因。`UMask=0077` 同时保证 SQLite 新建的 `vpsmon.db`/`-wal`/`-shm` 默认 600（现状靠目录 700 兜底）。

### 4.10 安装脚本加固（T3，用户核心需求）

**A. 端口交互输入（替换静默默认 8080）**
1. 交互模式判定：`[ -t 0 ]` 为真（终端；`bash -c "$(curl ...)"` 形态下 stdin 仍是终端 → 交互）。
2. 交互模式：`read -rp "监听端口 [1-65535]（默认 8080）: "`；校验 `^[0-9]+$` 且 1-65535，非法**循环重试**（最多 N 次或直到合法）；留空 = 8080（明确提示使用了默认值）。
3. 非交互/管道模式（`[ -t 0 ]` 为假，如 `curl | sudo bash`）：**必须**提供 `--port` 或环境变量 `VPSMON_PORT`，否则 `err` 并退出 1（禁止静默默认）。
4. `--port`/`VPSMON_PORT` 同样过 `validate_port`（1-65535）。

**B. token 默认自动生成（替换默认空）**
1. 未提供 `--token` 且未设 `VPSMON_TOKEN` → 自动生成强随机：
   ```bash
   TOKEN="$(openssl rand -hex 16 2>/dev/null \
     || od -An -N32 -tx1 /dev/urandom | tr -d ' \n' \
     || python3 -c 'import secrets; print(secrets.token_hex(16))')"
   ```
   32 位 hex = 128 bit 熵；`openssl` 不可用时依次回退。
2. 交互模式允许用户输入自定义 token，**留空 = 不开启鉴权**，但输出黄色警告"未设置 token，任何人均可读取数据（强烈建议使用自动生成的 token）"。
3. 自定义 `--token` 长度 < 8 时警告（建议使用自动生成）。
4. 安装成功输出**必须打印自动生成的 token**（用户明确要求），并提示妥善保管、忘记时编辑 `/var/lib/vpsmon/config.json` 后 `systemctl restart vpsmon`。
5. 提示 `--token` 参数会短暂出现在 `ps`/shell 历史：可用 `VPSMON_TOKEN` 环境变量替代（文档）。

**C. 防火墙自动放行（交互确认 + 卸载撤销）**
1. 安装末尾检测到 `ufw` 或 `firewall-cmd` 且端口未放行 → 交互询问 `是否放行 <port>/tcp？[y/N]`。
2. 同意则执行：
   - ufw：`ufw allow <port>/tcp comment 'vpsmon'`（记录到 `/var/lib/vpsmon/.firewall-rule`，内容 `ufw|<port>`）；
   - firewalld：`firewall-cmd --permanent --add-port=<port>/tcp && firewall-cmd --reload`（记录 `firewalld|<port>`）。
3. 非交互模式默认**只提示**（不自动放行，安全优先），与现状一致。
4. 卸载（install.sh do_uninstall 与 uninstall.sh）：读取标记文件 → 执行 `ufw delete allow <port>/tcp` / `firewall-cmd --permanent --remove-port=<port>/tcp && --reload` → 删除标记文件（S3）。若标记文件缺失则不撤销（避免误删用户既有规则，文档说明）。

**D. 权限属主复核**
1. `/opt/vpsmon`：**root:root**，目录 755、文件 644（`setup_venv` 去掉 `chown -R vpsmon:vpsmon "$APP_DIR"`，改为 `chmod -R o-w "$APP_DIR"` 保底），运行期由 `ProtectSystem=strict` 强制只读。
2. `/var/lib/vpsmon`：700，`vpsmon:vpsmon`（现状达标，保持）。
3. `config.json`：600 `vpsmon:vpsmon`；**写入用 `umask 077` 子 shell 或 `install -m 600`**，消除 644 中间窗口（M6）：
   ```bash
   ( umask 077; cat > "$CONFIG_FILE" <<EOF ... EOF )
   chown vpsmon:vpsmon "$CONFIG_FILE"
   ```
4. 自签证书 `key.pem` 600（§4.5）。
5. `vpsmon.service`：`install -m 644` root:root（现状达标）。

**E. 卸载流程复核**：停服 → 删单元 → 删 `/opt/vpsmon` → 数据目录交互确认（默认保留，管道模式强制保留——现状已安全）→ 撤销防火墙规则（新增）→ 删除用户。`userdel` 失败仅警告（现状达标）。

### 4.11 供应链（T3 + 文档）

1. **requirements 精确 pin（M3）**：改为
   ```
   flask==3.1.3
   psutil==<实施时 pip index versions 确认的当前稳定版>
   ```
   （flask 3.1.3 与 werkzeug 3.1.8 已在本项目验证环境出现；psutil 以安装环境实测为准。）可选进阶：生成 `requirements-hashes.txt` 并 `pip install --require-hashes -r ...`。
2. **远程安装校验（H6）**：
   - 文档明确信任模型：`curl|bash` = 无条件信任脚本内容；**任何 GitHub 仓库被接管都会导致 root 失陷**；
   - 推荐 pin commit：`https://raw.githubusercontent.com/<owner>/<repo>/<commit-sha>/install.sh`；
   - 支持 `VPSMON_EXPECTED_SHA256=<发布方公布的 tarball 校验和>`：`fetch_remote_source` 下载后先 `sha256sum -c` 比对，不匹配立即退出（提示供应链风险）。
3. **前端 CDN 兜底删除（M4）**：`app.js:543-559` 的 CDN 回退分支移除（`static/vendor/echarts.min.js` 1.0MB 已随包部署，删除兜底消除第三方脚本执行面，同时使 `script-src 'self'` CSP 严格成立）。
4. **`.gitignore` 复核**：config.json/*.db 已忽略；确认密钥证书（cert.pem/key.pem）、`.firewall-rule` 不进仓库（补充规则）。

---

## 5. 实施分级清单

### 5.1 必须做（T2 后端加固）
- [x] H2 `hmac.compare_digest` 恒定时间比较
- [x] H3 `allow_url_token` 默认 false，鉴权仅认 `X-Token` 头
- [x] H4 内存限流 `rate_limit`（默认 60/min，0=关），429 响应
- [x] H5 `allow_ips` IP/CIDR 白名单，403 响应
- [x] M1 安全响应头全量注入（§4.6 工作值）
- [x] M2 TLS 支持（`ssl_certfile`/`ssl_keyfile` → `ssl_context`，默认不启用）
- [x] M4 删除前端 CDN 兜底脚本
- [x] M5 werkzeug 访问日志 query 脱敏
- [x] 4.8：`debug` 配置守卫强制 false、Host 头校验、`bind` 配置项、`expose_meta`（可选）

### 5.2 必须做（T3 安装加固）
- [x] H1 默认 token 自动生成（强随机 128bit）+ 未设置 token 的醒目警告
- [x] M3 requirements 精确 pin
- [x] M6 config.json 写入权限窗口修复（umask 077 / install -m 600）
- [x] M7 /opt/vpsmon 归 root 只读（去掉 chown -R vpsmon）
- [x] M8 systemd 加固清单落地（§4.9 新增项 + 不兼容项注释）
- [x] M9 端口交互输入（1-65535 非法重试）；非交互/管道必须 `--port`/`VPSMON_PORT` 否则报错退出
- [x] M10 防火墙交互确认自动放行 + 标记记录
- [x] S3 卸载撤销防火墙规则
- [x] H6 远程安装：`VPSMON_EXPECTED_SHA256` 校验支持 + README 信任模型/commit pin 文档

### 5.3 建议做
- [ ] L1 `/api/status` 元信息脱敏开关 `expose_meta`（未实施：hostname/uptime/db_bytes 常显，token 保护下可接受）
- [x] L2 Host 头校验（T2 已实施；T4 复核时追加加固：拒绝 `@` userinfo 与非法端口）
- [x] L4 前端 `setFreshness` 改 textContent（已实施：app.js:169 注释标注 SECURITY L4）
- [ ] S1 生产 WSGI（waitress）替换 dev server（未实施，单用户场景可接受）
- [~] S4 Permissions-Policy（已随 M1 头清单落地）；journald `SystemMaxUse` 限额与 `keep_days` 清理**未实施**（运维可选）

### 5.4 仅文档说明
- [ ] S2 反代（nginx/caddy）+ ACME HTTPS 示例、自签证书生成与告警说明
- [ ] L3 接口信息面说明（token 保护下可接受）
- [ ] L5 公网 IP 探测第三方依赖说明
- [ ] H6 供应链信任模型与 commit pin 指引（README"远程安装"章节重写）

---

## 6. 已复核安全项（无问题清单，回归时保持）

| 项 | 结论 |
|---|---|
| SQL 注入面 | **无**。storage.py 全部 SQL 参数化（`?` 占位）；`iface` 一律走参数绑定；`month` 经 `_parse_month` 严格校验（YYYY-MM + 年 1-9999/月 1-12）；`limit`/`minutes` 经 `_clamp_int` 钳制；无字符串拼接 SQL |
| 500 响应 | 通用 JSON、不泄堆栈（app.py:70-73），详情仅服务端日志 |
| 参数边界 | daily 非法 month→400；limit 1-1000、minutes 5-1440 越界回退默认（api.py:_clamp_int） |
| 静态文件服务 | `send_from_directory`，无目录穿越 |
| 方法限制 | 仅 GET，405 JSON 处理（app.py:66-68） |
| CSRF | 全部端点只读 GET、无 Cookie/会话/状态变更，不适用 |
| 前端注入面 | 渲染均用 textContent；innerHTML 仅一处且数据面为数字/固定字符串（L4）；ECharts 数据全数值 |
| 数据库文件 | WAL 模式 + 目录 700 保护；`keep_days` 未启用（存储增长可接受） |
| 卸载数据安全 | 数据目录默认保留；管道模式强制保留不阻塞（uninstall.sh:99-121） |
| 配置文件解析 | 非法 JSON 回退默认不崩溃（config.py:78-84）；token 不做任何日志输出 |

---

## 7. 遗留风险与接受项（文档化）

1. **token 明文存 config.json**：600 权限 + 目录 700 已隔离本机其他用户；root 可见属必然（安装/运维需要）。接受。
2. **自签 TLS 的浏览器告警**：过渡方案；公网正式部署走反代 ACME。接受（S2）。
3. **内存限流重启清零**：单进程单用户场景可接受；攻击者在服务重启窗口可短暂突破（需同时有弱 token 才构成威胁）。接受。
4. **curl|bash 固有信任问题**：无法代码消除，只能文档化 + 校验和 + commit pin（H6）。接受为部署方责任。
5. **监控数据本身的价值**：流量/系统占用属敏感业务信号；建议配合防火墙只对可信 IP 开放（H5/白名单）或仅内网访问。

---

## 8. 加固验收清单（供 T4 reviewer 使用）

```bash
# 1) 安全头（全部响应）
curl -sI http://127.0.0.1:<port>/ | grep -iE 'content-security-policy|x-frame-options|x-content-type-options|referrer-policy|cache-control'
# 2) 鉴权（默认仅头）
curl -s http://127.0.0.1:<port>/api/status            # → 401
curl -s -H "X-Token: <token>" http://127.0.0.1:<port>/api/status   # → 200
curl -s "http://127.0.0.1:<port>/api/status?token=<token>"         # → 401（allow_url_token=false）
# 3) 限流
for i in $(seq 1 70); do curl -s -o /dev/null -w '%{http_code}\n' -H "X-Token: <token>" http://127.0.0.1:<port>/api/status; done | sort | uniq -c   # 出现 429
# 4) 白名单
#    配置 allow_ips=["127.0.0.1"] 后从其他 IP 访问 → 403
# 5) TLS（启用后）
curl -sk https://127.0.0.1:<port>/api/status -H "X-Token: <token>"   # → 200
# 6) systemd 加固
systemd-analyze security vpsmon    # 期望评分显著优于基线
systemctl cat vpsmon | grep -E 'MemoryDenyWriteExecute|ProcSubset'   # 应为注释态（不启用）
# 7) 日志脱敏
journalctl -u vpsmon | grep -E '\?token='   # 应无输出
# 8) 安装流程
#    管道模式（stdin 非终端）不带 --port → 报错退出；带 --port 正常安装；
#    交互模式输入非法端口 → 重试；token 自动生成并打印
```
